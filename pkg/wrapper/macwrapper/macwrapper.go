// Package macwrapper authenticates opaque byte strings using HMAC-SHA-256
// (truncated to 16 bytes), keyed by an HKDF derivation from the keystorage
// Root Key under which the reference was minted.
//
// Byte strings are wrapped as follows:
//
//		root_seqno (u64 BE) || plaintext
//	   || HMAC-SHA-256-128(K, uint64(len(aad)) || plaintext || aad)
//
// where K = HKDF(root_key, "khaled/lease-reference/HMAC-SHA256", 32).
//
// The MAC key is derived once per Root Key and cached in-process.
// Because retired Root Keys are stored indefinitely, references created under any
// prior Root Key can continue to be verified after rotation. Old root keys
// can be loaded automatically to compute the necessary K as needed.
package macwrapper

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/messier-42/khaled/pkg/plugin/keystorage"
)

const (
	// derivationConstant is the constant used to derive the MAC key
	// from a given Root Key.
	derivationConstant = "khaled/lease-reference/HMAC-SHA256-128"

	// macKeyLen is the MAC key length in bytes.
	macKeyLen = 32

	// macTagLen is the trunated HMAC-SHA-256 tag length.
	macTagLen = 16

	// rootSeqNumLen is size of the encoded Root Key sequence number
	// in bytes prefixed to each wrapped byte string.
	rootSeqNumLen = 8

	// cacheSize is the maximum number of MAC keys retained in memory.
	// Least-recently-used keys are evicted on overflow; cache misses
	// fall back to re-derivation via keystorage.
	cacheSize = 16
)

// Wrapper attaches authentication tags to opaque byte strings using keying material
// derived from a key store and verifies those tags.
//
// It is safe for concurrent use.
type Wrapper struct {
	domain keystorage.KeyStoreDomain

	// cache maps root_seqno to its derived MAC key. The cache is
	// internally synchronized; no external locking is required.
	//
	// Evicted entries are not zeroed: a concurrent Wrap/Unwrap may
	// still hold the slice and be computing an HMAC against it.
	// Dropping the cache reference makes the slice GC-eligible once
	// the last reader releases it.
	cache *lru.Cache[uint64, []byte]
}

// New returns a Wrapper that derives its MAC keys from the given
// KeyStoreDomain.
func New(domain keystorage.KeyStoreDomain) (*Wrapper, error) {
	if domain == nil {
		return nil, errors.New("macwrapper: domain is required")
	}

	cache, err := lru.New[uint64, []byte](cacheSize)
	if err != nil {
		return nil, fmt.Errorf("macwrapper: build cache: %w", err)
	}
	return &Wrapper{
		domain: domain,
		cache:  cache,
	}, nil
}

// Wrap takes plaintext, an opaque byte string, and produces another byte string
// which is protected against modification (but not examination) by third parties.
// It uses a key derived from the current Root Key.
func (w *Wrapper) Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error) {
	root, err := w.domain.CurrentRootKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("macwrapper: read current root: %w", err)
	}

	macKey, err := w.macKeyFor(ctx, root)
	if err != nil {
		return nil, err
	}

	tag := computeTag(macKey, plaintext, aad)

	out := make([]byte, 0, rootSeqNumLen+len(plaintext)+macTagLen)
	out = appendUint64BE(out, root.SeqNum())
	out = append(out, plaintext...)
	out = append(out, tag...)
	return out, nil
}

// Unwrap verifies a byte string previously wrapped using Wrap() and returns
// the plaintext if verification is successful. If verification fails, an error
// is returned and the plaintext is not returned.
func (w *Wrapper) Unwrap(ctx context.Context, opaque, aad []byte) ([]byte, error) {
	if len(opaque) < rootSeqNumLen+macTagLen {
		return nil, errors.New("macwrapper: ref too short")
	}
	rootSeqNum := binary.BigEndian.Uint64(opaque[:rootSeqNumLen])
	plaintext := opaque[rootSeqNumLen : len(opaque)-macTagLen]
	gotTag := opaque[len(opaque)-macTagLen:]

	root, err := w.domain.RootKeyByID(ctx, keystorage.KeyID(strconv.FormatUint(rootSeqNum, 10)))
	if err != nil {
		slog.DebugContext(ctx, "macwrapper: root key lookup failed during Unwrap",
			"rootSeqNum", rootSeqNum,
			"error", err,
		)
		return nil, errors.New("macwrapper: root key for ref not found")
	}

	macKey, err := w.macKeyFor(ctx, root)
	if err != nil {
		return nil, err
	}

	wantTag := computeTag(macKey, plaintext, aad)

	if !hmac.Equal(gotTag, wantTag) {
		return nil, errors.New("macwrapper: ref tag mismatch")
	}

	// Return a copy so callers can hold onto the plaintext without
	// aliasing the input slice.
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return out, nil
}

// macKeyFor returns the MAC key for the given root, deriving and
// caching the key as needed on cache miss.
func (w *Wrapper) macKeyFor(ctx context.Context, root keystorage.RootKey) ([]byte, error) {
	if k, ok := w.cache.Get(root.SeqNum()); ok {
		return k, nil
	}

	derived, err := w.domain.DeriveKey(ctx, root, &keystorage.DerivationInfo{
		Context: []byte(derivationConstant),
		Length:  macKeyLen,
	})
	if err != nil {
		return nil, fmt.Errorf("macwrapper: derive MAC key for root %d: %w", root.SeqNum(), err)
	}

	// PeekOrAdd resolves a lost-the-race scenario atomically: if a
	// concurrent caller cached an entry for this root in the meantime,
	// we keep theirs and discard our duplicate derivation.
	if existing, ok, _ := w.cache.PeekOrAdd(root.SeqNum(), derived.KeyBytes); ok {
		clear(derived.KeyBytes)
		return existing, nil
	}
	return derived.KeyBytes, nil
}

// computeTag returns HMAC-SHA-256(key, uint64BE(len(aad)) || plaintext || aad)
// truncated to macTagLen bytes.
func computeTag(key, plaintext, aad []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(appendUint64BE(nil, uint64(len(aad))))
	mac.Write(plaintext)
	mac.Write(aad)
	return mac.Sum(nil)[:macTagLen]
}

func appendUint64BE(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}
