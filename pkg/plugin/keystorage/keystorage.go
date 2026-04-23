// Package keystorage defines the Key Storage plugin interface.
//
// A Key Storage plugin holds Root Keys (the only Non-Derived Keys in
// the key schedule currently used by khaled) and exposes a deterministic
// key derivation primitive built on top of them. Root Keys are opaque handles;
// the plugin never exposes their bit pattern, so a backend whose root
// material is held in some captive store (e.g. a HSM, TPM, or AWS KMS) can
// implement the same interface. Thus, the Key Storage plugin interface is
// agnostic to the storage method used.
//
// A KeyStore is a container of one or more KeyStoreDomains, each of
// which holds an independent STRK (Single Temporal Root Key) chain as
// described in doc/arch. Higher-layer logic (specifically pkg/keyschedule)
// consumes this interface to derive Set Keys and Lease Keys; rotation cadence
// and lease tracking are not the concern of this plugin.
//
// # Key invariants
//
// The Root Key series is append-only. Root keys cannot be deleted after
// creation; keys are retained indefinitely so previously issued Lease
// References can be resolved forever after.
//
// RotateRootKey is an atomic compare-and-swap operation; the caller specifies
// the RootKey it believed to be current. If this is no longer accurate,
// ErrStaleRootKey is returned, and the caller can repeat the operation.
//
// RotateRootKey atomically clears all per-Attribute-Set subepoch
// counters for the domain in the same transaction that retires the
// old root. A new Root Key Epoch implicitly resets every Set Key
// Series. This keeps the subepoch table size bounded.
//
// # Opaque KeyID
//
// KeyID is a non-empty UTF-8 string, rather than an integer. Although
// the present implementation using SQLite decimally encodes an integral value,
// this design ensures that future backends with long/non-integral handle types
// can implement the interface.
package keystorage

import (
	"context"
	"errors"
	"io"
	"iter"
	"time"
)

// KeyID is a plugin-opaque, non-empty UTF-8 string identifying a Root
// Key within a KeyStoreDomain. It is fixed and permanently unique.
type KeyID string

// DomainID is a plugin-opaque, non-empty UTF-8 string identifying a
// KeyStoreDomain within a KeyStore. It is fixed and permanently unique,
// and in most implementations is distinct from a domain's name.
type DomainID string

// RootKey is an opaque handle to a Root Key held by a KeyStoreDomain.
// The Root Key's bit pattern is never exposed; it is used only as the
// input to DeriveKey.
type RootKey interface {
	// ID returns the key's unique identifier.
	ID() KeyID

	// SeqNum returns the key's sequence number. Within a given domain, a
	// Root Key with a sequence number of 0 always exists, and the existence
	// of a Root Key with a sequence number of n > 0 implies that a Root Key
	// with a sequence number of (n-1) also exists.
	SeqNum() uint64

	// CreationTime returns the time at which a Root Key was created.
	CreationTime() time.Time

	// RetirementTime returns the time at which this Root Key was
	// retired, or the zero time if this Root Key is the Current Root Key.
	RetirementTime() time.Time
}

// DerivationInfo specifies the inputs to a key derivation operation.
//
// Context is an opaque byte string that the KeyStoreDomain treats as
// a domain separator: distinct Context values MUST yield distinct
// DerivedKeys.
//
// Length is the requested DerivedKey length in bytes and MUST be
// positive. The plugin returns an error if it cannot produce a key of
// the requested length (for example, exceeding the maximum output
// length of the underlying KDF).
type DerivationInfo struct {
	Context []byte
	Length  int
}

// DerivedKey holds the bit pattern of a key derived from a Root Key.
// KeyBytes is sensitive; callers SHOULD zero it as soon as it is no
// longer needed.
type DerivedKey struct {
	KeyBytes []byte
}

// ErrStaleRootKey is returned by KeyStoreDomain.RotateRootKey when the
// supplied oldKey is no longer the current Root Key (i.e. another
// rotation has occurred since it was observed). Callers should
// re-read CurrentRootKey and retry if desired.
var ErrStaleRootKey = errors.New("root key is no longer current")

// ErrNoSuchDomain is returned by KeyStore.DomainByName when no domain with
// the requested name exists.
var ErrNoSuchDomain = errors.New("no such domain")

// ErrNoSuchRootKey is returned by KeyStoreDomain.RootKeyByID or
// KeyStoreDomain.RootKeyBySeqNum when no root key with the requested
// identity exists in the domain.
var ErrNoSuchRootKey = errors.New("no such root key")

// KeyStore is the Key Storage plugin interface. A KeyStore is a
// container of one or more KeyStoreDomains. All methods are safe for
// concurrent use from multiple goroutines.
type KeyStore interface {
	io.Closer

	// ListDomains yields all KeyStoreDomains held by this KeyStore.
	// The iteration order is plugin-defined. Callers may break early.
	// Yielding a non-nil error terminates iteration.
	ListDomains(ctx context.Context) iter.Seq2[KeyStoreDomain, error]

	// DomainByName returns the KeyStoreDomain with the given name. If no
	// such domain exists the returned error wraps ErrNoSuchDomain.
	DomainByName(ctx context.Context, name string) (KeyStoreDomain, error)
}

// KeyStoreDomain is an independent sequence of Root Keys within a KeyStore.
// All methods are safe for concurrent use from multiple goroutines.
type KeyStoreDomain interface {
	// ID is a stable plugin-opaque identifier for this domain.
	ID() DomainID

	// Name is the user-facing name of this domain.
	Name() string

	// CurrentRootKey returns the unretired Root Key (the Root Key within
	// the domain with the highest sequence number). There is always exactly
	// one such key for a given domain.
	CurrentRootKey(ctx context.Context) (RootKey, error)

	// RootKeyByID returns the Root Key with the given ID. If no such
	// key exists, the returned error satisfies `errors.Is(ErrNoSuchRootKey)`.
	RootKeyByID(ctx context.Context, id KeyID) (RootKey, error)

	// RootKeyBySeqNum returns the Root Key with the given sequence
	// number.
	//
	// If no such key exists the returned error satisfies
	// `errors.Is(ErrNoSuchRootKey)`.
	//
	// Callers that already have a KeyID should prefer RootKeyByID.
	RootKeyBySeqNum(ctx context.Context, seqNum uint64) (RootKey, error)

	// ListRootKeys yields all Root Keys in descending sequence number
	// order (current key first, then progressively older retired keys).
	// Callers may break early. Yielding a non-nil error terminates iteration.
	ListRootKeys(ctx context.Context) iter.Seq2[RootKey, error]

	// RotateRootKey atomically verifies that oldKey is the Current Root Key,
	// retires oldKey, creates a successor Root Key with SeqNum == oldKey.SeqNum()+1,
	// and clears all subepoch counters for this domain. If oldKey is not the
	// Current Root Key at call time, ErrStaleRootKey is returned and no changes
	// occur.
	RotateRootKey(ctx context.Context, oldKey RootKey) (RootKey, error)

	// DeriveKey deterministically derives a key from rootKey using
	// info. The same (rootKey, info) MUST always yield the same
	// DerivedKey; distinct info values MUST yield distinct
	// DerivedKeys.
	DeriveKey(ctx context.Context, rootKey RootKey, info *DerivationInfo) (*DerivedKey, error)

	// CurrentSubEpoch returns the current subepoch counter for
	// attrSetHash. If the given Attribute Set has never been advanced,
	// this function returns (0, nil).
	CurrentSubEpoch(ctx context.Context, attrSetHash []byte) (uint64, error)

	// AdvanceSubEpoch atomically increments the subepoch counter for
	// attrSetHash and returns the new value. The first call for a
	// given attrSetHash returns 1. Counters are cleared as a
	// side effect of RotateRootKey; subsequent calls then restart at 1.
	AdvanceSubEpoch(ctx context.Context, attrSetHash []byte) (uint64, error)
}
