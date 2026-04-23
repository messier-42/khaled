package keyschedule

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
)

// setKeyInfo is the HKDF info prefix for Set Key derivation.
const setKeyInfo = "khaled/set-key\x00"

// leaseKeyInfo is the HKDF info prefix for Lease Key derivation.
const leaseKeyInfoPrefix = "khaled/lease-key\x00"

// keyLen is the length in bytes of every derived key in the key schedule.
const keyLen = 32

// NewLease derives a fresh Lease Key for attrSet under the current
// Root Key and the current subepoch for attrSet. The returned
// LeaseRefInfo carries the tuple needed to rederive the same key;
// the keyserver layer is responsible for cryptographically securing it against
// modification and serializing it.
func (s *Schedule) NewLease(ctx context.Context, attrSet attrset.Set) (*LeaseKeyInfo, error) {
	repr := attrSet.Repr()

	root, err := s.domain.CurrentRootKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("keyschedule: NewLease: current root: %w", err)
	}
	subepoch, err := s.domain.CurrentSubEpoch(ctx, hashAttrSet(attrSet))
	if err != nil {
		return nil, fmt.Errorf("keyschedule: NewLease: current subepoch: %w", err)
	}

	now := s.now().UTC()
	leaseTimeMicros := now.UnixMicro()

	leaseKey, err := s.deriveLeaseKey(ctx, root, repr, subepoch, leaseTimeMicros)
	if err != nil {
		return nil, err
	}

	return &LeaseKeyInfo{
		RefInfo: LeaseRefInfo{
			Time:       time.UnixMicro(leaseTimeMicros).UTC(),
			RootSeqNum: root.SeqNum(),
			SubEpoch:   subepoch,
		},
		Key: leaseKey,
	}, nil
}

// ResolveLease rederives the Lease Key for the given already-
// authenticated LeaseRefInfo. The caller is responsible for having
// authenticated the Ref that produced info before calling this
// method: the schedule trusts info unconditionally and will
// derive a key for any tuple handed to it.
func (s *Schedule) ResolveLease(ctx context.Context, info LeaseRefInfo, attrSet attrset.Set) (*LeaseKeyInfo, error) {
	repr := attrSet.Repr()

	// Look up the root key by sequence number. Using the sequence number
	// (which the Lease Reference embeds) rather than a plugin-specific KeyID
	// keeps the schedule agnostic to how the plugin encodes its IDs.
	root, err := s.domain.RootKeyBySeqNum(ctx, info.RootSeqNum)
	if err != nil {
		return nil, fmt.Errorf("keyschedule: ResolveLease: root key %d: %w", info.RootSeqNum, err)
	}

	leaseKey, err := s.deriveLeaseKey(ctx, root, repr, info.SubEpoch, info.Time.UnixMicro())
	if err != nil {
		return nil, err
	}

	return &LeaseKeyInfo{
		RefInfo: info,
		Key:     leaseKey,
	}, nil
}

// AdvanceSubEpoch atomically increments the subepoch counter for
// attrSet in the keystorage.
func (s *Schedule) AdvanceSubEpoch(ctx context.Context, attrSet attrset.Set) error {
	if _, err := s.domain.AdvanceSubEpoch(ctx, hashAttrSet(attrSet)); err != nil {
		return fmt.Errorf("keyschedule: AdvanceSubEpoch: %w", err)
	}
	return nil
}

// hashAttrSet hashes an attribute set.
func hashAttrSet(attrSet attrset.Set) []byte {
	v := sha256.Sum256([]byte(attrSet.Repr()))
	return v[:]
}

// RotateRootKey rotates the domain's Root Key and, by virtue of
// keystorage's RotateRootKey contract, atomically clears all
// subepoch counters.
func (s *Schedule) RotateRootKey(ctx context.Context) error {
	cur, err := s.domain.CurrentRootKey(ctx)
	if err != nil {
		return fmt.Errorf("keyschedule: RotateRootKey: read current: %w", err)
	}
	if _, err := s.domain.RotateRootKey(ctx, cur); err != nil {
		if errors.Is(err, keystorage.ErrStaleRootKey) {
			return nil
		}
		return fmt.Errorf("keyschedule: RotateRootKey: %w", err)
	}
	return nil
}

// rotationLoop drives periodic background root rotation. Each tick
// calls RotateRootKey with a deadline of one interval; a tick that
// errors is logged as an error. Cancellation via parent.Done() or
// Close() is logged at DEBUG and is not an error.
func (s *Schedule) rotationLoop(parent context.Context, interval time.Duration) {
	defer close(s.loopDoneCh)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-parent.Done():
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(parent, interval)
			err := s.RotateRootKey(ctx)
			cancel()
			if err != nil {
				// Cancellation (via Close / parent ctx) is expected during
				// shutdown; don't raise it to ERROR.
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					slog.DebugContext(parent, "keyschedule: background rotation cancelled", "error", err)
				} else {
					slog.ErrorContext(parent, "keyschedule: background root rotation failed", "error", err)
				}
			}
		}
	}
}

// deriveLeaseKey performs the two-stage HKDF: SetKey from
// (root, attr_set_repr, subepoch), then LeaseKey from
// (SetKey, lease_time_micros).
//
// leaseTimeMicros MUST be non-negative.
func (s *Schedule) deriveLeaseKey(
	ctx context.Context,
	root keystorage.RootKey,
	repr attrset.Repr,
	subepoch uint64,
	leaseTimeMicros int64,
) ([]byte, error) {
	if leaseTimeMicros < 0 {
		return nil, fmt.Errorf("keyschedule: lease time %d µs is before Unix epoch; check server clock", leaseTimeMicros)
	}

	// Obtain set key.
	setKeyCtx := append([]byte(nil), repr...)
	setKeyCtx = appendUint64BE(setKeyCtx, subepoch)
	setKeyDerived, err := s.domain.DeriveKey(ctx, root, &keystorage.DerivationInfo{
		Context: append([]byte(setKeyInfo), setKeyCtx...),
		Length:  keyLen,
	})
	if err != nil {
		return nil, fmt.Errorf("keyschedule: derive set key: %w", err)
	}
	defer clear(setKeyDerived.KeyBytes)

	// Derive lease key.
	infoBytes := appendUint64BE([]byte(leaseKeyInfoPrefix), uint64(leaseTimeMicros))
	leaseKey, err := hkdf.Key(sha256.New, setKeyDerived.KeyBytes, nil, string(infoBytes), keyLen)
	if err != nil {
		return nil, fmt.Errorf("keyschedule: derive lease key: %w", err)
	}
	return leaseKey, nil
}

func appendUint64BE(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}
