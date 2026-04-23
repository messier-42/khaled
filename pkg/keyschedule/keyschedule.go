// Package keyschedule owns the key-mechanics layer of khaled: Set
// Key and Lease Key derivation, and the subepoch / Root Key
// rotation state machine for a single CABE domain.
//
// The schedule consumes a keystorage.KeyStoreDomain below and is
// consumed by a higher-layer "keyserver" that authenticates and
// frames Lease References on the wire, gates requests through the
// policy engine, and assembles CKAP responses. The schedule has no
// Principal, policy, or Ref-serialization concept: it only derives
// keys. Ref authentication and framing is a keyserver concern; this
// separation is load-bearing — the schedule is the crypto plane
// and must not import anything from the authorization plane.
//
// # Trust contract
//
// ResolveLease takes an already-authenticated LeaseRefInfo tuple and
// derives the corresponding Lease Key without re-checking anything.
// The schedule trusts its caller to have verified (typically via a
// MAC) that the tuple was issued by this Key Server. Passing an
// unauthenticated LeaseRefInfo is a security bug in the caller;
// downstream derivation will happily produce a key for any tuple.
//
// # State model
//
// Only Root Keys and per-Attribute-Set subepoch counters are
// persisted (both live in the keystorage plugin). Set Keys and
// Lease Keys are pure functions of state + inputs and are never
// stored. Background Root Key rotation is opt-in via
// Config.RootRotationInterval; subepoch advance is admin-only with
// no background behaviour.
//
// # Clock requirements
//
// Lease mint times are used as policy inputs upstream. The schedule
// assumes the Key Server's wall clock is monotonic and
// NTP-synchronised; there is no in-process mitigation for backward
// clock jumps.
//
// See doc/plans/2026-04-18-keyschedule-design.md for the full design
// rationale.
package keyschedule

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/messier-42/khaled/pkg/plugin/keystorage"
)

// LeaseRefInfo is the logical content of a Lease Reference: the
// tuple of fields that uniquely determines a Lease Key, independent
// of any particular wire serialization. The keyserver layer is
// responsible for authenticating and framing Refs on the wire and
// hands resolved LeaseRefInfo values back to the schedule.
type LeaseRefInfo struct {
	// Time is the wall-clock mint time of the Lease.
	Time time.Time
	// RootSeqNum is the SeqNum of the Root Key under which the Lease
	// was minted.
	RootSeqNum uint64
	// SubEpoch is the subepoch number for the Attribute Set at mint
	// time.
	SubEpoch uint64
}

// LeaseKeyInfo bundles a derived Lease Key with its LeaseRefInfo.
// Key is sensitive; callers SHOULD zero it when no longer needed.
type LeaseKeyInfo struct {
	RefInfo LeaseRefInfo
	Key     []byte
}

// Config configures a Schedule.
type Config struct {
	// Domain is the KeyStoreDomain this schedule operates against.
	// Required.
	Domain keystorage.KeyStoreDomain

	// RootRotationInterval, if non-zero, causes the schedule to run
	// a background goroutine that rotates the Root Key on that
	// cadence. Zero (the default) disables background rotation;
	// callers may still trigger rotation manually via RotateRootKey.
	RootRotationInterval time.Duration

	// Now provides a clock source for testing. If nil, time.Now is used.
	Now func() time.Time
}

// Schedule manages the key schedule for a single CABE domain. It is
// concurrency-safe; all methods may be called concurrently.
type Schedule struct {
	domain     keystorage.KeyStoreDomain
	now        func() time.Time
	closeOnce  sync.Once
	closeCh    chan struct{}
	loopDoneCh chan struct{}
}

// New constructs a Schedule from cfg, validates it, and starts the
// background rotation schedule if configured. ctx bounds the
// rotation loop; cancelling it (or calling Close) terminates the
// background rotation schedule.
func New(ctx context.Context, cfg Config) (*Schedule, error) {
	if cfg.Domain == nil {
		return nil, errors.New("keyschedule: Config.Domain is required")
	}
	if cfg.RootRotationInterval < 0 {
		return nil, errors.New("keyschedule: Config.RootRotationInterval must be non-negative")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	s := &Schedule{
		domain:  cfg.Domain,
		now:     now,
		closeCh: make(chan struct{}),
	}
	if cfg.RootRotationInterval > 0 {
		s.loopDoneCh = make(chan struct{})
		go s.rotationLoop(ctx, cfg.RootRotationInterval)
	}

	return s, nil
}

// Close stops the background rotation goroutine (if any) and
// releases the schedule's resources. Idempotent.
func (s *Schedule) Close() error {
	s.closeOnce.Do(func() {
		close(s.closeCh)
		if s.loopDoneCh != nil {
			<-s.loopDoneCh
		}
	})
	return nil
}

var _ io.Closer = &Schedule{}
