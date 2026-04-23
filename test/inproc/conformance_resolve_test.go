//go:build integration

package inproc

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"

	"github.com/messier-42/khaled/test/ktutil"
)

// TestPrograde_HappyPath drives a fresh server through a Prograde
// against a small attribute set. Asserts the returned Lease is
// well-formed: non-empty LeaseRef, future expiry, non-captive LKAI
// carrying a non-empty COSE key (the default the permit-all Cedar
// policy yields, since the policy plugin sets RequireCaptive=false
// today).
func TestPrograde_HappyPath(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	client := srv.Client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	as, err := attrset.New(map[string]any{"env": "test"})
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}

	resp, err := client.Prograde(ctx, ckap.ProgradeRequest{AttributeSet: as})
	if err != nil {
		t.Fatalf("Prograde: %s", describeError(err))
	}
	if resp == nil || resp.Lease == nil {
		t.Fatalf("Prograde returned nil lease")
	}
	lease := resp.Lease
	if len(lease.LeaseRef) == 0 {
		t.Errorf("Lease.LeaseRef is empty")
	}
	if !lease.Expiry.After(time.Now()) {
		t.Errorf("Lease.Expiry = %v, want a future time", lease.Expiry)
	}
	if lease.LKAI.NonCaptive == nil {
		t.Fatalf("Lease.LKAI.NonCaptive is nil; permit-all policy should yield a non-captive lease (LKAI=%+v)", lease.LKAI)
	}
	if len(lease.LKAI.NonCaptive.RawCOSEKey) == 0 {
		t.Errorf("Lease.LKAI.NonCaptive.RawCOSEKey is empty")
	}
	if lease.LKAI.Captive != nil {
		t.Errorf("Lease.LKAI.Captive = %+v, want nil for non-captive lease", lease.LKAI.Captive)
	}
}

// TestRetrograde_RoundTripsProgradeLease pins the Prograde→Retrograde
// round trip: a LeaseRef minted by Prograde must be resolvable by
// Retrograde with the same attribute set, and the recovered LKAI
// must carry the same COSE key bytes as the Prograde response.
//
// Stability of the COSE key bytes across the two operations is the
// load-bearing property: it is what lets a CBES decapsulation succeed
// after the original sender's Prograde response has been dropped.
func TestRetrograde_RoundTripsProgradeLease(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	client := srv.Client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	as, err := attrset.New(map[string]any{"env": "test", "tier": "gold"})
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}

	pro, err := client.Prograde(ctx, ckap.ProgradeRequest{AttributeSet: as})
	if err != nil {
		t.Fatalf("Prograde: %s", describeError(err))
	}
	if pro.Lease.LKAI.NonCaptive == nil {
		t.Fatalf("Prograde returned no non-captive LKAI: %+v", pro.Lease.LKAI)
	}
	originalKey := pro.Lease.LKAI.NonCaptive.RawCOSEKey

	retro, err := client.Retrograde(ctx, ckap.RetrogradeRequest{
		AttributeSet: as,
		LeaseRef:     pro.Lease.LeaseRef,
	})
	if err != nil {
		t.Fatalf("Retrograde: %s", describeError(err))
	}
	if retro == nil || retro.LKAI == nil {
		t.Fatalf("Retrograde returned nil LKAI")
	}
	if retro.LKAI.NonCaptive == nil {
		t.Fatalf("Retrograde LKAI.NonCaptive is nil; expected non-captive resolution (LKAI=%+v)", retro.LKAI)
	}
	if !bytes.Equal(retro.LKAI.NonCaptive.RawCOSEKey, originalKey) {
		t.Errorf("Retrograde COSE key differs from Prograde COSE key:\n  Prograde:   %x\n  Retrograde: %x",
			originalKey, retro.LKAI.NonCaptive.RawCOSEKey)
	}
}

// TestRetrograde_AttributeSetMismatchRejected pins the AAD binding
// between a LeaseRef and the AttributeSet it was minted under: a
// Retrograde quoting the original LeaseRef but a different AttributeSet
// must fail with CodeInvalidRef. The keyserver passes the caller-
// supplied AttributeSet's Repr to the macwrapper Unwrap as AAD; any
// disagreement with the AAD baked into the ref at Prograde time
// surfaces as an Unwrap failure, mapped to ErrInvalidRef.
//
// Without this test, a regression that dropped the AAD binding (or
// silently re-derived a key for the wrong attrset) would let two
// callers with different attribute sets share a Lease — exactly the
// confused-deputy condition the binding exists to prevent.
func TestRetrograde_AttributeSetMismatchRejected(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	client := srv.Client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	asMint, err := attrset.New(map[string]any{"env": "test", "tier": "gold"})
	if err != nil {
		t.Fatalf("attrset.New mint: %v", err)
	}
	asOther, err := attrset.New(map[string]any{"env": "test", "tier": "silver"})
	if err != nil {
		t.Fatalf("attrset.New other: %v", err)
	}

	pro, err := client.Prograde(ctx, ckap.ProgradeRequest{AttributeSet: asMint})
	if err != nil {
		t.Fatalf("Prograde: %s", describeError(err))
	}

	resp, err := client.Retrograde(ctx, ckap.RetrogradeRequest{
		AttributeSet: asOther,
		LeaseRef:     pro.Lease.LeaseRef,
	})
	if err == nil {
		t.Fatalf("Retrograde with mismatched attrset: want error, got resp=%+v", resp)
	}
	var cerr *ckap.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("Retrograde: want *ckap.Error, got %T: %v", err, err)
	}
	if cerr.Code != cabe.CodeInvalidRef {
		t.Errorf("Retrograde: code = %d, want CodeInvalidRef (%d) — %s",
			cerr.Code, cabe.CodeInvalidRef, describeError(err))
	}
}
