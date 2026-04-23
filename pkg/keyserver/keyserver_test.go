package keyserver_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/keyschedule"
	"github.com/messier-42/khaled/pkg/keyserver"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/plugin/keystorage/disk"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/wrapper/macwrapper"
)

// --- test helpers ---

type stubEngine struct {
	encap func(policyengine.EncapsulateRequest) (policyengine.Decision, error)
	decap func(policyengine.DecapsulateRequest) (policyengine.Decision, error)
}

func (e *stubEngine) DecideEncapsulate(_ context.Context, req policyengine.EncapsulateRequest) (policyengine.Decision, error) {
	if e.encap != nil {
		return e.encap(req)
	}
	return policyengine.Decision{Allow: true}, nil
}

func (e *stubEngine) DecideDecapsulate(_ context.Context, req policyengine.DecapsulateRequest) (policyengine.Decision, error) {
	if e.decap != nil {
		return e.decap(req)
	}
	return policyengine.Decision{Allow: true}, nil
}

func (e *stubEngine) Close() error { return nil }

// Engine lets *stubEngine act as its own keyserver.PolicySource.
func (e *stubEngine) Engine() policyengine.Engine { return e }

type fixture struct {
	srv       *keyserver.Server
	sched     *keyschedule.Schedule
	engine    *stubEngine
	domain    keystorage.KeyStoreDomain
	principal policyengine.Principal
}

func newFixture(t *testing.T, opts ...func(*fixture)) *fixture {
	t.Helper()
	ctx := context.Background()
	store, err := disk.New(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("disk.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d, err := store.DomainByName(ctx, "default")
	if err != nil {
		t.Fatalf("Domain: %v", err)
	}
	sched, err := keyschedule.New(t.Context(), keyschedule.Config{Domain: d})
	if err != nil {
		t.Fatalf("keyschedule.New: %v", err)
	}
	t.Cleanup(func() { _ = sched.Close() })
	wrap, err := macwrapper.New(d)
	if err != nil {
		t.Fatalf("macwrapper.New: %v", err)
	}
	eng := &stubEngine{}
	srv, err := keyserver.New(keyserver.Config{
		DomainName:    "default",
		Schedule:      sched,
		Policy:        eng,
		RefWrapper:    wrap,
		LeaseDuration: time.Minute,
		VersionString: "khaled/test go/test test/test",
	})
	if err != nil {
		t.Fatalf("keyserver.New: %v", err)
	}
	f := &fixture{
		srv:       srv,
		sched:     sched,
		engine:    eng,
		domain:    d,
		principal: policyengine.Principal{URI: "spiffe://test/alice"},
	}
	for _, opt := range opts {
		opt(f)
	}
	return f
}

func mustSet(t *testing.T, m map[string]any) attrset.Set {
	t.Helper()
	s, err := attrset.New(m)
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}
	return s
}

// --- construction / validation ---

func TestNew_Validation(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*keyserver.Config)
	}{
		{"no domain name", func(c *keyserver.Config) { c.DomainName = "" }},
		{"no schedule", func(c *keyserver.Config) { c.Schedule = nil }},
		{"no policy", func(c *keyserver.Config) { c.Policy = nil }},
		{"no wrapper", func(c *keyserver.Config) { c.RefWrapper = nil }},
		{"negative lease duration", func(c *keyserver.Config) { c.LeaseDuration = -time.Second }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			cfg := keyserver.Config{
				DomainName:    "default",
				Schedule:      f.sched,
				Policy:        f.engine,
				RefWrapper:    stubWrapper{},
				LeaseDuration: time.Minute,
			}
			tc.mod(&cfg)
			if _, err := keyserver.New(cfg); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

type stubWrapper struct{}

func (stubWrapper) Wrap(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("stub")
}
func (stubWrapper) Unwrap(context.Context, []byte, []byte) ([]byte, error) {
	return nil, errors.New("stub")
}

// --- Prograde ---

func TestPrograde_NonCaptive(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	as := mustSet(t, map[string]any{"sensitivity": "secret"})

	resp, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if err != nil {
		t.Fatalf("Prograde: %v", err)
	}
	if resp.Lease.LKAI.NonCaptive == nil || resp.Lease.LKAI.Captive != nil {
		t.Fatal("expected non-captive LKAI")
	}
	if len(resp.Lease.LKAI.NonCaptive.LeaseKey) != 32 {
		t.Fatalf("lease key len = %d, want 32", len(resp.Lease.LKAI.NonCaptive.LeaseKey))
	}
	if len(resp.Lease.LeaseRef) == 0 {
		t.Fatal("LeaseRef missing")
	}
	if resp.Lease.Expiry.IsZero() {
		t.Fatal("Expiry missing")
	}
	if as.Repr() != resp.Lease.AttributeSet.Repr() {
		t.Fatal("echoed AttributeSet differs from request")
	}
}

func TestPrograde_Captive(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, RequireCaptive: true}, nil
	}
	as := mustSet(t, map[string]any{"k": "v"})

	resp, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if err != nil {
		t.Fatalf("Prograde: %v", err)
	}
	if resp.Lease.LKAI.Captive == nil || resp.Lease.LKAI.NonCaptive != nil {
		t.Fatal("expected captive LKAI")
	}
	if len(resp.Lease.LKAI.Captive.LKAT) == 0 {
		t.Fatal("LKAT missing")
	}
}

func TestPrograde_Denied(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: false, Reason: "nope"}, nil
	}
	_, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal:    f.principal,
		AttributeSet: mustSet(t, nil),
	})
	if !errors.Is(err, keyserver.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	// The deny Reason must not leak into err.Error(): transports
	// rely on the sentinel, not a detail-bearing string.
	if strings.Contains(err.Error(), "nope") {
		t.Fatalf("err.Error() = %q; policy Reason must not appear in returned error", err.Error())
	}
}

func TestPrograde_ARINTokenGivesLeaseID(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	resp, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal:    f.principal,
		AttributeSet: mustSet(t, nil),
		ARINToken:    []byte("token"),
	})
	if err != nil {
		t.Fatalf("Prograde: %v", err)
	}
	if resp.Lease.LeaseID == "" {
		t.Fatal("ARIN token quoted but LeaseID empty")
	}
}

// --- Retrograde ---

func TestRetrograde_NonCaptiveRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	as := mustSet(t, map[string]any{"k": "v"})

	pro, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if err != nil {
		t.Fatalf("Prograde: %v", err)
	}
	retro, err := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{
		Principal: f.principal, AttributeSet: as, LeaseRef: pro.Lease.LeaseRef,
	})
	if err != nil {
		t.Fatalf("Retrograde: %v", err)
	}
	if retro.Lease.LKAI.NonCaptive == nil {
		t.Fatal("expected non-captive")
	}
	if !bytes.Equal(pro.Lease.LKAI.NonCaptive.LeaseKey, retro.Lease.LKAI.NonCaptive.LeaseKey) {
		t.Fatal("retro LeaseKey differs from prograde LeaseKey")
	}
}

func TestRetrograde_CaptiveLeaseRefEscalates(t *testing.T) {
	// A v=1 (captive) LeaseRef must always yield LKAI_Captive on
	// Retrograde, even if current policy would have permitted
	// non-captive.
	ctx := context.Background()
	f := newFixture(t)
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, RequireCaptive: true}, nil
	}
	as := mustSet(t, map[string]any{"k": "v"})

	pro, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if err != nil {
		t.Fatalf("Prograde: %v", err)
	}

	// Relax policy for Retrograde.
	f.engine.decap = func(policyengine.DecapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, RequireCaptive: false}, nil
	}
	retro, err := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{
		Principal: f.principal, AttributeSet: as, LeaseRef: pro.Lease.LeaseRef,
	})
	if err != nil {
		t.Fatalf("Retrograde: %v", err)
	}
	if retro.Lease.LKAI.Captive == nil {
		t.Fatal("captive LeaseRef must escalate to captive LKAI")
	}
	// The escalated LKAT must NOT be the caller's LeaseRef echoed
	// back — it's a distinct v=2 token that identifies the Lease
	// Key independently of the Retrograde request (the client
	// quotes the LKAT, not the LeaseRef, to AssistedEncap/Decap).
	if bytes.Equal(retro.Lease.LKAI.Captive.LKAT, pro.Lease.LeaseRef) {
		t.Fatal("escalation returned the LeaseRef bytes as an LKAT; expected a distinct token")
	}
	// And it must be usable end-to-end as an LKAT.
	wrapResp, err := f.srv.AssistedEncapsulate(ctx, keyserver.AssistedEncapsulateRequest{
		Principal: f.principal,
		LKAT:      retro.Lease.LKAI.Captive.LKAT,
		CEK:       bytes.Repeat([]byte{0x5A}, 32),
	})
	if err != nil {
		t.Fatalf("AssistedEncapsulate with escalated LKAT: %v", err)
	}
	if _, err := f.srv.AssistedDecapsulate(ctx, keyserver.AssistedDecapsulateRequest{
		Principal:  f.principal,
		LKAT:       retro.Lease.LKAI.Captive.LKAT,
		WrappedCEK: wrapResp.WrappedCEK,
	}); err != nil {
		t.Fatalf("AssistedDecapsulate with escalated LKAT: %v", err)
	}
}

func TestRetrograde_PreservesLeaseAcrossRootRotation(t *testing.T) {
	// A LeaseRef minted under a now-retired Root Key must still
	// Retrograde successfully and yield the same Lease Key, because
	// the keystorage retains retired Root Keys indexed by SeqNum.
	ctx := context.Background()
	f := newFixture(t)
	as := mustSet(t, map[string]any{"k": "v"})

	pro, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if err != nil {
		t.Fatalf("Prograde: %v", err)
	}
	if err := f.srv.RotateRootKey(ctx); err != nil {
		t.Fatalf("RotateRootKey: %v", err)
	}
	retro, err := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{
		Principal: f.principal, AttributeSet: as, LeaseRef: pro.Lease.LeaseRef,
	})
	if err != nil {
		t.Fatalf("Retrograde after rotation: %v", err)
	}
	if !bytes.Equal(pro.Lease.LKAI.NonCaptive.LeaseKey, retro.Lease.LKAI.NonCaptive.LeaseKey) {
		t.Fatal("post-rotation Retrograde returned a different Lease Key")
	}
}

func TestAssistedEncapsulate_Denied(t *testing.T) {
	// Revoking the principal between Prograde and AssistedEncapsulate
	// must deny the wrap: every Assisted call re-checks policy.
	ctx := context.Background()
	f := newFixture(t)
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, RequireCaptive: true}, nil
	}
	as := mustSet(t, map[string]any{"k": "v"})
	pro, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if err != nil {
		t.Fatalf("Prograde: %v", err)
	}

	// Flip policy: the encap decision now denies. Prograde's
	// captive decision is already cached in the LKAT, so the deny
	// here tests the AssistedEncapsulate gate specifically.
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: false, Reason: "revoked"}, nil
	}
	_, err = f.srv.AssistedEncapsulate(ctx, keyserver.AssistedEncapsulateRequest{
		Principal: f.principal,
		LKAT:      pro.Lease.LKAI.Captive.LKAT,
		CEK:       bytes.Repeat([]byte{0x7F}, 32),
	})
	if !errors.Is(err, keyserver.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
	if strings.Contains(err.Error(), "revoked") {
		t.Fatalf("err.Error() = %q; policy Reason must not appear in returned error", err.Error())
	}
}

func TestRetrograde_TamperedRef(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	as := mustSet(t, nil)
	pro, _ := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	tampered := append([]byte(nil), pro.Lease.LeaseRef...)
	tampered[len(tampered)-1] ^= 0x01
	_, err := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{
		Principal: f.principal, AttributeSet: as, LeaseRef: tampered,
	})
	if !errors.Is(err, keyserver.ErrInvalidRef) {
		t.Fatalf("err = %v, want ErrInvalidRef", err)
	}
}

func TestRetrograde_WrongAttrSet(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	asA := mustSet(t, map[string]any{"k": "a"})
	asB := mustSet(t, map[string]any{"k": "b"})
	pro, _ := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: asA,
	})
	_, err := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{
		Principal: f.principal, AttributeSet: asB, LeaseRef: pro.Lease.LeaseRef,
	})
	if !errors.Is(err, keyserver.ErrInvalidRef) {
		t.Fatalf("err = %v, want ErrInvalidRef", err)
	}
}

func TestRetrograde_LKATQuotedAsLeaseRef(t *testing.T) {
	// A v=2 LKAT quoted where a v=0/v=1 LeaseRef is expected must
	// be rejected.
	ctx := context.Background()
	f := newFixture(t)
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, RequireCaptive: true}, nil
	}
	as := mustSet(t, map[string]any{"k": "v"})
	pro, _ := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if _, err := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{
		Principal: f.principal, AttributeSet: as, LeaseRef: pro.Lease.LKAI.Captive.LKAT,
	}); !errors.Is(err, keyserver.ErrInvalidRef) {
		t.Fatalf("err = %v, want ErrInvalidRef", err)
	}
}

func TestRetrograde_Denied(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	as := mustSet(t, nil)
	pro, _ := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	f.engine.decap = func(policyengine.DecapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: false, Reason: "revoked"}, nil
	}
	_, err := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{
		Principal: f.principal, AttributeSet: as, LeaseRef: pro.Lease.LeaseRef,
	})
	if !errors.Is(err, keyserver.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

func TestRetrograde_PolicySeesLeaseTime(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	as := mustSet(t, nil)
	pro, _ := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})

	var seen time.Time
	f.engine.decap = func(req policyengine.DecapsulateRequest) (policyengine.Decision, error) {
		seen = req.LeaseTime
		return policyengine.Decision{Allow: true}, nil
	}
	if _, err := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{
		Principal: f.principal, AttributeSet: as, LeaseRef: pro.Lease.LeaseRef,
	}); err != nil {
		t.Fatalf("Retrograde: %v", err)
	}
	if seen.IsZero() {
		t.Fatal("policy did not receive LeaseTime")
	}
	// Minted-at time should be close to now.
	if time.Since(seen) > 5*time.Second {
		t.Fatalf("LeaseTime appears stale: %v", seen)
	}
}

// --- Assisted operations ---

func TestAssistedEncapDecap_RoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, RequireCaptive: true}, nil
	}
	as := mustSet(t, map[string]any{"k": "v"})

	pro, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if err != nil {
		t.Fatalf("Prograde: %v", err)
	}
	cek := bytes.Repeat([]byte{0xAB}, 32)

	wrapResp, err := f.srv.AssistedEncapsulate(ctx, keyserver.AssistedEncapsulateRequest{
		Principal: f.principal, LKAT: pro.Lease.LKAI.Captive.LKAT, CEK: cek,
	})
	if err != nil {
		t.Fatalf("AssistedEncapsulate: %v", err)
	}
	if bytes.Equal(wrapResp.WrappedCEK, cek) {
		t.Fatal("wrapped CEK equals plaintext")
	}
	// Per RFC 3394, wrapped output is plaintext length + 8 bytes.
	if len(wrapResp.WrappedCEK) != len(cek)+8 {
		t.Fatalf("wrapped len = %d, want %d", len(wrapResp.WrappedCEK), len(cek)+8)
	}

	unwrapResp, err := f.srv.AssistedDecapsulate(ctx, keyserver.AssistedDecapsulateRequest{
		Principal: f.principal, LKAT: pro.Lease.LKAI.Captive.LKAT, WrappedCEK: wrapResp.WrappedCEK,
	})
	if err != nil {
		t.Fatalf("AssistedDecapsulate: %v", err)
	}
	if !bytes.Equal(unwrapResp.CEK, cek) {
		t.Fatal("round-trip CEK differs")
	}
}

func TestAssistedEncap_LeaseRefRejected(t *testing.T) {
	// A v=0 LeaseRef quoted as an LKAT must be rejected.
	ctx := context.Background()
	f := newFixture(t)
	as := mustSet(t, nil)
	pro, _ := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	_, err := f.srv.AssistedEncapsulate(ctx, keyserver.AssistedEncapsulateRequest{
		Principal: f.principal,
		LKAT:      pro.Lease.LeaseRef,
		CEK:       bytes.Repeat([]byte{0}, 32),
	})
	if !errors.Is(err, keyserver.ErrInvalidRef) {
		t.Fatalf("err = %v, want ErrInvalidRef", err)
	}
}

func TestAssistedDecap_Denied(t *testing.T) {
	// Revoking the principal between Prograde and AssistedDecapsulate
	// must take effect on the next Assisted call (finer-grained than
	// lease expiry).
	ctx := context.Background()
	f := newFixture(t)
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, RequireCaptive: true}, nil
	}
	as := mustSet(t, nil)
	pro, _ := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	wrapResp, err := f.srv.AssistedEncapsulate(ctx, keyserver.AssistedEncapsulateRequest{
		Principal: f.principal, LKAT: pro.Lease.LKAI.Captive.LKAT, CEK: bytes.Repeat([]byte{1}, 32),
	})
	if err != nil {
		t.Fatalf("AssistedEncapsulate: %v", err)
	}

	// Now revoke.
	f.engine.decap = func(policyengine.DecapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: false, Reason: "revoked"}, nil
	}
	_, err = f.srv.AssistedDecapsulate(ctx, keyserver.AssistedDecapsulateRequest{
		Principal: f.principal, LKAT: pro.Lease.LKAI.Captive.LKAT, WrappedCEK: wrapResp.WrappedCEK,
	})
	if !errors.Is(err, keyserver.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

// --- GetSelf ---

func TestGetSelf(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	resp, err := f.srv.GetSelf(ctx, keyserver.GetSelfRequest{Principal: f.principal})
	if err != nil {
		t.Fatalf("GetSelf: %v", err)
	}
	if resp.Principal.URI != f.principal.URI {
		t.Fatalf("URI = %q, want %q", resp.Principal.URI, f.principal.URI)
	}
	if resp.ServerInfo["domainName"] != "default" {
		t.Fatalf("domainName = %v, want default", resp.ServerInfo["domainName"])
	}
	if v, _ := resp.ServerInfo["version"].(string); v == "" {
		t.Fatal("version empty")
	}
}

func TestGetSelf_EmptyPrincipalURI(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	if _, err := f.srv.GetSelf(ctx, keyserver.GetSelfRequest{
		Principal: policyengine.Principal{},
	}); err == nil {
		t.Fatal("empty principal URI accepted")
	}
}

// --- Admin ops ---

func TestAdmin_AdvanceSubEpochChangesKeys(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	as := mustSet(t, map[string]any{"k": "v"})
	pre, _ := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if err := f.srv.AdvanceSubEpoch(ctx, as); err != nil {
		t.Fatalf("AdvanceSubEpoch: %v", err)
	}
	post, _ := f.srv.Prograde(ctx, keyserver.ProgradeRequest{
		Principal: f.principal, AttributeSet: as,
	})
	if bytes.Equal(pre.Lease.LKAI.NonCaptive.LeaseKey, post.Lease.LKAI.NonCaptive.LeaseKey) {
		t.Fatal("subepoch advance did not change LeaseKey")
	}
}

func TestAdmin_RotateRootKey(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	startCur, _ := f.domain.CurrentRootKey(ctx)
	if err := f.srv.RotateRootKey(ctx); err != nil {
		t.Fatalf("RotateRootKey: %v", err)
	}
	newCur, _ := f.domain.CurrentRootKey(ctx)
	if newCur.SeqNum() <= startCur.SeqNum() {
		t.Fatalf("root did not rotate: %d -> %d", startCur.SeqNum(), newCur.SeqNum())
	}
}

// Sanity that test helpers satisfy io.Closer where applicable.
var _ io.Closer = (*stubEngine)(nil)
