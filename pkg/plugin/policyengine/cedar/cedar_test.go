package cedar_test

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/plugin/policyengine/cedar"
)

func mustSet(t *testing.T, m map[string]any) attrset.Set {
	t.Helper()
	s, err := attrset.New(m)
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}
	return s
}

func mustEngine(t *testing.T, src string) *cedar.Engine {
	t.Helper()
	eng, err := cedar.New(cedar.Config{PolicyText: []byte(src)})
	if err != nil {
		t.Fatalf("cedar.New: %v", err)
	}
	return eng
}

func TestNew_InvalidPolicy(t *testing.T) {
	if _, err := cedar.New(cedar.Config{PolicyText: []byte("not cedar")}); err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestDecideEncapsulate_EmptyDeniesAll(t *testing.T) {
	eng := mustEngine(t, "")
	defer eng.Close() // best effort

	d, err := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "spiffe://x/alice"},
		AttributeSet: mustSet(t, map[string]any{"tenant": "acme"}),
		Now:          time.Now(),
	})
	if err != nil {
		t.Fatalf("DecideEncapsulate: %v", err)
	}
	if d.Allow {
		t.Errorf("empty policy: expected deny, got allow")
	}
	if d.Reason == "" {
		t.Errorf("expected a reason on default deny")
	}
}

func TestDecideEncapsulate_MissingPrincipalURI(t *testing.T) {
	eng := mustEngine(t, "")
	defer eng.Close() // best effort

	_, err := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		AttributeSet: mustSet(t, nil),
	})
	if err == nil {
		t.Errorf("expected error for empty principal URI")
	}
}

func TestDecideEncapsulate_PermitByPrincipal(t *testing.T) {
	src := `permit(
		principal == Principal::"spiffe://example.org/alice",
		action,
		resource
	);`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	d, err := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "spiffe://example.org/alice"},
		AttributeSet: mustSet(t, map[string]any{"tenant": "acme"}),
	})
	if err != nil {
		t.Fatalf("DecideEncapsulate: %v", err)
	}
	if !d.Allow {
		t.Errorf("want allow, got deny (reason=%q, diag=%v)", d.Reason, d.Diagnostics)
	}
	if len(d.DeterminingPolicies) != 1 {
		t.Errorf("DeterminingPolicies = %v, want 1 entry", d.DeterminingPolicies)
	}
}

func TestDecideEncapsulate_PermitWrongPrincipal(t *testing.T) {
	src := `permit(
		principal == Principal::"spiffe://example.org/alice",
		action,
		resource
	);`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	d, err := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "spiffe://example.org/bob"},
		AttributeSet: mustSet(t, nil),
	})
	if err != nil {
		t.Fatalf("DecideEncapsulate: %v", err)
	}
	if d.Allow {
		t.Errorf("want deny, got allow")
	}
}

func TestDecide_ActionDistinction(t *testing.T) {
	src := `permit(
		principal,
		action == Action::"Encapsulate",
		resource
	);`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	ctx := context.Background()
	principal := policyengine.Principal{URI: "p"}
	as := mustSet(t, nil)

	if d, _ := eng.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal: principal, AttributeSet: as,
	}); !d.Allow {
		t.Errorf("Encapsulate should be allowed")
	}

	if d, _ := eng.DecideDecapsulate(ctx, policyengine.DecapsulateRequest{
		Principal: principal, AttributeSet: as,
	}); d.Allow {
		t.Errorf("Decapsulate should be denied")
	}
}

func TestDecide_AttributeSetGate(t *testing.T) {
	src := `permit(
		principal,
		action,
		resource
	) when { resource.tenant == "acme" };`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	ctx := context.Background()
	principal := policyengine.Principal{URI: "p"}

	if d, _ := eng.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal: principal, AttributeSet: mustSet(t, map[string]any{"tenant": "acme"}),
	}); !d.Allow {
		t.Errorf("tenant=acme should be allowed")
	}

	if d, _ := eng.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal: principal, AttributeSet: mustSet(t, map[string]any{"tenant": "zorg"}),
	}); d.Allow {
		t.Errorf("tenant=zorg should be denied")
	}
}

func TestDecide_ClaimsGate(t *testing.T) {
	src := `permit(
		principal,
		action,
		resource
	) when { principal.admin == true };`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	ctx := context.Background()
	as := mustSet(t, nil)

	if d, _ := eng.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p", Claims: map[string]any{"admin": true}},
		AttributeSet: as,
	}); !d.Allow {
		t.Errorf("admin=true should be allowed")
	}

	if d, _ := eng.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p", Claims: map[string]any{"admin": false}},
		AttributeSet: as,
	}); d.Allow {
		t.Errorf("admin=false should be denied")
	}
}

func TestDecide_ForbidOverridesPermit(t *testing.T) {
	src := `permit(principal, action, resource);
forbid(principal, action, resource) when { resource.danger == true };`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	d, _ := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p"},
		AttributeSet: mustSet(t, map[string]any{"danger": true}),
	})
	if d.Allow {
		t.Errorf("forbid should override permit")
	}
	if !strings.Contains(d.Reason, "forbidden") {
		t.Errorf("expected forbidden reason, got %q", d.Reason)
	}
}

// TestDecide_FloatClaim verifies that a float64 claim value is
// converted to Cedar's Decimal rather than rejected. A prior
// implementation errored on any float, blocking any attrset or
// claim that carried a floating-point value.
func TestDecide_FloatClaim(t *testing.T) {
	eng := mustEngine(t, "")
	defer eng.Close() // best effort

	_, err := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal: policyengine.Principal{
			URI:    "p",
			Claims: map[string]any{"weight": 1.5},
		},
		AttributeSet: mustSet(t, nil),
	})
	if err != nil {
		t.Fatalf("float64 claim should convert to Decimal, got error: %v", err)
	}
}

// TestDecide_UnrepresentableFloat confirms that values Decimal
// cannot represent (NaN, Inf, excessive magnitude) are rejected
// with a clear error rather than silently rounded, so policies
// cannot treat "close-but-not-equal" inputs as equal.
func TestDecide_UnrepresentableFloat(t *testing.T) {
	eng := mustEngine(t, "")
	defer eng.Close() // best effort

	_, err := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal: policyengine.Principal{
			URI:    "p",
			Claims: map[string]any{"weight": math.Inf(1)},
		},
		AttributeSet: mustSet(t, nil),
	})
	if err == nil {
		t.Errorf("expected conversion error for +Inf claim")
	}
}

func TestDecide_IntegerClaimTypes(t *testing.T) {
	src := `permit(principal, action, resource) when { principal.level > 2 };`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	ctx := context.Background()

	if d, _ := eng.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p", Claims: map[string]any{"level": int64(3)}},
		AttributeSet: mustSet(t, nil),
	}); !d.Allow {
		t.Errorf("level=3 should be allowed")
	}
	if d, _ := eng.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p", Claims: map[string]any{"level": int64(1)}},
		AttributeSet: mustSet(t, nil),
	}); d.Allow {
		t.Errorf("level=1 should be denied")
	}
}

// TestDecide_TemporalClaimViaContext exercises the wall-clock
// security primitive: a Cedar policy denies Retrograde if the
// principal's grantedSecretClearanceAtTime (Unix µs) is later than
// the authenticated lease mint time. A principal whose clearance
// was granted after the lease was minted cannot decapsulate it.
func TestDecide_TemporalClaimViaContext(t *testing.T) {
	src := `permit(principal, action, resource) when { principal.grantedSecretClearanceAtTime <= context.leaseTime };`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	ctx := context.Background()
	leaseT := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Clearance granted before the lease was minted: allowed.
	d, err := eng.DecideDecapsulate(ctx, policyengine.DecapsulateRequest{
		Principal: policyengine.Principal{
			URI:    "p",
			Claims: map[string]any{"grantedSecretClearanceAtTime": leaseT.Add(-time.Hour).UnixMicro()},
		},
		AttributeSet: mustSet(t, nil),
		Now:          leaseT.Add(time.Minute),
		LeaseTime:    &leaseT,
	})
	if err != nil {
		t.Fatalf("decap (allow case): %v", err)
	}
	if !d.Allow {
		t.Errorf("principal with clearance before lease mint should be allowed")
	}

	// Clearance granted after the lease was minted: denied.
	d, err = eng.DecideDecapsulate(ctx, policyengine.DecapsulateRequest{
		Principal: policyengine.Principal{
			URI:    "p",
			Claims: map[string]any{"grantedSecretClearanceAtTime": leaseT.Add(time.Hour).UnixMicro()},
		},
		AttributeSet: mustSet(t, nil),
		Now:          leaseT.Add(2 * time.Hour),
		LeaseTime:    &leaseT,
	})
	if err != nil {
		t.Fatalf("decap (deny case): %v", err)
	}
	if d.Allow {
		t.Errorf("principal whose clearance was granted after the lease must not be able to decapsulate")
	}
}

// TestDecide_NowInContext verifies the encapsulate path exposes the
// current wall clock as context.now. Policies can embargo
// encapsulation of an attribute set before a configured cutoff.
func TestDecide_NowInContext(t *testing.T) {
	src := `permit(principal, action, resource) when { context.now >= 1735689600000000 };` // 2025-01-01 UTC in µs
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	ctx := context.Background()
	before := time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	if d, _ := eng.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p"},
		AttributeSet: mustSet(t, nil),
		Now:          before,
	}); d.Allow {
		t.Errorf("pre-embargo call should be denied")
	}
	if d, _ := eng.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p"},
		AttributeSet: mustSet(t, nil),
		Now:          after,
	}); !d.Allow {
		t.Errorf("post-embargo call should be allowed")
	}
}

func TestDecide_NestedRecordClaims(t *testing.T) {
	src := `permit(principal, action, resource) when { principal.meta.tier == "gold" };`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	if d, _ := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal: policyengine.Principal{
			URI:    "p",
			Claims: map[string]any{"meta": map[string]any{"tier": "gold"}},
		},
		AttributeSet: mustSet(t, nil),
	}); !d.Allow {
		t.Errorf("nested record claim should allow")
	}
}

// TestDecide_EvaluationErrorYieldsDenyWithDiagnostics pins the
// contract that a Cedar runtime error during policy evaluation
// (e.g. accessing an attribute that does not exist on the
// Principal record) must produce a deny Decision carrying the
// error message in Diagnostics — not a permit, and not a
// Go-level error return. Cedar's "fail-safe deny on error"
// model is security-critical: a silent allow on error would
// bypass every restriction the policy expresses.
func TestDecide_EvaluationErrorYieldsDenyWithDiagnostics(t *testing.T) {
	// The permit references an attribute the Principal does not
	// have. Cedar evaluates the condition, raises an evaluation
	// error, and drops the permit — so the request falls through
	// to the default deny.
	src := `permit(principal, action, resource) when { principal.absentAttr == "x" };`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	d, err := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "spiffe://test/alice"},
		AttributeSet: mustSet(t, nil),
	})
	if err != nil {
		t.Fatalf("DecideEncapsulate: %v", err)
	}
	if d.Allow {
		t.Errorf("evaluation error must fail-safe to deny; got allow")
	}
	if len(d.Diagnostics) == 0 {
		t.Errorf("expected Diagnostics populated from Cedar evaluation error; got %+v", d)
	}
}

// TestDecide_Concurrent pins the package doc's "safe for concurrent
// use" guarantee. A single Engine is shared across many goroutines
// issuing alternating Encapsulate/Decapsulate calls. Under `-race`,
// any unsynchronised mutation of the underlying PolicySet would be
// flagged; a data-corruption would manifest as divergent Decisions
// across the racers.
func TestDecide_Concurrent(t *testing.T) {
	src := `permit(
		principal == Principal::"spiffe://test/alice",
		action,
		resource
	);`
	eng := mustEngine(t, src)
	defer eng.Close() // best effort

	const (
		racers  = 16
		rounds  = 64
		goodURI = "spiffe://test/alice"
		badURI  = "spiffe://test/mallory"
	)

	done := make(chan error, racers)
	for i := range racers {
		go func() {
			for range rounds {
				// Alternate the principal so each racer sees a
				// mix of allow and deny verdicts. Alternate the
				// action so both DecideEncapsulate and
				// DecideDecapsulate are exercised concurrently.
				useGood := (i % 2) == 0
				uri := badURI
				if useGood {
					uri = goodURI
				}
				req := policyengine.EncapsulateRequest{
					Principal:    policyengine.Principal{URI: uri},
					AttributeSet: mustSet(t, nil),
					Now:          time.Now(),
				}
				d, err := eng.DecideEncapsulate(context.Background(), req)
				if err != nil {
					done <- err
					return
				}
				if d.Allow != useGood {
					done <- unexpectedVerdictError{allow: d.Allow, want: useGood}
					return
				}
				dreq := policyengine.DecapsulateRequest{
					Principal:    policyengine.Principal{URI: uri},
					AttributeSet: mustSet(t, nil),
					Now:          time.Now(),
					LeaseTime:    new(time.Now()),
				}
				d, err = eng.DecideDecapsulate(context.Background(), dreq)
				if err != nil {
					done <- err
					return
				}
				if d.Allow != useGood {
					done <- unexpectedVerdictError{allow: d.Allow, want: useGood}
					return
				}
			}
			done <- nil
		}()
	}
	for range racers {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Decide failed: %v", err)
		}
	}
}

type unexpectedVerdictError struct {
	allow bool
	want  bool
}

func (e unexpectedVerdictError) Error() string {
	return "unexpected verdict"
}
