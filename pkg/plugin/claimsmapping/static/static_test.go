package static_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping/static"
)

// stubIdentity is a minimal ClientIdentity implementation for tests.
type stubIdentity string

func (s stubIdentity) URI() string { return string(s) }

func TestNewRejectsEmptyPrincipals(t *testing.T) {
	if _, err := static.New(nil); err == nil {
		t.Fatalf("expected empty principals list to fail")
	}
}

func TestNewRejectsEmptyURI(t *testing.T) {
	_, err := static.New([]static.PrincipalConfig{{URI: "  ", Claims: map[string]string{"k": "v"}}})
	if err == nil {
		t.Fatalf("expected empty uri to fail")
	}
}

func TestNewRejectsBadRegex(t *testing.T) {
	_, err := static.New([]static.PrincipalConfig{{URI: "(", Claims: map[string]string{}}})
	if err == nil {
		t.Fatalf("expected bad regex to fail")
	}
}

func TestNewRejectsBadTemplate(t *testing.T) {
	_, err := static.New([]static.PrincipalConfig{{
		URI:    ".*",
		Claims: map[string]string{"bad": "{{"},
	}})
	if err == nil {
		t.Fatalf("expected bad template to fail")
	}
}

func TestMapSuccess(t *testing.T) {
	m, err := static.New([]static.PrincipalConfig{{
		URI: `spiffe://(?P<td>[^/]+)/ns/(?P<ns>[^/]+)/sa/(?P<sa>[^/]+)/pod/[^/]+/[^/]+`,
		Claims: map[string]string{
			"team":         "{{.URIMatch.ns}}",
			"sa":           "{{.URIMatch.sa}}",
			"trust-domain": "{{.URIMatch.td}}",
			"uri-echo":     "{{.Identity.URI}}",
			"static":       "fixed-value",
		},
	}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer m.Close() // best effort

	p, err := m.Map(context.Background(),
		stubIdentity("spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1"))
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	if want := "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1"; p.URI != want {
		t.Errorf("URI = %q, want %q", p.URI, want)
	}

	for k, want := range map[string]string{
		"team":         "prod",
		"sa":           "app",
		"trust-domain": "example.org",
		"uri-echo":     "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1",
		"static":       "fixed-value",
	} {
		got, ok := p.Claims[k]
		if !ok {
			t.Errorf("claims[%q] missing", k)
			continue
		}
		if got != want {
			t.Errorf("claims[%q] = %v, want %q", k, got, want)
		}
	}
}

func TestMapAnchorsRegexFully(t *testing.T) {
	// Operator writes `foo` without ^$ — should NOT match `xfooy`.
	m, _ := static.New([]static.PrincipalConfig{{
		URI:    "foo",
		Claims: map[string]string{"c": "x"},
	}})
	defer m.Close() // best effort

	if _, err := m.Map(context.Background(), stubIdentity("xfooy")); !errors.Is(err, claimsmapping.ErrPrincipalUnknown) {
		t.Errorf("expected ErrPrincipalUnknown for partial-match, got %v", err)
	}
	if _, err := m.Map(context.Background(), stubIdentity("foo")); err != nil {
		t.Errorf("expected exact match to succeed, got %v", err)
	}
}

func TestMapFirstMatchWins(t *testing.T) {
	m, _ := static.New([]static.PrincipalConfig{
		{URI: "spiffe://example.org/a.*", Claims: map[string]string{"which": "first"}},
		{URI: "spiffe://example.org/.*", Claims: map[string]string{"which": "second"}},
	})
	defer m.Close() // best effort

	p, err := m.Map(context.Background(), stubIdentity("spiffe://example.org/alpha"))
	if err != nil {
		t.Fatalf("map: %v", err)
	}
	if got := p.Claims["which"]; got != "first" {
		t.Errorf("first-match winner = %v, want first", got)
	}
}

func TestMapUnmatchedReturnsPrincipalUnknown(t *testing.T) {
	m, _ := static.New([]static.PrincipalConfig{{
		URI:    "spiffe://example.org/.*",
		Claims: map[string]string{"c": "x"},
	}})
	defer m.Close() // best effort

	_, err := m.Map(context.Background(), stubIdentity("spiffe://other.example/x"))
	if !errors.Is(err, claimsmapping.ErrPrincipalUnknown) {
		t.Errorf("err = %v, want ErrPrincipalUnknown", err)
	}
}

// TestNewRejectsTemplateReferencingUnknownCapture verifies that a
// claim template referencing a URIMatch key not declared by the
// regex is caught at construction time (config error) rather than
// surfacing as a per-request 403 once traffic starts.
func TestNewRejectsTemplateReferencingUnknownCapture(t *testing.T) {
	_, err := static.New([]static.PrincipalConfig{{
		URI:    `spiffe://(?P<td>[^/]+)/.*`,
		Claims: map[string]string{"c": "{{.URIMatch.nonexistent}}"},
	}})
	if err == nil {
		t.Fatal("expected New to reject template referencing unknown capture")
	}
	if !strings.Contains(err.Error(), "nonexistent") {
		t.Errorf("error does not mention the missing key: %v", err)
	}
}

// TestNewAcceptsTemplateReferencingDeclaredCapture is the
// positive-path complement: a template that references a capture
// the regex actually declares passes probe-time validation.
func TestNewAcceptsTemplateReferencingDeclaredCapture(t *testing.T) {
	if _, err := static.New([]static.PrincipalConfig{{
		URI:    `spiffe://(?P<td>[^/]+)/.*`,
		Claims: map[string]string{"c": "{{.URIMatch.td}}"},
	}}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestAnchoring_PreAnchoredPatternAccepted verifies that an
// operator-supplied pattern that is already anchored (^...$) is not
// broken by the wrapping. The naive prefix/suffix fix-up would
// produce ^^...$$, which the regex engine accepts as a no-op; the
// "^(?:...)$" wrapping preserves correctness regardless.
func TestAnchoring_PreAnchoredPatternAccepted(t *testing.T) {
	m, err := static.New([]static.PrincipalConfig{{
		URI:    `^spiffe://example\.org/alice$`,
		Claims: map[string]string{"k": "v"},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close() // best effort

	p, err := m.Map(context.Background(), stubIdentity("spiffe://example.org/alice"))
	if err != nil {
		t.Fatalf("Map exact match: %v", err)
	}
	if p.URI != "spiffe://example.org/alice" {
		t.Errorf("URI = %q", p.URI)
	}
}

// TestAnchoring_InlineFlagsAccepted verifies that a pattern
// beginning with an inline flag group (e.g. (?i) for case-insensitive)
// is handled correctly. The naive prefix check would prepend ^ to
// produce ^(?i)..., making the ^ apply before flags took effect;
// the "^(?:...)$" wrapping ensures flags apply to the whole match.
func TestAnchoring_InlineFlagsAccepted(t *testing.T) {
	m, err := static.New([]static.PrincipalConfig{{
		URI:    `(?i)spiffe://example\.org/ALICE`,
		Claims: map[string]string{"k": "v"},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close() // best effort

	// Case-insensitive: lower-case "alice" should match.
	if _, err := m.Map(context.Background(), stubIdentity("spiffe://example.org/alice")); err != nil {
		t.Fatalf("case-insensitive Map: %v", err)
	}
}

// TestAnchoring_TrailingLiteralDollar verifies a pattern that ends
// in an escaped dollar (\$, meaning a literal $ in the URI) is not
// mishandled. The naive suffix check saw any '$' at the end and
// skipped appending, leaving the pattern unanchored at the end.
func TestAnchoring_TrailingLiteralDollar(t *testing.T) {
	m, err := static.New([]static.PrincipalConfig{{
		URI:    `spiffe://example\.org/alice\$`,
		Claims: map[string]string{"k": "v"},
	}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer m.Close() // best effort

	// The correct anchoring is "^(?:spiffe://example\.org/alice\$)$" —
	// matches an exact URI ending in a literal $ and nothing else.
	if _, err := m.Map(context.Background(), stubIdentity("spiffe://example.org/alice$")); err != nil {
		t.Fatalf("exact literal-dollar URI should match: %v", err)
	}
	// Trailing junk after the literal $ must not match (would
	// succeed with the old unanchored-at-end form).
	if _, err := m.Map(context.Background(), stubIdentity("spiffe://example.org/alice$extra")); err == nil {
		t.Error("trailing-junk URI incorrectly matched; anchor is still broken at end")
	}
}

func TestMapRejectsNilIdentity(t *testing.T) {
	m, _ := static.New([]static.PrincipalConfig{{URI: ".*", Claims: map[string]string{}}})
	defer m.Close() // best effort

	_, err := m.Map(context.Background(), nil)
	if !errors.Is(err, claimsmapping.ErrIdentityUnsupported) {
		t.Errorf("err = %v, want ErrIdentityUnsupported for nil identity", err)
	}
}
