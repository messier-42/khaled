package httpmw_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/messier-42/khaled/pkg/httpmw"
	klog "github.com/messier-42/khaled/pkg/log"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// TestChain_LoggingAuthenticateMapClaims_HappyPath wires the three
// middleware in the order doc.go documents and asserts each one's
// context contribution reaches the inner handler:
//
//   - Logging attaches a correlationID via klog.
//   - Authenticate attaches a ClientIdentity.
//   - MapClaims attaches a Principal.
//
// The test exercises the integration contract that the isolated-layer
// tests in authn_test.go / claims_test.go / logging_test.go cannot,
// because each runs its middleware standalone. Regression fence for
// subtle ordering bugs (e.g. MapClaims reading the context before
// Authenticate populates it).
func TestChain_LoggingAuthenticateMapClaims_HappyPath(t *testing.T) {
	wantPrincipal := policyengine.Principal{
		URI:    "spiffe://example.org/alice",
		Claims: map[string]any{"team": "x"},
	}
	authnSrc := authnSource(stubAuthenticator{id: stubIdentity(wantPrincipal.URI)})
	mapperSrc := mapperSource(stubMapper{p: wantPrincipal})

	var sawCorrelationID string
	var sawIdentity clientauthn.ClientIdentity
	var sawPrincipal policyengine.Principal
	var sawIdentityOK, sawPrincipalOK bool

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCorrelationID, _ = klog.CorrelationID(r.Context())
		sawIdentity, sawIdentityOK = httpmw.ClientIdentityFrom(r.Context())
		sawPrincipal, sawPrincipalOK = httpmw.PrincipalFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	chain := httpmw.Logging(httpmw.Authenticate(authnSrc)(httpmw.MapClaims(mapperSrc)(inner)))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if sawCorrelationID == "" {
		t.Error("correlationID not attached by Logging")
	}
	if !sawIdentityOK || sawIdentity.URI() != wantPrincipal.URI {
		t.Errorf("identity not attached: ok=%v uri=%q", sawIdentityOK, identityURI(sawIdentity))
	}
	if !sawPrincipalOK || sawPrincipal.URI != wantPrincipal.URI {
		t.Errorf("principal not attached: ok=%v uri=%q", sawPrincipalOK, sawPrincipal.URI)
	}
}

// TestChain_AuthenticateFailureShortCircuitsMapper ensures MapClaims
// does not run when Authenticate rejects the request. A missing
// short-circuit would surface as 500 (MapClaims "called without
// Authenticate") instead of the 401 Authenticate produced.
func TestChain_AuthenticateFailureShortCircuitsMapper(t *testing.T) {
	authnSrc := authnSource(stubAuthenticator{err: errors.New("bad sig")})
	mapperRan := false
	mapperSrc := mapperSource(mapperHook(func() (policyengine.Principal, error) {
		mapperRan = true
		return policyengine.Principal{}, errors.New("unreachable")
	}))

	innerRan := false
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		innerRan = true
	})

	chain := httpmw.Logging(httpmw.Authenticate(authnSrc)(httpmw.MapClaims(mapperSrc)(inner)))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if mapperRan {
		t.Error("MapClaims ran despite Authenticate failure")
	}
	if innerRan {
		t.Error("inner handler ran despite Authenticate failure")
	}
}

// TestChain_MapClaimsDenyShortCircuitsHandler pins that a mapper
// denial (403) stops the inner handler from seeing the request.
func TestChain_MapClaimsDenyShortCircuitsHandler(t *testing.T) {
	authnSrc := authnSource(stubAuthenticator{id: stubIdentity("spiffe://x")})
	mapperSrc := mapperSource(stubMapper{err: claimsmapping.ErrPrincipalUnknown})

	innerRan := false
	inner := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		innerRan = true
	})

	chain := httpmw.Logging(httpmw.Authenticate(authnSrc)(httpmw.MapClaims(mapperSrc)(inner)))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
	if innerRan {
		t.Error("inner handler ran despite claims-mapping denial")
	}
}

// mapperHook is a ClaimsMapper that invokes a closure on Map.
type mapperHook func() (policyengine.Principal, error)

func (f mapperHook) Map(context.Context, clientauthn.ClientIdentity) (policyengine.Principal, error) {
	return f()
}
func (f mapperHook) Close() error { return nil }

func identityURI(id clientauthn.ClientIdentity) string {
	if id == nil {
		return ""
	}
	return id.URI()
}
