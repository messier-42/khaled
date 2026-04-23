package httpmw_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/messier-42/khaled/pkg/httpmw"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// stubMapper is a ClaimsMapper returning a fixed principal or error.
type stubMapper struct {
	p   policyengine.Principal
	err error
}

func (s stubMapper) Map(context.Context, clientauthn.ClientIdentity) (policyengine.Principal, error) {
	return s.p, s.err
}
func (s stubMapper) Close() error { return nil }

// mapperSource returns a fixed ClaimsMapper on every call; used to
// adapt a plain value to the per-request src func.
func mapperSource(m claimsmapping.ClaimsMapper) func() claimsmapping.ClaimsMapper {
	return func() claimsmapping.ClaimsMapper { return m }
}

func TestMapClaimsRequiresAuthenticateFirst(t *testing.T) {
	src := mapperSource(stubMapper{})

	mw := httpmw.MapClaims(src)
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("inner handler should not run")
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestMapClaimsStashesPrincipal(t *testing.T) {
	want := policyengine.Principal{URI: "spiffe://example.org/x", Claims: map[string]any{"team": "x"}}
	src := mapperSource(stubMapper{p: want})

	var got policyengine.Principal
	mw := httpmw.MapClaims(src)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := httpmw.PrincipalFrom(r.Context())
		if !ok {
			t.Errorf("no principal in context")
			return
		}
		got = p
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	r = r.WithContext(httpmw.WithClientIdentity(r.Context(), stubIdentity("spiffe://example.org/x")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if got.URI != want.URI {
		t.Errorf("URI = %q, want %q", got.URI, want.URI)
	}
}

func TestMapClaims403OnUnknown(t *testing.T) {
	src := mapperSource(stubMapper{err: claimsmapping.ErrPrincipalUnknown})

	mw := httpmw.MapClaims(src)
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("inner handler should not run")
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	r = r.WithContext(httpmw.WithClientIdentity(r.Context(), stubIdentity("spiffe://x")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestMapClaims500OnIdentityUnsupported(t *testing.T) {
	src := mapperSource(stubMapper{err: claimsmapping.ErrIdentityUnsupported})

	mw := httpmw.MapClaims(src)
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("inner handler should not run")
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	r = r.WithContext(httpmw.WithClientIdentity(r.Context(), stubIdentity("spiffe://x")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestMapClaims500OnOtherError(t *testing.T) {
	src := mapperSource(stubMapper{err: errors.New("k8s API timeout")})

	mw := httpmw.MapClaims(src)
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("inner handler should not run")
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	r = r.WithContext(httpmw.WithClientIdentity(r.Context(), stubIdentity("spiffe://x")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestMapClaimsNilMapper(t *testing.T) {
	src := mapperSource(nil)

	mw := httpmw.MapClaims(src)
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("inner handler should not run")
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	r = r.WithContext(httpmw.WithClientIdentity(r.Context(), stubIdentity("spiffe://x")))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}
