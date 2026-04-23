package httpmw_test

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/httpmw"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
)

// stubAuthenticator returns id or err on every call.
type stubAuthenticator struct {
	id  clientauthn.ClientIdentity
	err error
}

func (s stubAuthenticator) Authenticate(*http.Request) (clientauthn.ClientIdentity, error) {
	return s.id, s.err
}
func (s stubAuthenticator) Close() error { return nil }

// authnSource returns a fixed Authenticator on every call; used to
// adapt a plain value to the per-request src func.
func authnSource(a clientauthn.Authenticator) func() clientauthn.Authenticator {
	return func() clientauthn.Authenticator { return a }
}

type stubIdentity string

func (s stubIdentity) URI() string { return string(s) }

func TestAuthenticateStashesIdentity(t *testing.T) {
	src := authnSource(stubAuthenticator{id: stubIdentity("spiffe://example.org/x")})

	var sawURI string
	mw := httpmw.Authenticate(src)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := httpmw.ClientIdentityFrom(r.Context())
		if !ok {
			t.Errorf("expected identity in context")
			return
		}
		sawURI = id.URI()
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if sawURI != "spiffe://example.org/x" {
		t.Errorf("uri = %q", sawURI)
	}
}

func TestAuthenticateRejectsNilAuthenticator(t *testing.T) {
	src := authnSource(nil)

	mw := httpmw.Authenticate(src)
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("inner handler should not run")
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assertCKAPError(t, w, http.StatusInternalServerError, cabe.CodeInternal)
}

func TestAuthenticate401OnAuthFailure(t *testing.T) {
	src := authnSource(stubAuthenticator{err: errors.New("bad sig")})

	mw := httpmw.Authenticate(src)
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("inner handler should not run")
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assertCKAPError(t, w, http.StatusUnauthorized, cabe.CodeUnauthorized)
}

func TestAuthenticate401OnNotTLS(t *testing.T) {
	src := authnSource(stubAuthenticator{err: clientauthn.ErrNotTLS})

	mw := httpmw.Authenticate(src)
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assertCKAPError(t, w, http.StatusUnauthorized, cabe.CodeUnauthorized)
}

// assertCKAPError pins both the HTTP status and the requirement
// that the response body be a CBOR-framed CKAP Error structure
// under application/ckap+cbor — what cabe-go's ckapclient parses
// into a typed *ckap.Error. A plain-text response (the bug this
// suite was strengthened to catch) would fail the Content-Type
// check and the Unmarshal both.
func assertCKAPError(t *testing.T, w *httptest.ResponseRecorder, wantStatus int, wantCode cabe.Code) {
	t.Helper()
	if w.Code != wantStatus {
		t.Errorf("status = %d, want %d", w.Code, wantStatus)
	}
	if got := w.Header().Get("Content-Type"); got != ckap.MediaType {
		t.Errorf("Content-Type = %q, want %q", got, ckap.MediaType)
	}
	var body ckapraw.Error
	if err := cbor.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body as CBOR: %v (raw=%x)", err, w.Body.Bytes())
	}
	if body.Kind != ckapraw.KindError {
		t.Errorf("Kind = %q, want %q", body.Kind, ckapraw.KindError)
	}
	if cabe.Code(body.ErrorCode) != wantCode {
		t.Errorf("ErrorCode = %d, want %d", body.ErrorCode, wantCode)
	}
}

func TestAuthenticatePassesTLSStateToAuthenticator(t *testing.T) {
	var sawTLS bool
	checker := stubAuthenticator{}
	checker.id = stubIdentity("x")
	src := authnSource(authenticatorFunc(func(r *http.Request) (clientauthn.ClientIdentity, error) {
		sawTLS = r.TLS != nil
		return checker.id, nil
	}))

	mw := httpmw.Authenticate(src)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequestWithContext(t.Context(), "GET", "/", nil)
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if !sawTLS {
		t.Errorf("authenticator did not see r.TLS")
	}
}

// authenticatorFunc is a test helper adapting a function to the
// clientauthn.Authenticator interface.
type authenticatorFunc func(r *http.Request) (clientauthn.ClientIdentity, error)

func (f authenticatorFunc) Authenticate(r *http.Request) (clientauthn.ClientIdentity, error) {
	return f(r)
}
func (f authenticatorFunc) Close() error { return nil }
