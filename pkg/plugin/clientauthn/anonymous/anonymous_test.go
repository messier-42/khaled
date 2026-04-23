package anonymous_test

import (
	"net/http/httptest"
	"testing"

	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn/anonymous"
)

func TestAuthenticateReturnsConfiguredURI(t *testing.T) {
	a := anonymous.New("https://example.test/dev")
	t.Cleanup(func() { _ = a.Close() })

	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://localhost/", nil)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got := id.URI(); got != "https://example.test/dev" {
		t.Errorf("URI() = %q, want %q", got, "https://example.test/dev")
	}
	if _, ok := id.(clientauthn.AnonymousIdentity); !ok {
		t.Errorf("id is %T, want clientauthn.AnonymousIdentity", id)
	}
}

func TestAuthenticateUsesDefaultURIWhenEmpty(t *testing.T) {
	a := anonymous.New("")
	t.Cleanup(func() { _ = a.Close() })

	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://localhost/", nil)
	id, err := a.Authenticate(req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got := id.URI(); got != anonymous.DefaultURI {
		t.Errorf("URI() = %q, want default %q", got, anonymous.DefaultURI)
	}
}

func TestAuthenticateIgnoresRequestState(t *testing.T) {
	a := anonymous.New("https://example.test/dev")
	t.Cleanup(func() { _ = a.Close() })

	// Plaintext request with no TLS, no headers: plugin must not
	// care. Distinct from tls-spiffe, which would reject this with
	// ErrNotTLS.
	req := httptest.NewRequestWithContext(t.Context(), "GET", "http://localhost/", nil)
	if _, err := a.Authenticate(req); err != nil {
		t.Errorf("plaintext request rejected: %v", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	a := anonymous.New("")
	if err := a.Close(); err != nil {
		t.Errorf("first close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
}
