package clientauthn_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
)

func TestSPIFFEIdentityURI(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://example.org/ns/prod/sa/app/pod/pod-1/uid-1")
	ci := clientauthn.NewSPIFFEIdentity(id, nil)

	if got := ci.URI(); got != "spiffe://example.org/ns/prod/sa/app/pod/pod-1/uid-1" {
		t.Errorf("URI() = %q, want SPIFFE ID string", got)
	}
	if got := ci.SPIFFEID(); got != id {
		t.Errorf("SPIFFEID() = %v, want %v", got, id)
	}
}

func TestSPIFFEIdentitySatisfiesClientIdentity(t *testing.T) {
	id := spiffeid.RequireFromString("spiffe://example.org/x")
	var ci clientauthn.ClientIdentity = clientauthn.NewSPIFFEIdentity(id, nil)
	if ci.URI() == "" {
		t.Errorf("expected non-empty URI")
	}
}

func TestAnonymousIdentityURI(t *testing.T) {
	ci := clientauthn.NewAnonymousIdentity("https://cabespec.org/anonymous")
	if got := ci.URI(); got != "https://cabespec.org/anonymous" {
		t.Errorf("URI() = %q, want configured URI", got)
	}
}

func TestAnonymousIdentitySatisfiesClientIdentity(t *testing.T) {
	var ci clientauthn.ClientIdentity = clientauthn.NewAnonymousIdentity("https://example.test/anon")
	if ci.URI() == "" {
		t.Errorf("expected non-empty URI")
	}
}
