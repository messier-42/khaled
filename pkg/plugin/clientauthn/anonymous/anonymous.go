// Package anonymous implements the "anonymous" Client Authentication
// plugin: every request is accepted without credentials and mapped to
// a single configured identity URI.
//
// This plugin exists strictly for local developer testing. It
// refuses nothing and carries no access control of its own; any
// deployment that enables it has effectively disabled authentication.
package anonymous

import (
	"log/slog"
	"net/http"

	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
)

// DefaultURI is the AnonymousIdentity URI emitted when the config does
// not specify clientAuthn.anonymous.uri. Chosen to be a well-known URI.
const DefaultURI = "https://cabespec.org/anonymous"

// Authenticator is the anonymous implementation of
// clientauthn.Authenticator. The identity is fixed at construction
// and returned verbatim for every request.
type Authenticator struct {
	identity clientauthn.AnonymousIdentity
}

var _ clientauthn.Authenticator = &Authenticator{}

// New constructs an anonymous Authenticator that emits an
// AnonymousIdentity with the given URI for every request. An empty
// URI is replaced with DefaultURI.
func New(uri string) *Authenticator {
	if uri == "" {
		uri = DefaultURI
	}

	slog.Warn("anonymous authenticator in use - UNSAFE IN PRODUCTION - authentication is completely disabled", "uri", uri)

	return &Authenticator{
		identity: clientauthn.NewAnonymousIdentity(uri),
	}
}

func (a *Authenticator) Close() error { return nil }

// Authenticate ignores the request entirely and returns the
// configured AnonymousIdentity. It never returns an error.
func (a *Authenticator) Authenticate(_ *http.Request) (clientauthn.ClientIdentity, error) {
	return a.identity, nil
}
