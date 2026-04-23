// Package claimsmapping defines the Claims Mapping plugin interface.
//
// A ClaimsMapper translates an authenticated clientauthn.ClientIdentity
// into a policyengine.Principal (URI + Claims) that the Policy Engine
// evaluates. This is not authorization but a precursor to it;
// authorization is a decision made by the Policy Engine as a result of
// it evaluating its policy against the resulting Claims.
//
// Not every mapper accepts every ClientIdentity. A mapper may return
// ErrIdentityUnsupported when the authenticator's identity type is not
// supported. This mismatch reflects a server configuration error if it
// occurs.
//
// ErrPrincipalUnknown can be used to represent the circumstance where
// no principal maps to a given identity. This reflects denial, not a
// server error, and is mapped to HTTP 403 in the HTTP transport.
package claimsmapping

import (
	"context"
	"errors"
	"io"

	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// ClaimsMapper instances map an authenticated ClientIdentity to a Principal
// suitable for the Policy Engine.
//
// Implementations must be safe for concurrent use; middleware invokes
// Map once per request. Close releases any long-lived resources
// (connection pools, caches, ticker goroutines); it does not need to
// cancel in-flight Map calls.
type ClaimsMapper interface {
	io.Closer

	// Map derives a Principal from id. The returned error, if any,
	// categorises the failure:
	//
	//   - ErrIdentityUnsupported: the concrete ClientIdentity type
	//     is not compatible with this mapper (e.g. k8s-attestation
	//     received a non-SPIFFE identity). This is a config error;
	//     middleware responds with HTTP 500.
	//
	//   - ErrPrincipalUnknown: the identity is recognised but no
	//     principal can be derived (e.g. static mapper found no
	//     matching URI entry, or k8s-attestation's pod UID
	//     verification failed). Middleware responds with HTTP 403.
	//
	//   - Any other error: treated as an internal failure;
	//     middleware responds with HTTP 500.
	Map(ctx context.Context, id clientauthn.ClientIdentity) (policyengine.Principal, error)
}

// ErrIdentityUnsupported indicates a configuration mismatch: the
// authenticator produced a ClientIdentity of a concrete type that
// this mapper does not accept.
var ErrIdentityUnsupported = errors.New("claimsmapping: authenticated identity type not supported by mapper")

// ErrPrincipalUnknown indicates that the mapper recognises the
// identity's shape but cannot derive a principal from it.
var ErrPrincipalUnknown = errors.New("claimsmapping: no principal matches authenticated identity")
