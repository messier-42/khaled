package httpmw

import (
	"context"

	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// ctxKey is an internal type used to key request-scoped values
// added to an HTTP request by the Authenticate and MapClaims middleware.
type ctxKey int

const (
	ctxKeyClientIdentity ctxKey = iota + 1 // client authn identity
	ctxKeyPrincipal                        // mapped principal
)

// WithClientIdentity returns a copy of ctx carrying an established
// client identity for authentication purposes.
func WithClientIdentity(ctx context.Context, id clientauthn.ClientIdentity) context.Context {
	return context.WithValue(ctx, ctxKeyClientIdentity, id)
}

// ClientIdentityFrom returns the ClientIdentity attached to ctx by
// WithClientIdentity.
func ClientIdentityFrom(ctx context.Context) (clientauthn.ClientIdentity, bool) {
	v, ok := ctx.Value(ctxKeyClientIdentity).(clientauthn.ClientIdentity)
	return v, ok
}

// WithPrincipal returns a copy of ctx carrying principal p.
func WithPrincipal(ctx context.Context, p policyengine.Principal) context.Context {
	return context.WithValue(ctx, ctxKeyPrincipal, p)
}

// PrincipalFrom returns the Principal attached to ctx by WithPrincipal.
func PrincipalFrom(ctx context.Context) (policyengine.Principal, bool) {
	v, ok := ctx.Value(ctxKeyPrincipal).(policyengine.Principal)
	return v, ok
}
