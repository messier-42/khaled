package plugin

import (
	"context"
	"errors"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"

	"github.com/messier-42/khaled/pkg/config/schema"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn/anonymous"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn/tlsca"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn/tlsspiffe"
)

// AuthenticatorArgs provides the inputs used to instantiate a Client
// Authentication plugin.
type AuthenticatorArgs struct {
	// PluginName is the name of the Authenticator plugin to use
	// (e.g. "tls-spiffe").
	PluginName string

	// Bundles is the SPIFFE trust-bundle source consumed by the
	// tls-spiffe plugin. May be nil when instantiating other plugins.
	Bundles x509bundle.Source

	// Anonymous holds configuration for the "anonymous" plugin. It is
	// ignored by other plugins. Its zero value is valid: an empty URI
	// causes the anonymous plugin to use its DefaultURI.
	Anonymous AnonymousArgs

	// TLSCA holds configuration for the "tls-ca" plugin. It is
	// ignored by other plugins.
	TLSCA TLSCAArgs
}

// AnonymousArgs holds the per-plugin configuration for the
// "anonymous" Client Authentication plugin.
type AnonymousArgs struct {
	// URI is the identity URI the plugin emits for every request.
	// An empty value selects anonymous.DefaultURI.
	URI string
}

// TLSCAArgs holds the per-plugin configuration for the "tls-ca"
// Client Authentication plugin.
type TLSCAArgs struct {
	// CABundlePath is the filesystem path to a PEM file containing
	// one or more CA certificates. Required when PluginName is
	// "tls-ca".
	CABundlePath string
}

var clientAuthnFactory = func() *Factory[AuthenticatorArgs, clientauthn.Authenticator] {
	f := NewFactory[AuthenticatorArgs, clientauthn.Authenticator]("client authentication")
	f.Register("tls-spiffe",
		func(_ context.Context, a AuthenticatorArgs) (clientauthn.Authenticator, error) {
			if a.Bundles == nil {
				return nil, errors.New("tls-spiffe: trust bundle source is required")
			}
			return tlsspiffe.New(a.Bundles)
		},
		tlsspiffe.RegisterSchema)
	f.Register("anonymous",
		func(_ context.Context, a AuthenticatorArgs) (clientauthn.Authenticator, error) {
			return anonymous.New(a.Anonymous.URI), nil
		},
		anonymous.RegisterSchema)
	f.Register("tls-ca",
		func(_ context.Context, a AuthenticatorArgs) (clientauthn.Authenticator, error) {
			return tlsca.New(a.TLSCA.CABundlePath)
		},
		tlsca.RegisterSchema)
	return f
}()

// NewAuthenticator instantiates an Authenticator given the specified
// arguments. Returns an error for an unknown plugin name or a
// plugin-specific construction failure.
func NewAuthenticator(ctx context.Context, args AuthenticatorArgs) (clientauthn.Authenticator, error) {
	return clientAuthnFactory.Build(ctx, args.PluginName, args)
}

// RegisterClientAuthnSchemas contributes every client authentication
// plugin's schema.
func RegisterClientAuthnSchemas(r *schema.Registry) error {
	return clientAuthnFactory.RegisterSchemas(r)
}
