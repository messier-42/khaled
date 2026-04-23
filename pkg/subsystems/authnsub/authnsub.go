// Package authnsub provides the client authenticator subsystem.
package authnsub

import (
	"context"
	"errors"
	"fmt"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/lifecycle"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/x509source"
)

// Manager owns the lifecycle of the current Authenticator and
// reconciles it in the event of config reloads. It is a lifecycle.Manager
// configured with the authnsub-specific Apply; the currently-installed
// Authenticator is obtained via Current.
type Manager = lifecycle.Manager[clientauthn.Authenticator]

// argsData captures the config snapshot data that drives client
// authenticator plugin instantiation.
type argsData struct {
	// PluginName is the clientAuthn.use value. An empty value means
	// no authenticator is configured.
	PluginName string

	// AnonymousURI is the clientAuthn.anonymous.uri value. An empty
	// value is tolerated — the anonymous plugin substitutes its
	// DefaultURI. Ignored for other plugins.
	AnonymousURI string

	// TLSCACABundlePath is the clientAuthn.tls-ca.caBundlePath value.
	// Required/used when PluginName is "tls-ca".
	TLSCACABundlePath string
}

// New builds the initial Authenticator from snap and returns a
// Manager that manages its lifecycle.
func New(snap config.Snapshot, spiffe x509source.Source) (*Manager, error) {
	return lifecycle.New(context.Background(), snap, spec(spiffe))
}

// NewEmpty returns a Manager with no current Authenticator. Used
// for testing.
func NewEmpty() *Manager {
	return lifecycle.NewEmpty(spec(nil))
}

// spec returns the lifecycle Spec for this subsystem, closing over
// the SPIFFE source.
func spec(spiffe x509source.Source) lifecycle.Spec[clientauthn.Authenticator] {
	return lifecycle.Spec[clientauthn.Authenticator]{
		Name: "authenticator",
		Apply: func(ctx context.Context, old clientauthn.Authenticator, oldSnap, newSnap config.Snapshot) (clientauthn.Authenticator, error) {
			newArgs := argsFromSnapshot(newSnap)
			if newArgs.PluginName == "" {
				return nil, nil
			}
			if old != nil && argsFromSnapshot(oldSnap) == newArgs {
				return old, nil
			}
			return buildAuthenticator(ctx, newArgs, spiffe)
		},
		Close: func(a clientauthn.Authenticator) error { return a.Close() },
	}
}

// argsFromSnapshot extracts the clientAuthn plugin name from snap
// and builds the argsData.
func argsFromSnapshot(snap config.Snapshot) argsData {
	ca, ok := snap.Root.GetMap("clientAuthn")
	if !ok {
		return argsData{}
	}
	use, _ := ca.GetString("use")
	args := argsData{PluginName: use}
	switch use {
	case "anonymous":
		if anon, ok := ca.GetMap("anonymous"); ok {
			args.AnonymousURI, _ = anon.GetString("uri")
		}
	case "tls-ca":
		if tlsca, ok := ca.GetMap("tls-ca"); ok {
			args.TLSCACABundlePath, _ = tlsca.GetString("caBundlePath")
		}
	}
	return args
}

const pluginNameTLSSpiffe = "tls-spiffe"

func buildAuthenticator(ctx context.Context, args argsData, spiffe x509source.Source) (clientauthn.Authenticator, error) {
	pluginArgs := plugin.AuthenticatorArgs{PluginName: args.PluginName}
	switch args.PluginName {
	case pluginNameTLSSpiffe:
		if spiffe == nil {
			return nil, errors.New("tls-spiffe requires a shared SPIFFE source (top-level spiffe block must be set)")
		}
		bundles, err := spiffe.Bundles()
		if err != nil {
			return nil, fmt.Errorf("tls-spiffe: obtain trust bundle source: %w", err)
		}
		pluginArgs.Bundles = bundles
	case "anonymous":
		pluginArgs.Anonymous.URI = args.AnonymousURI
	case "tls-ca":
		pluginArgs.TLSCA.CABundlePath = args.TLSCACABundlePath
	}
	return plugin.NewAuthenticator(ctx, pluginArgs)
}
