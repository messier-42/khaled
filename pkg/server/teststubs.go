package server

import (
	"context"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/keyserver"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/subsystems/authnsub"
	"github.com/messier-42/khaled/pkg/subsystems/claimssub"
	"github.com/messier-42/khaled/pkg/subsystems/keyserversub"
	"github.com/messier-42/khaled/pkg/subsystems/monitoringsub"
	"github.com/messier-42/khaled/pkg/subsystems/policysub"
	"github.com/messier-42/khaled/pkg/subsystems/spiffesub"
	"github.com/messier-42/khaled/pkg/subsystems/transportsub"
	"github.com/messier-42/khaled/pkg/x509source"
)

// StarterSet is the set of subsystem starter functions New uses to
// bring up a Server. In production every field is the corresponding
// pkg/subsystems package's Start function; tests can supply mock
// starters via Options.StarterSet. Any field left as nil defaults
// to the real starter so that callers can mock selectively.
//
// The type lives in regular (non-_test.go) Go so that test packages
// outside pkg/server — notably cmd/khaled — can construct one.
// Production callers must not set Options.StarterSet.
type StarterSet struct {
	Monitoring   func(context.Context, monitoringsub.Config, monitoringsub.ReadyFunc) (*monitoringsub.Running, error)
	Transport    func(context.Context, config.Snapshot, plugin.TransportDeps) (*transportsub.Running, error)
	Policy       func(context.Context, config.Snapshot) (*policysub.Manager, error)
	SharedSPIFFE func(context.Context, config.Snapshot) (*spiffesub.Manager, error)
	Authn        func(config.Snapshot, x509source.Source) (*authnsub.Manager, error)
	Claims       func(config.Snapshot) (*claimssub.Manager, error)
	Keyserver    func(context.Context, config.Snapshot, keyserver.PolicySource) (*keyserversub.Manager, error)
}

// MockStarterSet returns a StarterSet populated with no-op mock
// starters for every subsystem. Useful as a baseline that test packages
// can copy and selectively override.
func MockStarterSet() StarterSet {
	return StarterSet{
		Monitoring: func(context.Context, monitoringsub.Config, monitoringsub.ReadyFunc) (*monitoringsub.Running, error) {
			// Disabled by default: an empty Config yields an inert Running.
			return monitoringsub.New(context.Background(), monitoringsub.Config{}, nil)
		},
		Transport: func(context.Context, config.Snapshot, plugin.TransportDeps) (*transportsub.Running, error) {
			return transportsub.NewEmpty(), nil
		},
		Policy: func(context.Context, config.Snapshot) (*policysub.Manager, error) {
			return policysub.NewEmpty(), nil
		},
		SharedSPIFFE: func(context.Context, config.Snapshot) (*spiffesub.Manager, error) {
			return spiffesub.NewEmpty(), nil
		},
		Authn: func(config.Snapshot, x509source.Source) (*authnsub.Manager, error) {
			return authnsub.NewEmpty(), nil
		},
		Claims: func(config.Snapshot) (*claimssub.Manager, error) {
			return claimssub.NewEmpty(), nil
		},
		Keyserver: func(context.Context, config.Snapshot, keyserver.PolicySource) (*keyserversub.Manager, error) {
			return keyserversub.NewEmpty(), nil
		},
	}
}

// resolveStarters produces the fully-populated StarterSet New uses to
// bring up each subsystem. Any overrides.Foo that is non-nil replaces
// the real starter; everything else falls through to the real
// subsystem package. A nil overrides yields the all-real set used in
// production.
func resolveStarters(overrides *StarterSet) StarterSet {
	s := StarterSet{
		Monitoring:   monitoringsub.New,
		Transport:    transportsub.New,
		Policy:       policysub.New,
		SharedSPIFFE: spiffesub.New,
		Authn:        authnsub.New,
		Claims:       claimssub.New,
		Keyserver:    keyserversub.New,
	}
	if overrides == nil {
		return s
	}
	if overrides.Monitoring != nil {
		s.Monitoring = overrides.Monitoring
	}
	if overrides.Transport != nil {
		s.Transport = overrides.Transport
	}
	if overrides.Policy != nil {
		s.Policy = overrides.Policy
	}
	if overrides.SharedSPIFFE != nil {
		s.SharedSPIFFE = overrides.SharedSPIFFE
	}
	if overrides.Authn != nil {
		s.Authn = overrides.Authn
	}
	if overrides.Claims != nil {
		s.Claims = overrides.Claims
	}
	if overrides.Keyserver != nil {
		s.Keyserver = overrides.Keyserver
	}
	return s
}
