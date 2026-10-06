// Package keyserversub provides the CABE keyserver subsystem.
//
// A Manager owns the keyserverStack (keystorage, keyschedule,
// *keyserver.Server) and reconciles it against config reloads. The
// Keyserver method value is stable across reloads so the HTTP
// transport can retain it indefinitely and call it per request to
// get the live server.
package keyserversub

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/messier-42/khaled/pkg/federation"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/keyschedule"
	"github.com/messier-42/khaled/pkg/keyserver"
	"github.com/messier-42/khaled/pkg/lifecycle"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/wrapper/macwrapper"
)

// Stack is the set of resources that back a single CABE domain's
// request-handling pipeline. These are constructed together because
// they share a lifecycle: any change to the keyStorage configuration
// invalidates everything built on top.
type Stack struct {
	store    keystorage.KeyStore
	domain   keystorage.KeyStoreDomain
	schedule *keyschedule.Schedule
	server   *keyserver.Server
}

// Server returns the stack's keyserver.
func (s *Stack) Server() *keyserver.Server { return s.server }

// Healthy reports whether the stack is fully constructed and ready to
// serve CKAP requests: the store, schedule and server are all present.
//
// This is a cheap, non-blocking liveness read intended for the /readyz
// readiness check, which is polled frequently. It deliberately does no
// I/O — it does not open the DB or take the keystorage file lock. The
// store proved itself usable when it was constructed (DB opened, lock
// acquired); had that failed, buildStack would have returned an error
// and no Stack would exist, so last-known-good is reported instead.
//
// A nil Stack — never started, or a failed partial startup — is not
// healthy.
func (s *Stack) Healthy() bool {
	return s != nil && s.store != nil && s.schedule != nil && s.server != nil
}

// Close tears the stack down. The keyserver holds no resources of its
// own. The key schedule stops its background rotation goroutine; the
// key store closes the DB and releases the OS file lock.
func (s *Stack) Close() error {
	if s == nil {
		return nil
	}

	var errs []error
	if s.schedule != nil {
		if err := s.schedule.Close(); err != nil {
			errs = append(errs, fmt.Errorf("keyschedule: %w", err))
		}
	}
	if s.store != nil {
		if err := s.store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("keystorage: %w", err))
		}
	}

	return errors.Join(errs...)
}

// argsData captures the inputs that build a Stack, used to detect no-op
// reconciles.
type argsData struct {
	// Storage args used to create the Key Storage plugin.
	StoragePlugin string
	DiskPath      string

	// Runtime settings which relate to key storage.
	DomainName           string
	RootRotationInterval time.Duration
	LeaseDuration        time.Duration
}

// Defaults for the runtime settings.
const (
	DefaultDomainName           = "default"
	DefaultRootRotationInterval = 24 * time.Hour
	DefaultLeaseDuration        = 5 * time.Minute
)

// Manager owns the current Stack and reconciles it against live config
// changes. The currently-installed *Stack is obtainable via Current(),
// and the live *keyserver.Server via Current().Server(). The policy source
// is held independently of the key server stack  so Reconcile can rebuild the
// stack without needing to deal with it.
type Manager = lifecycle.Manager[*Stack]

// New builds the initial stack from the given config snapshot and returns a manager
// that owns it.
func New(ctx context.Context, snap config.Snapshot, policy keyserver.PolicySource) (*Manager, error) {
	return lifecycle.New(ctx, snap, spec(policy))
}

// NewEmpty returns a Manager with no current stack. Useful for tests.
func NewEmpty() *Manager {
	return lifecycle.NewEmpty(spec(nil))
}

// KeyserverFunc returns a per-request accessor that yields the current
// *keyserver.Server from m, or nil if none is currently active.
// This is used to plumb the key server subsystem into TransportDeps.Keyserver;
// the returned closure is stable across reloads.
func KeyserverFunc(m *Manager) func() *keyserver.Server {
	return func() *keyserver.Server {
		s := m.Current()
		if s == nil {
			return nil
		}

		return s.server
	}
}

func spec(policy keyserver.PolicySource) lifecycle.Spec[*Stack] {
	return lifecycle.Spec[*Stack]{
		Name: "keyserver",
		Apply: func(ctx context.Context, old *Stack, oldSnap, newSnap config.Snapshot) (*Stack, error) {
			newArgs, err := argsFromSnapshot(newSnap)
			if err != nil {
				return nil, err
			}
			if old != nil {
				oldArgs, err := argsFromSnapshot(oldSnap)
				if err == nil && oldArgs == newArgs {
					if !reflect.DeepEqual(oldSnap.Root["federation"], newSnap.Root["federation"]) {
						if err := old.configureFederation(ctx, newSnap); err != nil {
							return nil, err
						}
					}
					return old, nil
				}
			}
			next, err := buildStack(ctx, newArgs, policy)
			if err != nil {
				return nil, err
			}
			if err = next.configureFederation(ctx, newSnap); err != nil {
				_ = next.Close()
				return nil, err
			}
			return next, nil
		},
		Close: func(s *Stack) error { return s.Close() },
	}
}

// buildStack constructs a new stack from args, using the given policy
// engine source.
func buildStack(ctx context.Context, args argsData, policy keyserver.PolicySource) (*Stack, error) {
	store, err := plugin.NewKeyStorage(ctx, plugin.KeyStorageArgs{
		PluginName: args.StoragePlugin,
		Disk:       struct{ Path string }{Path: args.DiskPath},
	})
	if err != nil {
		return nil, fmt.Errorf("keystorage: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = store.Close()
		}
	}()

	domain, err := store.DomainByName(ctx, args.DomainName)
	if err != nil {
		return nil, fmt.Errorf("keystorage domain %q: %w", args.DomainName, err)
	}

	sched, err := keyschedule.New(ctx, keyschedule.Config{
		Domain:               domain,
		RootRotationInterval: args.RootRotationInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("keyschedule: %w", err)
	}
	schedOK := false
	defer func() {
		if !schedOK {
			_ = sched.Close()
		}
	}()

	wrap, err := macwrapper.New(domain)
	if err != nil {
		return nil, fmt.Errorf("macwrapper: %w", err)
	}

	srv, err := keyserver.New(keyserver.Config{
		DomainName:    args.DomainName,
		Schedule:      sched,
		Policy:        policy,
		RefWrapper:    wrap,
		LeaseDuration: args.LeaseDuration,
	})
	if err != nil {
		return nil, fmt.Errorf("keyserver: %w", err)
	}

	schedOK = true
	ok = true
	return &Stack{
		store:    store,
		domain:   domain,
		schedule: sched,
		server:   srv,
	}, nil
}

// argsFromSnapshot extracts the keyStorage block and any optional
// settings.
func argsFromSnapshot(snap config.Snapshot) (argsData, error) {
	var args argsData

	block, ok := snap.Root.GetMap("keyStorage")
	if !ok {
		return args, errors.New("keyStorage block is required")
	}
	use, _ := block.GetString("use")
	if use == "" {
		return args, errors.New("keyStorage.use is required")
	}
	args.StoragePlugin = use

	switch use {
	case "disk":
		sub, ok := block.GetMap("disk")
		if !ok {
			return args, errors.New("keyStorage.disk block is required when use=disk")
		}
		path, _ := sub.GetString("path")
		if path == "" {
			return args, errors.New("keyStorage.disk.path is required")
		}
		args.DiskPath = path
	default:
		return args, fmt.Errorf("unsupported keyStorage plugin %q", use)
	}

	args.DomainName = DefaultDomainName
	if name, ok := block.GetString("domainName"); ok && name != "" {
		args.DomainName = name
	}

	args.RootRotationInterval = DefaultRootRotationInterval
	if raw, ok := block.GetString("rootRotationInterval"); ok && raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return args, fmt.Errorf("keyStorage.rootRotationInterval: %w", err)
		}
		args.RootRotationInterval = d
	}

	args.LeaseDuration = DefaultLeaseDuration
	if raw, ok := block.GetString("leaseDuration"); ok && raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return args, fmt.Errorf("keyStorage.leaseDuration: %w", err)
		}
		args.LeaseDuration = d
	}

	return args, nil
}

// configureFederation reuses the live Domain handle; only runtime policy and
// volatile caches change. Validation failure leaves the active runtime intact.
func (s *Stack) configureFederation(ctx context.Context, snap config.Snapshot) error {
	cfg, err := federation.ConfigFromSnapshot(snap)
	if err != nil {
		return err
	}
	d, ok := s.domain.(keystorage.FederationDomain)
	if ok {
		id, err := d.FederationIdentity(ctx)
		if err != nil {
			return err
		}
		if err = s.server.BindFederationDomainID(id); err != nil {
			return err
		}
	}
	if cfg == nil {
		return s.server.SetFederation(nil)
	}
	if !ok {
		return errors.New("key storage does not support federation")
	}
	runtime, err := federation.New(ctx, d, *cfg)
	if err != nil {
		return err
	}
	return s.server.SetFederation(runtime)
}
