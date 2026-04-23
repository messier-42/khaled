// Package server constructs a khaled server instance from its assorted
// dependencies, manages the server lifecycle and config updates, and
// handles graceful shutdown. It is the CLI-independent top-level server
// implementation which is driven by the CLI entrypoint.
//
// Each stateful subsystem (authenticator, claims mapper, policy
// engine, keyserver, shared SPIFFE source, transports) lives in its
// own package under pkg/subsystems and can be driven independently.
// This package wires them together in the order the top-level server
// requires and exposes a Run loop that reconciles every subsystem
// against a single config snapshot on each reload.
//
// # Subsystem pattern
//
// Each stateful subsystem is owned by a lifecycle manager with Stop
// and Reconcile functions. Managers compare any new
// configuration against their cached configuration, and handle unchanged
// configuration items as a no-op. A changed configuration setting triggers
// rebuilds of associated state as needed. Failures leave the previous instance
// active so that a failed config change does not bring down the
// server and allows operation to continue using last-known-good values.
//
// # Starter indirection for tests
//
// Each subsystem's starter is held in a package-level var. The
// package-internal TestMain installs no-op stubs for every starter,
// enabling tests in this package to run without real dependencies.
// New starter indirections must install a stub in TestMain or existing
// tests will fail. This is used for unit testing; integration tests
// test the full assembly with real dependencies.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/messier-42/khaled/pkg/config"
	klog "github.com/messier-42/khaled/pkg/log"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/configsource"
	"github.com/messier-42/khaled/pkg/subsystems/authnsub"
	"github.com/messier-42/khaled/pkg/subsystems/claimssub"
	"github.com/messier-42/khaled/pkg/subsystems/keyserversub"
	"github.com/messier-42/khaled/pkg/subsystems/policysub"
	"github.com/messier-42/khaled/pkg/subsystems/spiffesub"
	"github.com/messier-42/khaled/pkg/subsystems/transportsub"
)

// Options carry environmental information that the
// server needs at runtime. Most values come through configuration
// objects; the values provided here are a small subset of values which
// externally influence the configuration and are provided via other channels.
type Options struct {
	// LogFormat is the environmentally-supplied default log format ("json" or
	// "text"). An empty value means to use the value specified in the
	// config source, or, failing that, a built-in default.
	LogFormat string
	// LogSeverity is the environmentally-supplied log severity.
	// An empty value means to use the value specified in the config source,
	// or, failing that, a built-in default.
	LogSeverity string

	// StarterSet, when non-nil, replaces the default subsystem
	// starters with the provided (mock) starters. Any field on the
	// StarterSet that is nil falls through to the real starter, so
	// callers can mock selectively. Production callers must leave
	// this nil; it exists solely to allow unit tests to exercise
	// server composition without standing up real plugin
	// dependencies.
	StarterSet *StarterSet
}

// Built-in defaults applied when neither the environment nor the config file
// specify a value. These are exported so that cmd/khaled can use the canonical
// defaults.
const (
	DefaultLogFormat   = klog.FormatJSON
	DefaultLogSeverity = slog.LevelError
)

// finalLoggingConfigObserver, when non-nil, receives the resolved
// klog.Config before slog.SetDefault is called. Used by tests to
// assert the precedence outcome without having to capture stderr.
var finalLoggingConfigObserver func(klog.Config)

// Server is a top-level khaled instance. It owns every subsystem manager
// and the running transport set. Stop tears them down in reverse order.
// Run is called to commence operation, and blocks until the supplied context
// is cancelled, reconciling every manager against fresh snapshots as updates
// occur.
type Server struct {
	opts Options

	spiffeSrc    *spiffesub.Manager
	authnMgr     *authnsub.Manager
	claimsMgr    *claimssub.Manager
	policyMgr    *policysub.Manager
	keyserverMgr *keyserversub.Manager
	transports   *transportsub.Running
}

// New constructs a top-level khaled instance from an initial
// config snapshot. Subsystems are started in dependency order. On any
// failure mid-startup, already-started subsystems are torn down in
// reverse before returning.
//
// The returned Server is live, with transports accepting connections
// and managers ready to reconcile. After constructing a Server,
// the Run method should be called to begin the reload loop.
//
// ctx is the lifetime context to use for the Server. The server can
// be shut down either by cancelling ctx, or by calling Stop. Either
// way is valid. Calling Stop has the advantage that it is synchronous
// and waits for background goroutines to finish.
func New(ctx context.Context, snap config.Snapshot, opts Options) (*Server, error) {
	// Apply the resolved logging configuration before any starter
	// runs so their startup-time slog.Info lines reflect the user's
	// chosen format/severity.
	finalCfg, err := resolveLoggingConfig(snap, opts)
	if err != nil {
		return nil, fmt.Errorf("resolve logging config: %w", err)
	}
	if finalLoggingConfigObserver != nil {
		finalLoggingConfigObserver(finalCfg)
	}
	slog.SetDefault(klog.New(os.Stderr, finalCfg))

	srv := &Server{opts: opts}
	starters := resolveStarters(opts.StarterSet)

	// Bring subsystems up in dependency order. A failure at any
	// step calls Stop on what is already up, so no resources leak.
	spiffeSrc, err := starters.SharedSPIFFE(ctx, snap)
	if err != nil {
		return nil, fmt.Errorf("start shared SPIFFE source: %w", err)
	}
	srv.spiffeSrc = spiffeSrc

	authnMgr, err := starters.Authn(snap, spiffeSrc.Current())
	if err != nil {
		_ = srv.Stop()
		return nil, fmt.Errorf("start authenticator: %w", err)
	}
	srv.authnMgr = authnMgr

	claimsMgr, err := starters.Claims(snap)
	if err != nil {
		_ = srv.Stop()
		return nil, fmt.Errorf("start claims mapper: %w", err)
	}
	srv.claimsMgr = claimsMgr

	policyMgr, err := starters.Policy(ctx, snap)
	if err != nil {
		_ = srv.Stop()
		return nil, fmt.Errorf("start policy runtime: %w", err)
	}
	srv.policyMgr = policyMgr

	keyserverMgr, err := starters.Keyserver(ctx, snap, srv.policyMgr)
	if err != nil {
		_ = srv.Stop()
		return nil, fmt.Errorf("start keyserver: %w", err)
	}
	srv.keyserverMgr = keyserverMgr

	deps := plugin.TransportDeps{
		SharedSPIFFE: spiffeSrc.Current(),
		Authn:        authnMgr.Current,
		Claims:       claimsMgr.Current,
		Keyserver:    keyserversub.KeyserverFunc(keyserverMgr),
	}
	transports, err := starters.Transport(ctx, snap, deps)
	if err != nil {
		_ = srv.Stop()
		return nil, fmt.Errorf("start transports: %w", err)
	}
	srv.transports = transports

	return srv, nil
}

// Stop tears every subsystem down in reverse dependency order. If a manager's
// Stop operation fails with an error, it is logged; the first error encountered
// is returned. This method is safe to call on a partially-started server,
// and can be called more than once.
func (s *Server) Stop() error {
	if s == nil {
		return nil
	}

	var firstErr error
	record := func(label string, err error) {
		if err == nil {
			return
		}
		slog.Error(label+" shutdown error", "error", err)
		if firstErr == nil {
			firstErr = err
		}
	}

	if s.transports != nil {
		record("transport", s.transports.Stop())
		s.transports = nil
	}
	if s.keyserverMgr != nil {
		record("keyserver", s.keyserverMgr.Stop())
		s.keyserverMgr = nil
	}
	if s.policyMgr != nil {
		record("policy runtime", s.policyMgr.Stop())
		s.policyMgr = nil
	}
	if s.claimsMgr != nil {
		record("claims mapper", s.claimsMgr.Stop())
		s.claimsMgr = nil
	}
	if s.authnMgr != nil {
		record("authenticator", s.authnMgr.Stop())
		s.authnMgr = nil
	}
	if s.spiffeSrc != nil {
		record("shared SPIFFE source", s.spiffeSrc.Stop())
		s.spiffeSrc = nil
	}

	return firstErr
}

// Run blocks until ctx is cancelled, consuming reload notifications
// from source. Each successful reload is applied by re-resolving
// logging configuration, replacing the slog default, and invoking
// each manager's Reconcile method in dependency order. Reconcile errors are
// logged but do not stop the loop or short-circuit later managers.
//
// Returns nil on graceful shutdown (context cancellation) or when
// the source closes its update channel.
func (s *Server) Run(ctx context.Context, source configsource.Source) error {
	return runReloadLoop(ctx, source, s.opts,
		s.spiffeSrc.Reconcile,
		s.authnMgr.Reconcile,
		s.claimsMgr.Reconcile,
		s.policyMgr.Reconcile,
		s.keyserverMgr.Reconcile,
	)
}

// ListenerAddresses returns the bound listener address of each
// running transport, in start order. Useful for tests that bind to
// a kernel-assigned port (":0") and need to learn the chosen one.
// The returned slice is empty if Stop has already been called.
func (s *Server) ListenerAddresses() []net.Addr {
	if s == nil || s.transports == nil {
		return nil
	}
	return s.transports.Addresses()
}
