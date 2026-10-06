// Package monitoringsub provides khaled's operational monitoring
// subsystem: a dedicated plaintext HTTP listener serving Kubernetes-style
// /livez and /readyz probes.
//
// # Why a separate listener
//
// khaled's data plane is the CKAP transport: an mTLS listener that
// requests a client certificate and is served over TLS 1.3. Kubelet
// HTTP-GET probes present no client certificate and cannot be probed
// before TLS certificates are available, so the probes are served on
// their own plaintext listener instead — the same data-plane /
// operational-plane split made by kube-apiserver, etcd and friends.
//
// # Enabling
//
// The listener is opt-in. It is enabled by a non-empty
// monitoring.address; an empty (the default) address yields a no-op
// Running that binds nothing. Config is YAML, so the monitoring block
// is always present — presence alone never enables behaviour.
//
// # Probe semantics
//
//   - /livez always reports 200 OK once the process is up. Liveness in
//     khaled is pure process-aliveness; a kubelet restart only helps a
//     wedged process. /livez never consults subsystem state and never
//     flips to 503, not even during shutdown — a terminating pod should
//     be drained, not restarted.
//
//   - /readyz reports 200 when every readiness check passes and 503
//     otherwise. The set of checks is owned by pkg/server (which closes
//     over its subsystem manager handles); this package only renders the
//     []health.CheckResult the supplied ReadyFunc returns.
//     /readyz?verbose adds a plaintext body, one line per check.
//
// # Lifecycle
//
// The monitoring listener is started first (before any data-plane
// subsystem) and stopped last, so the probes are useful during a slow
// startup and answer honestly throughout shutdown. monitoring.address
// and shutdownWarningTime are read once at startup; like listeners[],
// changes require a restart, so this package has no Reconcile and is
// not part of the reload loop.
package monitoringsub

import (
	"context"
	"errors"
	"fmt"
	"net"
	stdhttp "net/http"
	"sync"
	"time"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/health"
)

// ReadyFunc returns the current set of readiness checks. It is invoked
// once per /readyz request and must be concurrency-safe.
type ReadyFunc func() []health.CheckResult

// Config is the resolved configuration of the monitoring subsystem,
// extracted from the top-level `monitoring` block via [ConfigFromSnapshot].
type Config struct {
	// Address is the plaintext HTTP listener address (e.g.
	// "0.0.0.0:8081"). An empty Address disables the listener.
	Address string

	// ShutdownWarningTime is how long, on shutdown, the server should
	// keep serving after /readyz has flipped to 503, giving Kubernetes
	// time to drain the pod from Service endpoints. It is consumed by
	// pkg/server, not by this package. Zero means no warning delay.
	ShutdownWarningTime time.Duration
}

// ConfigFromSnapshot extracts the monitoring Config from a config
// snapshot. JSON schema validation should already have been performed.
//
// A bad shutdownWarningTime duration string is the only error; an
// empty address is valid and simply disables the listener.
func ConfigFromSnapshot(snap config.Snapshot) (Config, error) {
	block, _ := snap.Root.GetMap("monitoring")

	var cfg Config
	cfg.Address, _ = block.GetString("address")

	if raw, ok := block.GetString("shutdownWarningTime"); ok && raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("monitoring.shutdownWarningTime: %w", err)
		}
		cfg.ShutdownWarningTime = d
	}

	return cfg, nil
}

// Running is a handle to the monitoring subsystem. When the listener
// is disabled (empty address), it is an inert handle that owns nothing.
type Running struct {
	cfg Config

	// listener and server are nil when the subsystem is disabled.
	listener net.Listener
	server   *stdhttp.Server

	wg sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

// New constructs and starts the monitoring subsystem from cfg.
//
// If cfg.Address is empty the subsystem is disabled: New returns an
// inert Running that binds nothing and whose Stop is a no-op. Otherwise
// New binds a plaintext HTTP listener and serves /livez and /readyz in
// a background goroutine until Stop is called.
//
// readyFunc supplies the readiness checks for /readyz; it must be
// non-nil when the listener is enabled.
func New(ctx context.Context, cfg Config, readyFunc ReadyFunc) (*Running, error) {
	if cfg.Address == "" {
		return &Running{cfg: cfg}, nil
	}
	if readyFunc == nil {
		return nil, errors.New("monitoringsub: readyFunc must be set when a listener is configured")
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("monitoringsub: listen on %s: %w", cfg.Address, err)
	}

	srv := &stdhttp.Server{
		Handler:           newMux(readyFunc),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	r := &Running{
		cfg:      cfg,
		listener: ln,
		server:   srv,
	}

	r.wg.Go(func() {
		// Serve returns ErrServerClosed on a clean Stop; any other
		// error is unexpected for a plaintext listener.
		if err := srv.Serve(ln); err != nil && !errors.Is(err, stdhttp.ErrServerClosed) {
			r.closeErr = err
		}
	})

	return r, nil
}

// Active reports whether a monitoring listener is actually serving.
// pkg/server uses this to decide whether the shutdown-warning delay
// has any purpose: with no /readyz endpoint there is nothing for
// Kubernetes to observe.
func (r *Running) Active() bool {
	return r != nil && r.server != nil
}

// ShutdownWarningTime returns the configured shutdown-warning delay.
// It is meaningful only when Active reports true.
func (r *Running) ShutdownWarningTime() time.Duration {
	if r == nil {
		return 0
	}
	return r.cfg.ShutdownWarningTime
}

// BoundAddr returns the address of the bound listener, or nil when the
// subsystem is disabled or already stopped. For an address with a
// kernel-assigned port (":0"), this is how the chosen port is learnt.
func (r *Running) BoundAddr() net.Addr {
	if r == nil || r.listener == nil {
		return nil
	}
	return r.listener.Addr()
}

// Stop shuts the monitoring listener down and waits for the serving
// goroutine to exit. Idempotent and safe to call on a disabled Running.
//
// Stop is called last in the server teardown so that /readyz keeps
// answering (with 503) across the whole drain.
func (r *Running) Stop() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		if r.server != nil {
			_ = r.server.Close()
		}
		r.wg.Wait()
	})
	return r.closeErr
}
