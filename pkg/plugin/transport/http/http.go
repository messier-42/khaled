// Package http implements the "http" protocol transport plugin: an
// HTTPS listener that serves CKAP over HTTP with TLS, as per the
// CABE specifications.
//
// # Plumbing
//
// The CABE operation endpoints are mounted at `/ckap/“.
//
// Server certificates are supplied via pkg/x509source, which can obtain
// X.509 certificates from files or the SPIFFE Workload API. The transport
// itself only consumes the resulting opaque Source. Certificates can be
// rotated at runtime without re-constructing the transport.
package http

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"sync"
	"time"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/httpmw"
	"github.com/messier-42/khaled/pkg/keyserver"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/transport"
	"github.com/messier-42/khaled/pkg/x509source"
)

// DefaultShutdownGraceTime is the default amount of time to wait
// for in-flight requests to complete during shutdown.
const DefaultShutdownGraceTime = 1 * time.Second

// Config is the resolved configuration for a single CABE HTTP transport
// instance. It is generally created using [ConfigFromSnapshot] so as to
// drive it from the khaled config.
type Config struct {
	// Listener address (e.g. "0.0.0.0:8443").
	Address string

	// CertSource is the server certificate source. Required. The caller
	// owns the Source: the transport uses it for the lifetime of the
	// transport but never calls Close on it.
	CertSource x509source.Source

	// KeyLog, if non-nil, is a sink which rceives NSS-format key log data
	// for each TLS connection. Debug use only.
	KeyLog io.Writer

	// GetAuthnFunc is called once per request. The returned Client Authn plugin
	// is used to authenticate the request. The return value may change from request
	// to request, allowing live changes of authn configuration without reconstructing
	// the transport.
	GetAuthnFunc func() clientauthn.Authenticator

	// GetClaimsMapperFunc is called once per request. The returned Claims Mapper plugin
	// is used to authenticate the request. The return value may change from request
	// to request, allowing live changes of authn configuration without reconstructing
	GetClaimsMapperFunc func() claimsmapping.ClaimsMapper

	// GetKeyServerFunc, if non-nil, returns the currently active
	// key server instance that backs CKAP operation endpoints
	// (/ckap/Prograde etc.). The function is invoked per request.
	// If nil is returned, the transport returns 404 for all CKAP
	// operations.
	GetKeyServerFunc func() *keyserver.Server

	// ShutdownGraceTime specifies the amount of time to wait for existing requests
	// to complete. If zero, DefaultShutdownGraceTime is used.
	ShutdownGraceTime time.Duration
}

// Transport is an HTTPS listener plugin instance.
type Transport struct {
	cfg Config

	// The listener we receive traffic on. We own this and close it when
	// the transport is torn down.
	listener net.Listener

	// mu guards all of the below plus cfg.KeyLog (which Close nils to
	// signal ownership transfer). All other fields above are immutable
	// after construction.
	mu        sync.Mutex
	server    *stdhttp.Server
	closed    bool
	closeOnce sync.Once
}

var _ transport.Transport = &Transport{}

// New constructs an HTTPS transport from cfg. cfg.CertSource is
// required and must remain valid for the lifetime of the transport;
// the transport never closes it.
func New(ctx context.Context, cfg Config) (*Transport, error) {
	if cfg.Address == "" {
		return nil, errors.New("http transport: address must be set")
	}
	if cfg.CertSource == nil {
		return nil, errors.New("http transport: CertSource must be set")
	}
	if cfg.GetClaimsMapperFunc != nil && cfg.GetAuthnFunc == nil {
		return nil, errors.New("http transport: claims mapping configured without client authentication")
	}

	if cfg.ShutdownGraceTime == 0 {
		cfg.ShutdownGraceTime = DefaultShutdownGraceTime
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Address)
	if err != nil {
		return nil, fmt.Errorf("http transport: listen on %s: %w", cfg.Address, err)
	}

	return &Transport{
		cfg:      cfg,
		listener: ln,
	}, nil
}

// BoundAddr returns the address of the bound listener. For
// configurations that requested an OS-assigned port (e.g. "0.0.0.0:0"),
// this is how a caller discovers the bound port.
//
// Concurrency-safe.
func (t *Transport) BoundAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.listener == nil {
		return nil
	}

	return t.listener.Addr()
}

// Close shuts down the server. Idempotent, and causes Run() to return
// if it is currently executing.
func (t *Transport) Close() error {
	var closeErr error

	t.closeOnce.Do(func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		t.closed = true

		if t.server != nil {
			closeErr = t.server.Close()
			t.server = nil
		}

		if t.listener != nil {
			t.listener.Close() // best effort
			t.listener = nil
		}
	})

	return closeErr
}

// Run starts serving using the net.Listener until ctx is cancelled.
// The returned error is nil if graceful shutdown occurred successfully.
// If Close has already been called, Run exits immediately without
// having served. Run may only be called once on a given Transport.
func (t *Transport) Run(ctx context.Context) error {
	mux := stdhttp.NewServeMux()

	// Register CKAP operation routes.
	if t.cfg.GetKeyServerFunc != nil {
		registerCKAPHandlers(mux, t.cfg.GetKeyServerFunc)
	}

	// Fallback 404 route.
	mux.HandleFunc("/", stdhttp.NotFound)

	// Middleware order: Logging is outermost so every request is
	// logged regardless of authn; authn must run before the claims mapper.
	var handler stdhttp.Handler = mux
	if t.cfg.GetClaimsMapperFunc != nil {
		handler = httpmw.MapClaims(t.cfg.GetClaimsMapperFunc)(handler)
	}
	if t.cfg.GetAuthnFunc != nil {
		handler = httpmw.Authenticate(t.cfg.GetAuthnFunc)(handler)
	}
	// The discovery resource is public. Register its exact path outside the
	// identity middleware; every other operation retains authentication/claims.
	publicMux := stdhttp.NewServeMux()
	handleRequireMethod(publicMux, stdhttp.MethodGet, "/ckap/FederationIdentity", federationIdentityHandler(t.cfg.GetKeyServerFunc))
	publicMux.Handle("/", handler)
	handler = httpmw.Logging(publicMux)

	// TLS configuration. TLS 1.3 is required.
	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: t.cfg.CertSource.GetCertificate,

		// Always request a client certificate. crypto/tls does not do
		// validation of the client certificate if presented; the Client Authn
		// plugin is responsible for doing so.
		ClientAuth: tls.RequestClientCert,

		KeyLogWriter: t.cfg.KeyLog,
	}

	srv := &stdhttp.Server{
		Addr:      t.cfg.Address,
		Handler:   handler,
		TLSConfig: tlsCfg,

		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	// Publish the server pointer and claim ownership of the
	// pre-bound listener under the mutex. Also read cfg.KeyLog under
	// the lock — Close nils it, so an unsynchronised read here races
	// a concurrent Close. If Close has already been called before
	// we got here, the listener is already closed (or about to be)
	// and we exit without serving.
	var stop bool
	func() {
		t.mu.Lock()
		defer t.mu.Unlock()

		if t.closed {
			stop = true
			return
		}

		t.server = srv
	}()
	if stop {
		return nil
	}

	// Serve.
	errCh := make(chan error, 1)
	go func() {
		err := srv.ServeTLS(t.listener, "", "")
		if errors.Is(err, stdhttp.ErrServerClosed) {
			err = nil // Graceful shutdown.
		}
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		// A fresh context is required here; the parent ctx is
		// already cancelled, which would cause Shutdown to abort
		// immediately rather than give in-flight requests time to
		// complete.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), t.cfg.ShutdownGraceTime)
		defer cancel()

		_ = srv.Shutdown(shutdownCtx) //nolint:contextcheck // intentional detached context for graceful shutdown
		return <-errCh

	case err := <-errCh:
		return err
	}
}

// ConfigFromSnapshot extracts the schema-level fields (address,
// shutdownGraceTime) from a listener entry. The remaining fields of
// Config (CertSource, KeyLog, delegates) are runtime resources
// supplied by the caller; use [CertConfigFromSnapshot] and
// [KeyLogPathFromSnapshot] to recover the schema-level inputs needed
// to construct them.
//
// JSON schema validation should already have been performed before
// calling this function. shutdownGraceTime, if unset, leaves
// Config.ShutdownGraceTime zero so that New applies
// DefaultShutdownGraceTime.
func ConfigFromSnapshot(listenerEntry config.Map, _ config.Map) (Config, error) {
	address, ok := listenerEntry.GetString("address")
	if !ok || address == "" {
		return Config{}, errors.New("listeners[]: address is required")
	}

	cfg := Config{Address: address}

	httpBlock, _ := listenerEntry.GetMap("http")
	if raw, ok := httpBlock.GetString("shutdownGraceTime"); ok && raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return Config{}, fmt.Errorf("listeners[].http.shutdownGraceTime: %w", err)
		}
		cfg.ShutdownGraceTime = d
	}

	return cfg, nil
}

// CertConfigFromSnapshot extracts the x509source.Config that describes
// the listener's server certificate. The caller is responsible for
// building (and later closing) the resulting x509source.Source and
// wiring it into [Config.CertSource].
func CertConfigFromSnapshot(listenerEntry config.Map, rootCfg config.Map) x509source.Config {
	httpBlock, _ := listenerEntry.GetMap("http")
	tlsBlock, _ := httpBlock.GetMap("tls")
	serverCert, _ := tlsBlock.GetMap("serverCertificate")
	return x509source.ConfigFromSnapshot(serverCert, rootCfg)
}

// KeyLogPathFromSnapshot returns the NSS TLS key log file path
// configured for the listener, or "" if unset. The caller opens the
// file and wires the resulting io.WriteCloser into [Config.KeyLog].
func KeyLogPathFromSnapshot(listenerEntry config.Map) string {
	httpBlock, _ := listenerEntry.GetMap("http")
	tlsBlock, _ := httpBlock.GetMap("tls")
	path, _ := tlsBlock.GetString("keylog")
	return path
}
