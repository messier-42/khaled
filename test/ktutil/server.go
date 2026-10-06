// Package khaledtest is the in-process integration test harness for
// khaled. It spins up a real khaled server (every plugin live, no
// stubs) on a kernel-assigned localhost port, returns a cabe-go
// ckapclient bound to it, and tears the whole thing down when the
// test finishes.
//
// The default mode is mTLS: the harness ships with a process-cached
// CA, signs the server's TLS leaf and per-test client leaves with
// it, and configures khaled with the tls-ca clientAuthn plugin. A
// claims mapper that mirrors the cert URI verbatim into the
// principal lets tests assert against any URI they ask Client() to
// mint. WithAnonymousAuth swaps in the anonymous plugin for tests
// that need to focus on protocol surface rather than identity.
package khaledtest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/ckapclient"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn/anonymous"
	"github.com/messier-42/khaled/pkg/server"
)

const (
	filePlugin     = "file"
	staticPlugin   = "static"
	pluginSelector = "use"
)

// permitAllPolicy is the Cedar policy text used when the test does not
// override it. Mirrors doc/dev-policy.cedar — every principal, every
// action, every resource. Inlined so harness construction does not
// need a fixture-file dependency.
const permitAllPolicy = "permit(principal, action, resource);\n"

// DefaultMTLSPrincipal is the SAN URI written into the per-test
// client leaf when the test does not specify one. Tests that need
// to assert against a specific URI pass WithPrincipal.
const DefaultMTLSPrincipal = "spiffe://khaledtest.local/default"

// authMode selects the harness's clientAuthn plugin shape.
type authMode int

const (
	authMTLS      authMode = iota // tls-ca, default
	authAnonymous                 // anonymous, opt-in via WithAnonymousAuth
)

// startConfig collects the per-Start tunables an Option may mutate.
// Kept small on purpose — the harness exposes the minimum surface
// needed to write the current crop of integration tests; additional
// knobs land here as tests need them.
type startConfig struct {
	federation    config.Map
	keyStorageDir string
	policy        string
	auth          authMode
	principalURI  string
}

// Option mutates a startConfig before Start materialises a snapshot.
// Options compose: pass several to Start to combine their effects.
type Option func(*startConfig)

// WithPolicy overrides the Cedar policy text used by the started
// server. The default is a permit-all policy mirroring
// doc/dev-policy.cedar; tests that want to exercise the
// policy-denied path pass a deny-by-default policy here.
//
// The supplied text is written to a temp file and consumed by the
// `policySource: file` plugin — Cedar parsing failures surface as
// startup errors out of server.Run, which the harness treats as a
// test fatal.
func WithPolicy(cedarText string) Option {
	return func(c *startConfig) { c.policy = cedarText }
}

// WithAnonymousAuth swaps the harness's default mTLS authentication
// out for the anonymous plugin. Useful for tests focused on protocol
// surface rather than identity (the existing GetSelf/Prograde/etc.
// happy-path coverage was originally written against this mode and
// some tests are easier to read without the cert plumbing).
//
// Mutually exclusive with WithPrincipal: anonymous mode does not
// consult any client cert.
func WithAnonymousAuth() Option {
	return func(c *startConfig) { c.auth = authAnonymous }
}

// WithPrincipal sets the SAN URI written into the per-test client
// leaf. Implies mTLS (no effect when WithAnonymousAuth is also
// passed). The default is DefaultMTLSPrincipal.
func WithPrincipal(uri string) Option {
	return func(c *startConfig) { c.principalURI = uri }
}

// Server is a running khaled instance bound to a localhost ephemeral
// port. Stop is registered with t.Cleanup so the test does not need
// to call it explicitly.
type Server struct {
	stop    func() error
	srv     *server.Server
	source  *inMemorySource
	baseURL string

	// auth records the harness's authentication mode so Client()
	// knows whether to attach a client certificate.
	auth authMode

	// principalURI is the SAN URI baked into per-test client leaves
	// in mTLS mode. Empty in anonymous mode.
	principalURI string

	// ca is the process-cached CA + server cert material. Held so
	// Client() can issue client leaves on demand.
	ca *testCAMaterial

	// Inputs retained so Reload can rebuild a snapshot without the
	// test having to re-supply every path.
	keyStorageDir string
	policyPath    string
	cfg           startConfig
}

// Start brings up a fresh khaled server. The returned Server is
// already listening; callers can immediately construct a Client.
//
// All resources are released via t.Cleanup; the test does not need to
// call any teardown method.
func Start(t *testing.T, opts ...Option) *Server {
	t.Helper()

	cfg := startConfig{
		policy:       permitAllPolicy,
		auth:         authMTLS,
		principalURI: DefaultMTLSPrincipal,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	ca := caMaterial(t)

	policyDir := t.TempDir()
	policyPath := filepath.Join(policyDir, "policy.cedar")
	if err := os.WriteFile(policyPath, []byte(cfg.policy), 0o600); err != nil {
		t.Fatalf("khaledtest: write policy file: %v", err)
	}

	keyStorageDir := cfg.keyStorageDir
	if keyStorageDir == "" {
		keyStorageDir = filepath.Join(t.TempDir(), "keystorage")
	}
	if err := os.MkdirAll(keyStorageDir, 0o700); err != nil {
		t.Fatalf("khaledtest: create keystorage dir: %v", err)
	}

	snap := buildSnapshot(snapshotInputs{
		KeyStorageDir: keyStorageDir,
		PolicyPath:    policyPath,
		ServerCert:    ca.ServerCertPath,
		ServerKey:     ca.ServerKeyPath,
		CABundlePath:  ca.CABundlePath,
		Auth:          cfg.auth,
	})

	if cfg.federation != nil {
		snap.Root["federation"] = cfg.federation
	}
	registry, err := server.BuildRegistry()
	if err != nil {
		t.Fatalf("khaledtest: build registry: %v", err)
	}
	if err := registry.Validate(context.Background(), nil, snap); err != nil {
		t.Fatalf("khaledtest: validate snapshot: %v", err)
	}

	source := newInMemorySource(snap)
	t.Cleanup(func() { _ = source.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	srv, err := server.New(ctx, snap, server.Options{})
	if err != nil {
		cancel()
		t.Fatalf("khaledtest: server.Run: %v", err)
	}

	// Drive the reload loop in a background goroutine so reload
	// notifications pushed through source.reload are actually
	// consumed. The loop returns nil on ctx cancellation, which the
	// Cleanup below triggers; loopDone lets that cleanup wait for
	// the goroutine to exit before t.Cleanup tears down further
	// resources.
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		if err := srv.Run(ctx, source); err != nil {
			// RunReloadLoop logs internally; surface only at debug here.
			t.Logf("khaledtest: RunReloadLoop returned: %v", err)
		}
	}()

	var stopOnce sync.Once
	var stopErr error
	stop := func() error {
		stopOnce.Do(func() {
			cancel()
			_ = source.Close()
			<-loopDone
			stopErr = srv.Stop()
		})
		return stopErr
	}
	t.Cleanup(func() {
		if err := stop(); err != nil {
			t.Logf("khaledtest: stop: %v", err)
		}
	})

	addrs := srv.ListenerAddresses()
	if len(addrs) == 0 {
		t.Fatalf("khaledtest: no listener addresses reported")
	}

	return &Server{
		srv:           srv,
		stop:          stop,
		source:        source,
		baseURL:       fmt.Sprintf("https://%s/ckap/", addrs[0].String()),
		auth:          cfg.auth,
		principalURI:  cfg.principalURI,
		ca:            ca,
		keyStorageDir: keyStorageDir,
		policyPath:    policyPath,
		cfg:           cfg,
	}
}

// Reload rebuilds the server's config snapshot with opts applied on
// top of the current configuration and pushes the new snapshot
// through the in-memory config source so the running RunReloadLoop
// reconciles every subsystem against it.
//
// Reload returns once the snapshot has been validated and queued; it
// does NOT wait for the reload loop's per-subsystem reconciles to
// publish their effects. Callers that need to observe the post-
// reload state should poll the relevant request path until it
// reflects the new configuration. WaitFor is the conventional
// helper for that.
//
// Listener changes are rejected by the schema validator
// (validateListenersImmutableOnReload); the harness catches the
// validator failure as a test fatal so a Reload that tries to
// reshape the listener block surfaces clearly rather than silently
// no-op-ing.
func (s *Server) Reload(t *testing.T, opts ...Option) {
	t.Helper()
	cfg := s.cfg
	for _, opt := range opts {
		opt(&cfg)
	}

	// Persist the post-options policy text to the shared policy file
	// so both reload paths (snapshot-driven and file-watcher) see
	// consistent on-disk state.
	if err := os.WriteFile(s.policyPath, []byte(cfg.policy), 0o600); err != nil {
		t.Fatalf("khaledtest: rewrite policy file: %v", err)
	}

	snap := buildSnapshot(snapshotInputs{
		KeyStorageDir: s.keyStorageDir,
		PolicyPath:    s.policyPath,
		ServerCert:    s.ca.ServerCertPath,
		ServerKey:     s.ca.ServerKeyPath,
		CABundlePath:  s.ca.CABundlePath,
		Auth:          cfg.auth,
	})

	if cfg.federation != nil {
		snap.Root["federation"] = cfg.federation
	}
	registry, err := server.BuildRegistry()
	if err != nil {
		t.Fatalf("khaledtest: build registry: %v", err)
	}
	prev, _ := s.source.Current()
	if err := registry.Validate(context.Background(), &prev, snap); err != nil {
		t.Fatalf("khaledtest: validate reload snapshot: %v", err)
	}

	if !s.source.reload(snap) {
		t.Fatalf("khaledtest: reload after Close")
	}
	s.cfg = cfg
}

// WritePolicy overwrites the on-disk policy file with cedarText.
// The policysource.file plugin's fsnotify watcher picks up the
// change and pushes a fresh Engine into the policy holder, all
// without going through the top-level config snapshot reload path.
//
// Useful for tests that want to exercise the file-watcher reload
// mechanism specifically (the same path operators trigger by
// editing a policy file in production). For tests that want
// snapshot-driven reload — covering K8s ConfigMap updates and
// other config-source-driven reloads — use Reload(t, WithPolicy(...))
// instead.
func (s *Server) WritePolicy(t *testing.T, cedarText string) {
	t.Helper()
	// Publish one complete policy. Truncating in place can let the watcher
	// compile an intermediate empty policy as valid before reading the update.
	f, err := os.CreateTemp(filepath.Dir(s.policyPath), ".policy-*")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(f.Name()); err != nil && !os.IsNotExist(err) {
			t.Errorf("khaledtest: remove temporary policy file: %v", err)
		}
	}()
	if _, err := f.WriteString(cedarText); err != nil {
		_ = f.Close()
		t.Fatalf("khaledtest: write policy file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.Name(), s.policyPath); err != nil {
		t.Fatalf("khaledtest: publish policy file: %v", err)
	}
}

// BaseURL returns the https://host:port URL the test client should
// dial. Always uses 127.0.0.1 (set in the snapshot's listener
// address); the server cert's SANs cover localhost and 127.0.0.1.
func (s *Server) BaseURL() string { return s.baseURL }

// PrincipalURI returns the URI the harness expects the server to
// authenticate the client as. In mTLS mode it is the SAN URI written
// into the client leaf; in anonymous mode it is anonymous.DefaultURI.
func (s *Server) PrincipalURI() string {
	if s.auth == authAnonymous {
		return anonymous.DefaultURI
	}
	return s.principalURI
}

// AnonymousURI is preserved for callers written before the harness
// gained mTLS support. New code should prefer PrincipalURI, which
// returns the right value regardless of auth mode.
//
// Deprecated: use PrincipalURI.
func (s *Server) AnonymousURI() string { return anonymous.DefaultURI }

// Client returns a cabe-go ckapclient configured to dial the
// harness's server. In mTLS mode the client presents a fresh leaf
// signed by the harness CA; in anonymous mode no client cert is
// attached. Per-request timeouts are the caller's responsibility.
func (s *Server) Client(t *testing.T) *ckapclient.Client {
	t.Helper()
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL:    s.baseURL,
		HTTPClient: s.HTTPClient(t),
		UserAgent:  "khaledtest/0.0",
	})
	if err != nil {
		t.Fatalf("khaledtest: ckapclient.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// HTTPClient returns a *http.Client preconfigured with the same TLS
// trust as Client() but with no CKAP framing. Useful for tests that
// need to send a request the cabe-go client could never produce —
// wrong Content-Type, malformed body, missing kind field — to
// exercise the server's protocol-level error paths.
//
// In mTLS mode the returned client also presents the harness's
// per-test client leaf.
func (s *Server) HTTPClient(t *testing.T) *http.Client {
	t.Helper()
	return s.httpClientWith(t, s.defaultClientCerts(t))
}

// HTTPClientNoClientCert returns a *http.Client that trusts the
// server cert but does NOT present any client certificate. Used by
// the CodeUnauthorized tests under mTLS to provoke the server's
// "no client cert presented" error path. Callable in any auth mode;
// in anonymous mode it behaves identically to HTTPClient.
func (s *Server) HTTPClientNoClientCert(t *testing.T) *http.Client {
	t.Helper()
	return s.httpClientWith(t, nil)
}

// HTTPClientWithCert returns a *http.Client that presents leaf as
// its client certificate instead of the harness-default per-test
// leaf. Used by tests that want to drive auth failures with carefully
// crafted certs (e.g. signed by a different CA).
func (s *Server) HTTPClientWithCert(t *testing.T, leaf tls.Certificate) *http.Client {
	t.Helper()
	return s.httpClientWith(t, []tls.Certificate{leaf})
}

// IssueClientLeaf returns a fresh client leaf signed by the harness
// CA whose SAN URI is principalURI. Useful for tests that need a
// specific leaf — typically negative tests that pass it to
// HTTPClientWithCert. In the common case, callers should prefer
// Start(t, WithPrincipal(uri)) and let Client() handle leaf issuance.
func (s *Server) IssueClientLeaf(t *testing.T, principalURI string) tls.Certificate {
	t.Helper()
	return s.ca.issueClientLeaf(t, principalURI)
}

// IssueClientLeafFromForeignCA returns a client leaf signed by an
// ad-hoc CA *not* in the harness server's trust bundle. Used by
// CodeUnauthorized tests to drive the "valid-looking cert chain
// from an untrusted issuer" path.
func (s *Server) IssueClientLeafFromForeignCA(t *testing.T, principalURI string) tls.Certificate {
	t.Helper()
	foreign, err := generateCAMaterial()
	if err != nil {
		t.Fatalf("khaledtest: build foreign CA: %v", err)
	}
	return foreign.issueClientLeaf(t, principalURI)
}

func (s *Server) httpClientWith(t *testing.T, certs []tls.Certificate) *http.Client {
	t.Helper()
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(s.ca.CAPEM) {
		t.Fatalf("khaledtest: append CA PEM to pool")
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caPool,
				ServerName:   "localhost",
				MinVersion:   tls.VersionTLS13,
				Certificates: certs,
			},
		},
		Timeout: 10 * time.Second,
	}
}

// defaultClientCerts returns the per-call client cert chain attached
// to Client/HTTPClient requests under the harness's current auth
// mode. Anonymous mode → nil (no cert). mTLS mode → a fresh leaf
// signed by the harness CA, carrying s.principalURI as a SAN URI.
func (s *Server) defaultClientCerts(t *testing.T) []tls.Certificate {
	t.Helper()
	if s.auth == authAnonymous {
		return nil
	}
	return []tls.Certificate{s.ca.issueClientLeaf(t, s.principalURI)}
}

// snapshotInputs collects the file/directory paths and switches the
// snapshot builder needs.
type snapshotInputs struct {
	KeyStorageDir string
	PolicyPath    string
	ServerCert    string
	ServerKey     string
	CABundlePath  string
	Auth          authMode
}

// buildSnapshot returns a config snapshot for a test server: disk
// keystorage, Cedar with a file-backed policy, the chosen client
// authentication plugin, a static claims mapper that fits that
// plugin, JSON logging at error severity, and a single HTTPS
// listener bound to a kernel-assigned port on 127.0.0.1.
func buildSnapshot(in snapshotInputs) config.Snapshot {
	clientAuthn, claims := buildAuthnAndClaims(in.Auth, in.CABundlePath)
	return config.Snapshot{Root: config.Map{
		"keyStorage": config.Map{
			pluginSelector: "disk",
			"disk":         config.Map{"path": in.KeyStorageDir},
		},
		"policyEngine": config.Map{pluginSelector: "cedar"},
		"policySource": config.Map{
			pluginSelector: filePlugin,
			filePlugin:     config.Map{"path": in.PolicyPath},
		},
		"clientAuthn":   clientAuthn,
		"claimsMapping": claims,
		"logging": config.Map{
			"format":   "json",
			"severity": "error",
		},
		"listeners": config.Array{
			config.Map{
				pluginSelector: "http",
				"address":      "127.0.0.1:0",
				"http": config.Map{
					"tls": config.Map{
						"serverCertificate": config.Map{
							"source":              filePlugin,
							"certificateFilePath": in.ServerCert,
							"keyFilePath":         in.ServerKey,
						},
					},
				},
			},
		},
	}}
}

// buildAuthnAndClaims returns the clientAuthn and claimsMapping
// blocks suited to the requested auth mode. Kept separate from
// buildSnapshot so the auth-mode switch is easier to read.
func buildAuthnAndClaims(mode authMode, caBundlePath string) (config.Map, config.Map) {
	switch mode {
	case authAnonymous:
		clientAuthn := config.Map{pluginSelector: "anonymous"}
		// Match the anonymous plugin's DefaultURI verbatim.
		claims := config.Map{
			pluginSelector: staticPlugin,
			staticPlugin: config.Map{
				"principals": config.Array{
					config.Map{
						"uri": `https://cabespec\.org/anonymous`,
						"claims": config.Map{
							"role": "anonymous",
						},
					},
				},
			},
		}
		return clientAuthn, claims
	case authMTLS:
		clientAuthn := config.Map{
			pluginSelector: "tls-ca",
			"tls-ca":       config.Map{"caBundlePath": caBundlePath},
		}
		// Match any URI and pull it through as the principal URI.
		// The role claim is a fixed string so tests can sanity-check
		// the mapper actually ran.
		claims := config.Map{
			pluginSelector: staticPlugin,
			staticPlugin: config.Map{
				"principals": config.Array{
					config.Map{
						"uri": `.*`,
						"claims": config.Map{
							"role": "mtls-client",
						},
					},
				},
			},
		}
		return clientAuthn, claims
	default:
		panic(fmt.Sprintf("khaledtest: unknown auth mode %v", mode))
	}
}

// WithFederation configures the real federation subsystem for integration tests.
func WithFederation(block config.Map) Option { return func(c *startConfig) { c.federation = block } }

// WithKeyStorageDir preserves a key store across service restarts.
func WithKeyStorageDir(dir string) Option { return func(c *startConfig) { c.keyStorageDir = dir } }

// Stop closes the service, releasing its SQLite lock for offline maintenance.
func (s *Server) Stop() error { return s.stop() }
