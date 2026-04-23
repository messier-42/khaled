package x509source

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
)

// fileReloadRetryDelay is how long the fileSource waits before
// re-attempting a failed reload. A failed reload is most commonly
// caused by a non-atomic two-file update (for example, replacing a
// certificate file followed by replacing a key file a few moments later).
// In this case the most pragmatic solution is simply to retry a few
// seconds later.
//
// Kept as a package-level variable so tests can modify it.
var fileReloadRetryDelay = time.Second

// fileSource loads a TLS keypair from disk and reloads it when either
// file changes. It watches the containing directories so that atomic
// rename-style updates are picked up. Reload failures are logged and the
// previous certificate continues to be served; a single retry is
// scheduled fileReloadRetryDelay later so a two-file non-atomic
// update (cert written before key) still works.
type fileSource struct {
	certPath string
	keyPath  string

	// clientCAPool is the PEM-decoded client trust anchor pool loaded
	// once at construction from the optional clientTrustAnchorsPath.
	// nil means "no static client CAs configured" in which case
	// ClientCACertPool returns (nil, nil).
	//
	// The pool is never reloaded; changes to the file require a process
	// restart.
	clientCAPool *x509.CertPool

	// The filesystem watcher used to automatically reload certificates
	// and keys.
	watcher  *fsnotify.Watcher
	updateCh chan struct{}
	done     chan struct{}

	// closeOnce guards Close against concurrent callers. The
	// goroutine that wins the race performs the one-time teardown;
	// every other caller sees closeErr.
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup

	mu      sync.RWMutex
	current *tls.Certificate

	// retryMu guards retryTimer against concurrent Stop + reschedule.
	retryMu    sync.Mutex
	retryTimer *time.Timer
}

func newFileSource(certPath, keyPath, clientTrustAnchorsPath string) (*fileSource, error) {
	if certPath == "" || keyPath == "" {
		return nil, errors.New("x509source: certificateFilePath and keyFilePath are required when source=file")
	}

	cert, err := loadKeypair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("x509source: load keypair: %w", err)
	}

	var clientCAPool *x509.CertPool
	if clientTrustAnchorsPath != "" {
		clientCAPool, err = loadClientTrustAnchors(clientTrustAnchorsPath)
		if err != nil {
			return nil, fmt.Errorf("x509source: load client trust anchors: %w", err)
		}
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("x509source: create filesystem watcher: %w", err)
	}

	s := &fileSource{
		certPath:     filepath.Clean(certPath),
		keyPath:      filepath.Clean(keyPath),
		clientCAPool: clientCAPool,
		watcher:      watcher,
		updateCh:     make(chan struct{}, 1),
		done:         make(chan struct{}),
		current:      cert,
	}

	// Watch the directory containing the certificate and the directory containing the key.
	// If those are the same directory, deduplicate the watch.
	dirs := map[string]struct{}{
		filepath.Dir(s.certPath): {},
		filepath.Dir(s.keyPath):  {},
	}
	for dir := range dirs {
		if err := watcher.Add(dir); err != nil {
			_ = watcher.Close()
			return nil, fmt.Errorf("x509source: watch %q: %w", dir, err)
		}
	}

	s.wg.Add(1)
	go s.watchLoop()
	return s, nil
}

// Provides access for crypto/tls.Config.GetCertificate.
func (s *fileSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return nil, errors.New("x509source: no certificate loaded")
	}
	return s.current, nil
}

func (s *fileSource) UpdateChan() <-chan struct{} {
	return s.updateCh
}

// Bundles is not supported for file-backed sources: there is no SPIFFE
// trust bundle behind a plain keypair. Consumers wanting static client
// CA trust anchors should use ClientCACertPool instead.
func (s *fileSource) Bundles() (x509bundle.Source, error) {
	return nil, ErrBundlesUnsupported
}

// ClientCACertPool returns the client trust anchor pool loaded at
// construction from clientTrustAnchorsPath, or (nil, nil) when no
// path was configured. The pool is not rotated.
func (s *fileSource) ClientCACertPool() (*x509.CertPool, error) {
	return s.clientCAPool, nil
}

func (s *fileSource) Close() error {
	s.closeOnce.Do(func() {
		close(s.done) // Get the watchLoop to return.
		s.cancelRetry()
		s.wg.Wait() // Wait for the watchLoop to return.
		s.closeErr = s.watcher.Close()
	})
	return s.closeErr
}

func (s *fileSource) watchLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.done:
			return
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if !s.isRelevantEvent(event) {
				continue
			}
			if err := s.reload(); err != nil {
				// Keep serving the previous certificate, but
				// surface the failure so operators notice a
				// broken/partial keypair write rather than
				// silently serving a stale cert indefinitely.
				slog.Warn("x509source: certificate reload failed; continuing with previous cert",
					"certPath", s.certPath,
					"keyPath", s.keyPath,
					"error", err,
				)
				// Schedule a single retry. Non-atomic two-file
				// updates (write cert, fsnotify fires, then write
				// key) commonly produce a mismatched-pair error
				// that resolves itself once the key lands. Any
				// subsequent watcher event also triggers a fresh
				// reload; the retry is just insurance against a
				// write that does not generate a second event.
				s.scheduleRetry()
			} else {
				s.cancelRetry()
				doNotify(s.updateCh)
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("x509source: filesystem watcher error",
				"certPath", s.certPath,
				"keyPath", s.keyPath,
				"error", err,
			)
		}
	}
}

func (s *fileSource) isRelevantEvent(event fsnotify.Event) bool {
	if event.Name != s.certPath && event.Name != s.keyPath {
		return false
	}
	return event.Has(fsnotify.Create) ||
		event.Has(fsnotify.Write) ||
		event.Has(fsnotify.Rename) ||
		event.Has(fsnotify.Remove)
}

func (s *fileSource) reload() error {
	cert, err := loadKeypair(s.certPath, s.keyPath)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = cert
	return nil
}

// scheduleRetry arms a single delayed retry of reload. If a retry
// is already pending it is reset (coalescing multiple failed
// events into one retry window). A subsequent successful reload
// from any source cancels the retry via cancelRetry.
func (s *fileSource) scheduleRetry() {
	s.retryMu.Lock()
	defer s.retryMu.Unlock()
	if s.retryTimer != nil {
		s.retryTimer.Stop()
	}
	s.retryTimer = time.AfterFunc(fileReloadRetryDelay, s.retryReload)
}

// cancelRetry stops any pending retry timer. Safe to call when no
// retry is pending.
func (s *fileSource) cancelRetry() {
	s.retryMu.Lock()
	defer s.retryMu.Unlock()
	if s.retryTimer != nil {
		s.retryTimer.Stop()
		s.retryTimer = nil
	}
}

// retryReload is the function the retry timer fires. It re-runs
// reload and either notifies success or schedules another retry
// via the same path the watch loop uses. Bails if the source has
// been closed in the meantime.
func (s *fileSource) retryReload() {
	select {
	case <-s.done:
		return
	default:
	}
	if err := s.reload(); err != nil {
		slog.Warn("x509source: certificate retry reload failed; will not retry again until next watcher event",
			"certPath", s.certPath,
			"keyPath", s.keyPath,
			"error", err,
		)
		return
	}
	doNotify(s.updateCh)
}

// loadClientTrustAnchors reads a PEM bundle of CA certificates from
// path and returns a populated *x509.CertPool. An empty bundle is
// rejected.
func loadClientTrustAnchors(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}

	pool := x509.NewCertPool()
	added := 0
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate %d in %q: %w", added, path, err)
		}

		pool.AddCert(cert)
		added++
	}

	if added == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks found in %q", path)
	}

	return pool, nil
}

// loadKeypair loads a PEM certificate and key pair and parses the leaf.
func loadKeypair(certPath, keyPath string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("x509source: keypair %q contains no certificates", certPath)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("x509source: parse leaf of %q: %w", certPath, err)
	}

	cert.Leaf = leaf
	return &cert, nil
}
