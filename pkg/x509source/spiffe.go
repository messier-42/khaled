package x509source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// spiffeBootstrapTimeout bounds the initial Workload API bootstrap.
// workloadapi.NewX509Source blocks until the first SVID is received,
// so without a timeout a misconfigured or unreachable agent would
// cause khaled to hang indefinitely at startup.
const spiffeBootstrapTimeout = 30 * time.Second

// spiffeSource adapts a [workloadapi.X509Source] to the [Source]
// interface. SVID rotation is handled by go-spiffe itself: the callback
// produced by tlsconfig.GetCertificate always returns the current SVID.
// A bridge goroutine forwards the Workload API's Updated() signal to
// this package's UpdateChan().
type spiffeSource struct {
	source    *workloadapi.X509Source
	getCertFn func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	updateCh chan struct{}
	done     chan struct{}
	// closeOnce guards Close against concurrent callers; see the
	// equivalent field on fileSource for rationale.
	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
}

func newSPIFFESource(parent context.Context, socketPath string) (*spiffeSource, error) {
	ctx, cancel := context.WithTimeout(parent, spiffeBootstrapTimeout)
	defer cancel()

	var clientOpts []workloadapi.ClientOption
	if socketPath != "" {
		clientOpts = append(clientOpts, workloadapi.WithAddr("unix://"+socketPath))
	}

	var sourceOpts []workloadapi.X509SourceOption
	if len(clientOpts) > 0 {
		sourceOpts = append(sourceOpts, workloadapi.WithClientOptions(clientOpts...))
	}

	source, err := workloadapi.NewX509Source(ctx, sourceOpts...)
	if err != nil {
		return nil, fmt.Errorf("x509source: connect to SPIFFE Workload API: %w", err)
	}

	s := &spiffeSource{
		source:    source,
		getCertFn: tlsconfig.GetCertificate(source),
		updateCh:  make(chan struct{}, 1),
		done:      make(chan struct{}),
	}

	s.wg.Add(1)
	go s.bridgeUpdates()
	return s, nil
}

func (s *spiffeSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.getCertFn(hello)
}

func (s *spiffeSource) UpdateChan() <-chan struct{} {
	return s.updateCh
}

// Bundles returns the underlying workloadapi.X509Source, which
// keeps an up-to-date view of the trust bundles served by the
// workload API.
func (s *spiffeSource) Bundles() (x509bundle.Source, error) {
	return s.source, nil
}

// ClientCACertPool returns (nil, nil) for SPIFFE-backed sources.
func (s *spiffeSource) ClientCACertPool() (*x509.CertPool, error) {
	return nil, nil
}

func (s *spiffeSource) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		s.closeErr = s.source.Close()
		s.wg.Wait()
	})
	return s.closeErr
}

// bridgeUpdates forwards the Workload API's rotation signal.
func (s *spiffeSource) bridgeUpdates() {
	defer s.wg.Done()
	updated := s.source.Updated()
	for {
		select {
		case <-s.done:
			return
		case <-updated:
			doNotify(s.updateCh)
		}
	}
}
