// Package x509source provides an auto-reloading source of X.509 certificates
// for TLS server usage.
//
// It can be backed either by files on disk (reloaded on change via fsnotify)
// or by the SPIFFE Workload API (rotated automatically by go-spiffe).
//
// The Source interface exposes a tls.Config.GetCertificate-compatible
// callback plus an UpdateChan() notification channel for consumers
// that need to know when the certificate has changed (for example a
// consumer caching a derived *tls.Config). Consumers plugging the
// source directly into tls.Config.GetCertificate do not need to watch
// the channel.
//
// This package also owns the JSON Schema fragment describing the
// serverCertificate config block (see Schema) so the same shape can
// be reused by any configuration location that embeds a server
// certificate.
package x509source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"

	"github.com/messier-42/khaled/pkg/config"
)

// ErrBundlesUnsupported is returned by Bundles() on Sources whose backing
// store does not carry SPIFFE trust bundles (today: file-backed sources).
var ErrBundlesUnsupported = errors.New("x509source: trust bundle access not supported by this source")

// Kind selects the backing implementation.
type Kind string

const (
	KindFile   Kind = "file"
	KindSPIFFE Kind = "spiffe"
)

// Config describes how to obtain a server certificate. It mirrors the
// serverCertificate block in the khaled configuration, with a single
// extra global configuration item (WorkloadSocketPath) that is pulled
// from the top-level `spiffe` block for use in SPIFFE mode.
type Config struct {
	// Kind is the certificate source type. Required.
	Kind Kind

	// CertificateFilePath and KeyFilePath are required when Kind is
	// KindFile. Paths are opened once at construction and watched
	// for changes. Any changes are reloaded automatically.
	CertificateFilePath string
	KeyFilePath         string

	// ClientTrustAnchorsPath is an optional filesystem path to a PEM
	// file containing one or more CA certificates used as the trust
	// anchors for verifying client certificates at the TLS layer
	// (tls.Config.ClientCAs). Used only when Kind is KindFile. If
	// empty, ClientCACertPool returns (nil, nil) and the caller
	// should not enable static client CA verification.
	//
	// Note that currently, this file is only loaded once.
	ClientTrustAnchorsPath string

	// WorkloadSocketPath is the filesystem path to the SPIFFE
	// Workload API socket. Used only when Kind is KindSPIFFE. If
	// empty, the go-spiffe library falls back to the
	// SPIFFE_ENDPOINT_SOCKET environment variable.
	WorkloadSocketPath string
}

// Source delivers a sequence of server certificates, each the logical
// replacement of its predecessor. The GetCertificate method can be used
// directly with crypto/tls and can be used concurrently. For callers
// which require more advanced approaches or otherwise need to know about
// certificate rotation, the UpdateChan method can be used to get a notification
// whenever the certificate is replaced.
type Source interface {
	io.Closer

	// GetCertificate returns the current server certificate. It is
	// designed for use with tls.Config.GetCertificate and is concurrency
	// safe.
	//
	// If a failed rotation occurs (e.g. the Source sees a new certificate
	// but it is unable to load it), the Source continues to return the
	// old certificate until rotation successfully occurs.
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)

	// UpdateChan returns a channel that receives a value if one or more
	// successful rotations have occurred since it was last read from.
	//
	// If a failed rotation occurs, no notification is sent until
	// rotation successfully occurs.
	UpdateChan() <-chan struct{}

	// Bundles returns a live view of the SPIFFE trust bundle for
	// consumers that need SPIFFE-aware verification of peer
	// certificates (e.g. the tls-spiffe Authenticator, which uses
	// x509svid.Verify and so needs trust-domain-aware access). The
	// returned x509bundle.Source tracks rotation automatically.
	//
	// Sources backed by non-SPIFFE sources (e.g. trust anchors loaded
	// from a PEM file) do not have a SPIFFE
	// trust bundle and return ErrBundlesUnsupported.
	//
	// For wiring static client CA trust anchors into tls.Config.ClientCAs,
	// use ClientCACertPool instead.
	Bundles() (x509bundle.Source, error)

	// ClientCACertPool returns a snapshot *x509.CertPool suitable
	// for tls.Config.ClientCAs. Returning (nil, nil) means the
	// source does not provide static client trust anchors, and
	// the client must use another mechanism for client certificate
	// verification. SPIFFE-based backends return (nil, nil).
	//
	// The returned pool is not auto-reloaded.
	ClientCACertPool() (*x509.CertPool, error)
}

// New builds a Source from cfg. It blocks until initial material is
// available: a file source reads the keypair eagerly, and a SPIFFE
// source waits for the first SVID to arrive (bounded by an internal
// timeout). If the underlying system is unreachable, New returns an
// error rather than returning a partially-initialised source.
func New(ctx context.Context, cfg Config) (Source, error) {
	switch cfg.Kind {
	case KindFile:
		return newFileSource(cfg.CertificateFilePath, cfg.KeyFilePath, cfg.ClientTrustAnchorsPath)
	case KindSPIFFE:
		return newSPIFFESource(ctx, cfg.WorkloadSocketPath)
	case "":
		return nil, errors.New("x509source: kind must be set")
	default:
		return nil, fmt.Errorf("x509source: unknown kind %q", cfg.Kind)
	}
}

// ConfigFromSnapshot extracts a Config from a serverCertificate object
// and the top-level root config block. serverCertificate is permitted
// to omit the `source` discriminator, in which case the default is
// "file".
//
// The SPIFFE workload socket path is read from rootBlock's "spiffe"
// sub-block. rootBlock may be nil (or lack a "spiffe" block); in this
// case WorkloadSocketPath is left empty and the go-spiffe library
// automatically falls back to the environment variable
// SPIFFE_ENDPOINT_SOCKET.
func ConfigFromSnapshot(serverCertificate config.Map, rootBlock config.Map) Config {
	cfg := Config{Kind: KindFile}
	if raw, ok := serverCertificate.GetString("source"); ok {
		cfg.Kind = Kind(raw)
	}
	cfg.CertificateFilePath, _ = serverCertificate.GetString("certificateFilePath")
	cfg.KeyFilePath, _ = serverCertificate.GetString("keyFilePath")
	cfg.ClientTrustAnchorsPath, _ = serverCertificate.GetString("clientTrustAnchorsPath")
	spiffeBlock, _ := rootBlock.GetMap("spiffe")
	cfg.WorkloadSocketPath, _ = spiffeBlock.GetString("workloadSocketPath")
	return cfg
}

func doNotify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}
