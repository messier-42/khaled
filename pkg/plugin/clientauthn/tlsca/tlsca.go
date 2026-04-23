// Package tlsca implements the "tls-ca" Client Authentication
// plugin: mTLS whose peer certificate is validated against a static
// CA bundle loaded from disk at startup.
//
// Unlike tls-spiffe, this plugin does not depend on SPIFFE. A CA bundle
// file must be provided and the plugin simply verifies every client
// certificate chain against it. This is useful for deployments that
// already have an internal PKI or for test environments where the need
// to stand up a SPIFFE agent is burdensome.
//
// # Identity URI extraction
//
// The authenticated ClientIdentity's URI is derived from the leaf
// certificate's Subject Alternative Name extensions, in this order:
//
//  1. The first SAN URI, used verbatim. Operators that create
//     certificates with explicit identity URIs (SPIFFE-style or
//     otherwise) get them through unchanged.
//
//  2. Otherwise, the first SAN DNS name, prefixed as
//     "dns://<dnsname>". This allows garden-variety client certificates
//     to be used as-is, while still producing a URI-shaped identifier
//     that Claims Mapping plugins can use.
//
//  3. Otherwise, authentication fails.
//
// The Common Name field (or the Certificate's Subject in general)
// is not currently consulted by this plugin.
//
// This plugin does not currently reload the client certificate trust
// bundle after server launch.
package tlsca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
)

// Authenticator is the tls-ca implementation of
// clientauthn.Authenticator.
type Authenticator struct {
	roots *x509.CertPool
}

var _ clientauthn.Authenticator = &Authenticator{}

// New constructs a tls-ca Authenticator that validates client
// certificates. caBundlePath should be a path to a file containing
// one or more PEM-encoded certificates which represent the trust
// anchors for client certificates.
func New(caBundlePath string) (*Authenticator, error) {
	if caBundlePath == "" {
		return nil, errors.New("tls-ca: caBundlePath is required")
	}

	data, err := os.ReadFile(caBundlePath)
	if err != nil {
		return nil, fmt.Errorf("tls-ca: read CA bundle %q: %w", caBundlePath, err)
	}

	pool, err := poolFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("tls-ca: parse CA bundle %q: %w", caBundlePath, err)
	}

	return &Authenticator{roots: pool}, nil
}

func (a *Authenticator) Close() error {
	return nil
}

// Authenticate verifies the client certificate chain against the
// configured CA bundle, then extracts an identity URI from the
// leaf's SAN extensions.
func (a *Authenticator) Authenticate(r *http.Request) (clientauthn.ClientIdentity, error) {
	if r.TLS == nil {
		return nil, clientauthn.ErrNotTLS
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, clientauthn.ErrNoClientCertificate
	}
	leaf := r.TLS.PeerCertificates[0]

	// Build an intermediates pool from any non-leaf certs the peer
	// presented. crypto/x509 still requires the leaf to chain to a
	// root in Roots even if intermediates are present.
	intermediates := x509.NewCertPool()
	for _, c := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         a.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("tls-ca: verify peer cert: %w", err)
	}

	uri, err := extractIdentityURI(leaf)
	if err != nil {
		return nil, fmt.Errorf("tls-ca: %w", err)
	}

	return clientauthn.NewTLSCAIdentity(uri, leaf), nil
}

// extractIdentityURI determines the preferred identity URI.
func extractIdentityURI(leaf *x509.Certificate) (string, error) {
	if len(leaf.URIs) > 0 {
		return leaf.URIs[0].String(), nil
	}

	if len(leaf.DNSNames) > 0 {
		return "dns://" + leaf.DNSNames[0], nil
	}

	return "", errors.New("leaf certificate has no SAN URI or DNS name; cannot derive identity")
}

// poolFromPEM parses a PEM-encoded blob containing one or more
// concatenated CERTIFICATE blocks and returns a *x509.CertPool
// populated with them. Returns an error if no parseable certificates
// are found — an empty pool would silently accept nothing, which is
// almost never what an operator intended.
func poolFromPEM(data []byte) (*x509.CertPool, error) {
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
			return nil, fmt.Errorf("parse certificate %d: %w", added, err)
		}
		pool.AddCert(cert)
		added++
	}
	if added == 0 {
		return nil, errors.New("no CERTIFICATE blocks found")
	}
	return pool, nil
}
