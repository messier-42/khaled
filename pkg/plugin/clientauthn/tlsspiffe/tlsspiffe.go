// Package tlsspiffe implements the "tls-spiffe" Client Authentication
// plugin: mTLS whose client certificate is validated against the SPIFFE
// trust bundle obtained from the SPIFFE Workload API.
package tlsspiffe

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"

	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
)

// Authenticator is the tls-spiffe implementation of
// clientauthn.Authenticator.
type Authenticator struct {
	bundles x509bundle.Source
}

var _ clientauthn.Authenticator = &Authenticator{}

// New constructs a tls-spiffe Authenticator that verifies peer SVIDs
// against SPIFFE bundles.
func New(bundles x509bundle.Source) (*Authenticator, error) {
	if bundles == nil {
		return nil, errors.New("tls-spiffe: trust bundle source is required")
	}

	return &Authenticator{bundles: bundles}, nil
}

func (a *Authenticator) Close() error {
	return nil
}

// Authenticate verifies the client certificate chain presented during
// the TLS handshake against the SPIFFE trust bundle for the SVID's
// trust domain, and returns a SPIFFEIdentity bound to the verified
// leaf.
func (a *Authenticator) Authenticate(r *http.Request) (clientauthn.ClientIdentity, error) {
	if r.TLS == nil {
		return nil, clientauthn.ErrNotTLS
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return nil, clientauthn.ErrNoClientCertificate
	}

	// x509svid.Verify performs full SPIFFE-aware validation: leaf
	// SPIFFE ID extraction, leaf CA/KeyUsage sanity checks, chain
	// verification against the bundle for the leaf's trust domain.
	id, verifiedChains, err := x509svid.Verify(r.TLS.PeerCertificates, a.bundles)
	if err != nil {
		return nil, fmt.Errorf("tls-spiffe: verify peer SVID: %w", err)
	}
	if len(verifiedChains) == 0 {
		return nil, errors.New("tls-spiffe: verify peer SVID: no verified chains returned")
	}

	svid := &x509svid.SVID{
		ID:           id,
		Certificates: verifiedChains[0],
	}

	return clientauthn.NewSPIFFEIdentity(id, svid), nil
}
