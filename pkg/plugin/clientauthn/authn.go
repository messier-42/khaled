// Package clientauthn defines the Client Authentication plugin interface.
//
// An Authenticator extracts an authenticated identity from an incoming
// request arriving over a CABE transport. The returned ClientIdentity is
// a method-agnostic handle: the only universally-meaningful operation is
// URI(). Claims Mapping plugins that need richer data (e.g. the parsed
// SPIFFE SVID) can obtain it by type-asserting to a concrete implementation.
package clientauthn

import (
	"crypto/x509"
	"errors"
	"io"
	"net/http"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Authenticator authenticates a client from an incoming HTTP request.
//
// Implementations are expected to be safe for concurrent use: middleware
// invokes Authenticate once per request from whatever goroutine the
// HTTP server has scheduled the request on. Close releases long-lived
// resources (e.g. a reference to the shared SPIFFE source); it does
// not need to cancel in-flight Authenticate calls.
type Authenticator interface {
	io.Closer

	// Authenticate returns a non-nil ClientIdentity on success.
	// Returning an error typically causes an HTTP 401 response to be
	// sent.
	Authenticate(r *http.Request) (ClientIdentity, error)
}

// ClientIdentity is the authenticated identity of a client as produced
// by an Authenticator.
//
// The interface intentionally exposes only URI(). Richer, method-
// specific data is reached by type-asserting to a concrete
// implementation. This will typically be done by a claims mapper plugin.
// In general, it is expected that a given Claims Mapper plugin will
// only be compatible with a subset of the Client Authentication plugins
// available and vice versa.
//
// URI is the identity's stable textual identifier — the full SPIFFE
// ID for tls-spiffe, the issuer+subject combination for an OAuth2
// identity, etc. A Claims Mapper plugin will typically
// adopt this URI as a Principal's URI verbatim.
type ClientIdentity interface {
	// The client identity's unique URI.
	URI() string
}

// Sentinel errors surfaced by Authenticator implementations. They are
// reported through Authenticate's error return and matched with
// errors.Is by the HTTP middleware layer to produce structured log
// output; both map to HTTP 401 at the response level.
var (
	// ErrNotTLS is returned when Authenticate is called on a request
	// whose connection is not TLS.
	ErrNotTLS = errors.New("clientauthn: request is not over TLS")

	// ErrNoClientCertificate is returned when the TLS handshake
	// completed without a client certificate.
	ErrNoClientCertificate = errors.New("clientauthn: no client certificate presented")
)

// SPIFFEIdentity is the ClientIdentity produced by the "tls-spiffe"
// Authenticator. It carries the verified leaf SPIFFE ID and the raw
// parsed *x509svid.SVID for Claims Mapping plugins that need direct
// access to SVID-level details (notably k8s-attestation, which reads
// the SPIFFE ID's path components).
type SPIFFEIdentity struct {
	// id is the verified SPIFFE ID from the leaf SVID. Accessible
	// via URI().
	id spiffeid.ID

	// SVID is the verified peer SVID: leaf plus intermediates, with
	// the SPIFFE ID extracted. Exposed for mappers that need
	// certificate-level details (expiry, SANs, etc.). The structure
	// must not be mutated and is expected to be immutable.
	SVID *x509svid.SVID
}

// NewSPIFFEIdentity constructs a SPIFFEIdentity from the values
// produced by a successful x509svid.Verify.
func NewSPIFFEIdentity(id spiffeid.ID, svid *x509svid.SVID) SPIFFEIdentity {
	return SPIFFEIdentity{id: id, SVID: svid}
}

// URI returns the full SPIFFE ID string (e.g.
// "spiffe://example.org/ns/default/sa/app/pod/pod-a/uid-1").
func (s SPIFFEIdentity) URI() string { return s.id.String() }

// SPIFFEID returns the parsed SPIFFE ID. Useful for mappers that need
// to extract structured components (trust domain, path segments) without
// re-parsing the string form.
func (s SPIFFEIdentity) SPIFFEID() spiffeid.ID { return s.id }

// TLSCAIdentity is the ClientIdentity produced by the "tls-ca"
// Authenticator. It carries the URI extracted from the leaf
// certificate's SAN extensions plus the verified leaf certificate
// itself, so X.509-aware Claims Mapping plugins can obtain X.509-specific
// data.
type TLSCAIdentity struct {
	uri string

	// Leaf is the verified client leaf certificate. Exposed for
	// mappers that need certificate-level details (issuer,
	// expiry, full SAN list). The Certificate structure must
	// not be mutated and is expected to be immutable.
	Leaf *x509.Certificate
}

// NewTLSCAIdentity constructs a TLSCAIdentity.
func NewTLSCAIdentity(uri string, leaf *x509.Certificate) TLSCAIdentity {
	return TLSCAIdentity{uri: uri, Leaf: leaf}
}

// URI returns the identity URI extracted from the leaf certificate.
func (t TLSCAIdentity) URI() string { return t.uri }

// VerifiedClientLeafCertificate allows Claims Mapping plugins to detect
// a Client Authentication plugin that can export a verified leaf X.509
// client certificate. The method name is deliberately specific.
func (t TLSCAIdentity) VerifiedClientLeafCertificate() *x509.Certificate {
	return t.Leaf
}

// AnonymousIdentity is the ClientIdentity produced by the "anonymous"
// Authenticator. It carries only a statically configured URI string and is
// stateless and constant.
type AnonymousIdentity struct {
	uri string
}

// NewAnonymousIdentity constructs an AnonymousIdentity with the given
// URI. The URI is opaque: the Authenticator chooses what it means.
func NewAnonymousIdentity(uri string) AnonymousIdentity {
	return AnonymousIdentity{uri: uri}
}

// URI returns the configured anonymous identity URI.
func (a AnonymousIdentity) URI() string { return a.uri }
