package tlsspiffe_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn/tlsspiffe"
)

// testCA issues leaf X509-SVIDs for a specific trust domain. Used by
// the tests to assemble a bundle source and produce valid / invalid
// leaf certificates without pulling in go-spiffe's internal test rig.
type testCA struct {
	td        spiffeid.TrustDomain
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	caCertDER []byte
}

func newCA(t *testing.T, td string) *testCA {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &testCA{
		td:        spiffeid.RequireTrustDomainFromString(td),
		caKey:     caKey,
		caCert:    cert,
		caCertDER: der,
	}
}

// bundle builds an x509bundle.Source containing just this CA's cert
// under the CA's trust domain.
func (ca *testCA) bundle() x509bundle.Source {
	b := x509bundle.New(ca.td)
	b.AddX509Authority(ca.caCert)
	return b
}

// issue produces an X509-SVID leaf for the given SPIFFE ID path (the
// full URI is "spiffe://<ca.td>/<path>").
func (ca *testCA) issue(t *testing.T, path string) []*x509.Certificate {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}

	u := &url.URL{
		Scheme: "spiffe",
		Host:   ca.td.Name(),
		Path:   path,
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &leafKey.PublicKey, ca.caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return []*x509.Certificate{leaf, ca.caCert}
}

func TestNewRejectsNilBundles(t *testing.T) {
	if _, err := tlsspiffe.New(nil); err == nil {
		t.Fatalf("expected nil bundles to fail")
	}
}

func TestAuthenticateSuccess(t *testing.T) {
	ca := newCA(t, "example.org")
	chain := ca.issue(t, "/ns/prod/sa/app/pod/pod-a/uid-1")

	a, err := tlsspiffe.New(ca.bundle())
	if err != nil {
		t.Fatalf("new authenticator: %v", err)
	}

	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}

	spi, ok := id.(clientauthn.SPIFFEIdentity)
	if !ok {
		t.Fatalf("expected SPIFFEIdentity, got %T", id)
	}
	if got, want := spi.URI(), "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1"; got != want {
		t.Errorf("URI() = %q, want %q", got, want)
	}
}

func TestAuthenticateRejectsNoTLS(t *testing.T) {
	ca := newCA(t, "example.org")
	a, _ := tlsspiffe.New(ca.bundle())

	_, err := a.Authenticate(&http.Request{})
	if !errors.Is(err, clientauthn.ErrNotTLS) {
		t.Fatalf("err = %v, want ErrNotTLS", err)
	}
}

func TestAuthenticateRejectsNoPeerCert(t *testing.T) {
	ca := newCA(t, "example.org")
	a, _ := tlsspiffe.New(ca.bundle())

	r := &http.Request{TLS: &tls.ConnectionState{}}
	_, err := a.Authenticate(r)
	if !errors.Is(err, clientauthn.ErrNoClientCertificate) {
		t.Fatalf("err = %v, want ErrNoClientCertificate", err)
	}
}

func TestAuthenticateRejectsWrongTrustDomain(t *testing.T) {
	issuerCA := newCA(t, "untrusted.example")
	chain := issuerCA.issue(t, "/ns/prod/sa/app/pod/x/uid-1")

	trustedCA := newCA(t, "example.org")
	a, _ := tlsspiffe.New(trustedCA.bundle())

	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatalf("expected untrusted trust domain to fail")
	}
}

func TestAuthenticateRejectsExpiredCert(t *testing.T) {
	ca := newCA(t, "example.org")

	// Issue a cert that's already expired.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u := &url.URL{Scheme: "spiffe", Host: "example.org", Path: "/ns/prod/sa/x/pod/y/uid-1"}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &leafKey.PublicKey, ca.caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	chain := []*x509.Certificate{leaf, ca.caCert}

	a, _ := tlsspiffe.New(ca.bundle())
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatalf("expected expired cert to fail")
	}
}

// TestAuthenticateRejectsMultipleURISANs verifies that a leaf bearing
// two URI SANs is rejected. The SPIFFE X.509 profile (SPIFFE ID v1.1)
// mandates exactly one URI SAN per SVID: a leaf with two would be
// ambiguous about which identity the peer claims, and a buggy
// authenticator that picked arbitrary one could be induced to
// authenticate under an attacker-smuggled SPIFFE ID while the
// chain-verification path only examined the "intended" one.
func TestAuthenticateRejectsMultipleURISANs(t *testing.T) {
	ca := newCA(t, "example.org")

	// Issue a leaf with two URI SANs: a legitimate SPIFFE URI and
	// a second SPIFFE URI under the same trust domain. The SPIFFE
	// leaf-validation rule requires exactly one, so x509svid.Verify
	// must reject it.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u1 := &url.URL{Scheme: "spiffe", Host: "example.org", Path: "/ns/prod/sa/app/pod/legit/uid-1"}
	u2 := &url.URL{Scheme: "spiffe", Host: "example.org", Path: "/ns/prod/sa/app/pod/smuggled/uid-2"}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(123),
		Subject:      pkix.Name{CommonName: "double-uri-san"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{u1, u2},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &leafKey.PublicKey, ca.caKey)
	if err != nil {
		t.Fatalf("create leaf with two URI SANs: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	chain := []*x509.Certificate{leaf, ca.caCert}

	a, _ := tlsspiffe.New(ca.bundle())
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatalf("expected leaf with two URI SANs to fail authentication")
	}
}

func TestAuthenticateRejectsNonSPIFFECert(t *testing.T) {
	ca := newCA(t, "example.org")

	// Issue a leaf with no URI SAN — not a SPIFFE cert.
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(77),
		Subject:      pkix.Name{CommonName: "not-spiffe"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.caCert, &leafKey.PublicKey, ca.caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	chain := []*x509.Certificate{leaf, ca.caCert}

	a, _ := tlsspiffe.New(ca.bundle())
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatalf("expected non-SPIFFE cert to fail")
	}
}
