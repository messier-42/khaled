package tlsca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn/tlsca"
)

// testCA is a self-signed CA used to issue leaf certs for the tests.
// Mirrors the shape used by tlsspiffe_test.go but produces non-SPIFFE
// leaves: callers control the SAN URIs / DNS names directly.
type testCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tls-ca-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return &testCA{key: key, cert: cert}
}

// writePEM writes the CA certificate to a tempfile and returns the
// path. Mirrors how operators supply caBundlePath in production.
func (ca *testCA) writePEM(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca pem: %v", err)
	}
	return path
}

// issue produces a leaf signed by ca with the supplied SAN sets. The
// returned chain is leaf-then-CA, ready to drop into
// tls.ConnectionState.PeerCertificates.
func (ca *testCA) issue(t *testing.T, sanURIs []*url.URL, sanDNS []string, sanIPs []net.IP) []*x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         sanURIs,
		DNSNames:     sanDNS,
		IPAddresses:  sanIPs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return []*x509.Certificate{leaf, ca.cert}
}

func TestNewRejectsEmptyPath(t *testing.T) {
	if _, err := tlsca.New(""); err == nil {
		t.Fatalf("expected empty path to fail")
	}
}

func TestNewRejectsMissingFile(t *testing.T) {
	if _, err := tlsca.New(filepath.Join(t.TempDir(), "does-not-exist.pem")); err == nil {
		t.Fatalf("expected missing file to fail")
	}
}

func TestNewRejectsBundleWithNoCertificates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(path, []byte("not a pem block\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := tlsca.New(path); err == nil {
		t.Fatalf("expected empty bundle to fail")
	}
}

func TestAuthenticateSuccess_SANURI(t *testing.T) {
	ca := newTestCA(t)
	chain := ca.issue(t,
		[]*url.URL{{Scheme: "spiffe", Host: "example.org", Path: "/svc/a"}},
		nil, nil,
	)
	a, err := tlsca.New(ca.writePEM(t))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	tid, ok := id.(clientauthn.TLSCAIdentity)
	if !ok {
		t.Fatalf("identity type = %T, want TLSCAIdentity", id)
	}
	if got, want := tid.URI(), "spiffe://example.org/svc/a"; got != want {
		t.Errorf("URI() = %q, want %q", got, want)
	}
}

func TestAuthenticateSuccess_SANDNSFallback(t *testing.T) {
	ca := newTestCA(t)
	chain := ca.issue(t, nil, []string{"client-a.example.com"}, nil)
	a, err := tlsca.New(ca.writePEM(t))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got, want := id.URI(), "dns://client-a.example.com"; got != want {
		t.Errorf("URI() = %q, want %q", got, want)
	}
}

func TestAuthenticateSANURIWinsOverDNS(t *testing.T) {
	ca := newTestCA(t)
	chain := ca.issue(t,
		[]*url.URL{{Scheme: "https", Host: "id.example.org", Path: "/svc/a"}},
		[]string{"client-a.example.com"},
		nil,
	)
	a, _ := tlsca.New(ca.writePEM(t))
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	id, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if got, want := id.URI(), "https://id.example.org/svc/a"; got != want {
		t.Errorf("URI() = %q, want %q (URI must beat DNS fallback)", got, want)
	}
}

func TestAuthenticateRejectsLeafWithNoUsableSAN(t *testing.T) {
	ca := newTestCA(t)
	// Only an IP SAN — neither URI nor DNS, so no usable identity.
	chain := ca.issue(t, nil, nil, []net.IP{net.IPv4(10, 0, 0, 1)})
	a, _ := tlsca.New(ca.writePEM(t))
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatalf("expected leaf with no SAN URI/DNS to fail")
	}
}

func TestAuthenticateRejectsCNOnly(t *testing.T) {
	// A leaf whose only identifying field is the Subject CN. CN is
	// deliberately not consulted: the cert must fail to authenticate.
	ca := newTestCA(t)
	chain := ca.issue(t, nil, nil, nil)
	a, _ := tlsca.New(ca.writePEM(t))
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatalf("expected CN-only leaf to fail")
	}
}

func TestAuthenticateRejectsNoTLS(t *testing.T) {
	ca := newTestCA(t)
	a, _ := tlsca.New(ca.writePEM(t))
	if _, err := a.Authenticate(&http.Request{}); !errors.Is(err, clientauthn.ErrNotTLS) {
		t.Fatalf("err = %v, want ErrNotTLS", err)
	}
}

func TestAuthenticateRejectsNoPeerCert(t *testing.T) {
	ca := newTestCA(t)
	a, _ := tlsca.New(ca.writePEM(t))
	r := &http.Request{TLS: &tls.ConnectionState{}}
	if _, err := a.Authenticate(r); !errors.Is(err, clientauthn.ErrNoClientCertificate) {
		t.Fatalf("err = %v, want ErrNoClientCertificate", err)
	}
}

func TestAuthenticateRejectsUntrustedCA(t *testing.T) {
	issuerCA := newTestCA(t)
	chain := issuerCA.issue(t, []*url.URL{{Scheme: "spiffe", Host: "x", Path: "/y"}}, nil, nil)

	trustedCA := newTestCA(t)
	a, _ := tlsca.New(trustedCA.writePEM(t))
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatalf("expected untrusted CA to fail")
	}
}

func TestAuthenticateRejectsExpiredCert(t *testing.T) {
	ca := newTestCA(t)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{{Scheme: "spiffe", Host: "x", Path: "/y"}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	chain := []*x509.Certificate{leaf, ca.cert}
	a, _ := tlsca.New(ca.writePEM(t))
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatalf("expected expired leaf to fail")
	}
}

func TestAuthenticateRejectsLeafMissingClientAuthEKU(t *testing.T) {
	ca := newTestCA(t)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(101),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// Server auth EKU only — leaf must be rejected for client use.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		URIs:        []*url.URL{{Scheme: "spiffe", Host: "x", Path: "/y"}},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &leafKey.PublicKey, ca.key)
	leaf, _ := x509.ParseCertificate(der)
	chain := []*x509.Certificate{leaf, ca.cert}
	a, _ := tlsca.New(ca.writePEM(t))
	r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
	if _, err := a.Authenticate(r); err == nil {
		t.Fatalf("expected leaf without ClientAuth EKU to fail")
	}
}

func TestNewParsesMultipleCertsInBundle(t *testing.T) {
	caA := newTestCA(t)
	caB := newTestCA(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.pem")
	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caA.cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caB.cert.Raw})...,
	)
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	a, err := tlsca.New(path)
	if err != nil {
		t.Fatalf("new with concatenated bundle: %v", err)
	}
	// Both CAs should be accepted as roots.
	for i, ca := range []*testCA{caA, caB} {
		chain := ca.issue(t, []*url.URL{{Scheme: "spiffe", Host: "example", Path: "/x"}}, nil, nil)
		r := &http.Request{TLS: &tls.ConnectionState{PeerCertificates: chain}}
		if _, err := a.Authenticate(r); err != nil {
			t.Errorf("ca %d: authenticate: %v", i, err)
		}
	}
}
