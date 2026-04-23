package khaledtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testCAMaterial is the process-cached CA used by the harness to
// sign both the server's TLS leaf and per-test client leaves. The
// CA is generated once per test binary run via sync.Once because
// keypair generation dominates per-test setup cost otherwise.
//
// PEM bytes are kept in memory so client trust pools and tls-ca
// bundles can be built without re-reading from disk; the on-disk
// copies (CABundlePath, ServerCertPath, ServerKeyPath) exist
// because the file-backed x509source and the tls-ca plugin both
// load from paths.
type testCAMaterial struct {
	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate

	CABundlePath   string // PEM file with just the CA cert
	CAPEM          []byte // same content as CABundlePath, in memory
	ServerCertPath string
	ServerKeyPath  string
}

var (
	caOnce sync.Once
	caVal  *testCAMaterial
	errCA  error

	// leafSerial is the source of monotonically increasing serials
	// for client leaves issued during the test binary's run. Atomic
	// because tests run in parallel.
	leafSerial atomic.Uint64
)

// caMaterial returns the process-cached CA + server cert. Tests use
// CABundlePath as the tls-ca plugin's caBundlePath and CAPEM as the
// trust anchor for client RootCAs.
func caMaterial(t *testing.T) *testCAMaterial {
	t.Helper()
	caOnce.Do(func() { caVal, errCA = generateCAMaterial() })
	if errCA != nil {
		t.Fatalf("khaledtest: build CA material: %v", errCA)
	}
	return caVal
}

func generateCAMaterial() (*testCAMaterial, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "khaledtest-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Server leaf signed by the CA. SAN includes "localhost" and the
	// loopback IPs because the harness dials https://127.0.0.1:<port>
	// with ServerName=localhost.
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "khaledtest-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caCert, &srvKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	srvKeyDER, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return nil, err
	}
	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: srvKeyDER})

	dir, err := os.MkdirTemp("", "khaledtest-ca-")
	if err != nil {
		return nil, err
	}
	caBundlePath := filepath.Join(dir, "ca.pem")
	srvCertPath := filepath.Join(dir, "server.crt")
	srvKeyPath := filepath.Join(dir, "server.key")
	for _, w := range []struct {
		path string
		data []byte
	}{
		{caBundlePath, caPEM},
		{srvCertPath, srvCertPEM},
		{srvKeyPath, srvKeyPEM},
	} {
		if err := os.WriteFile(w.path, w.data, 0o600); err != nil {
			return nil, err
		}
	}

	return &testCAMaterial{
		caKey:          caKey,
		caCert:         caCert,
		CABundlePath:   caBundlePath,
		CAPEM:          caPEM,
		ServerCertPath: srvCertPath,
		ServerKeyPath:  srvKeyPath,
	}, nil
}

// issueClientLeaf produces a client certificate signed by the
// harness CA whose first SAN URI is principalURI (when non-empty)
// and which is suitable for use as a tls.Config.Certificates entry.
// Each call produces a fresh keypair so concurrent tests cannot
// accidentally share a private key.
//
// principalURI is parsed and embedded as a SAN URI extension; an
// empty string yields a leaf with no SAN URI (useful for negative
// tests that want to exercise the tls-ca plugin's "no usable SAN"
// rejection path).
func (m *testCAMaterial) issueClientLeaf(t *testing.T, principalURI string) tls.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("khaledtest: gen client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(int64(leafSerial.Add(1)) + 1000),
		Subject:      pkix.Name{CommonName: "khaledtest-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if principalURI != "" {
		u, err := url.Parse(principalURI)
		if err != nil {
			t.Fatalf("khaledtest: parse principal URI %q: %v", principalURI, err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &leafKey.PublicKey, m.caKey)
	if err != nil {
		t.Fatalf("khaledtest: create client leaf: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  leafKey,
		Leaf:        mustParseCert(t, der),
	}
}

func mustParseCert(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("khaledtest: parse cert: %v", err)
	}
	return c
}
