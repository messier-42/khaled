package plugin_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/messier-42/khaled/pkg/plugin"
)

func TestNewAuthenticatorRejectsUnknown(t *testing.T) {
	_, err := plugin.NewAuthenticator(plugin.AuthenticatorArgs{PluginName: "bogus"})
	if err == nil {
		t.Fatalf("expected unknown plugin name to fail")
	}
}

func TestNewAuthenticatorRejectsTLSSpiffeWithoutBundles(t *testing.T) {
	_, err := plugin.NewAuthenticator(plugin.AuthenticatorArgs{
		PluginName: "tls-spiffe",
		Bundles:    nil,
	})
	if err == nil {
		t.Fatalf("expected missing bundles to fail")
	}
}

func TestNewAuthenticatorBuildsTLSSpiffe(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	bundles := x509bundle.New(td)

	auth, err := plugin.NewAuthenticator(plugin.AuthenticatorArgs{
		PluginName: "tls-spiffe",
		Bundles:    bundles,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := auth.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestNewAuthenticatorBuildsAnonymous(t *testing.T) {
	auth, err := plugin.NewAuthenticator(plugin.AuthenticatorArgs{
		PluginName: "anonymous",
		Anonymous:  plugin.AnonymousArgs{URI: "https://example.test/anon"},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := auth.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestNewAuthenticatorBuildsAnonymousWithDefaultURI(t *testing.T) {
	auth, err := plugin.NewAuthenticator(plugin.AuthenticatorArgs{
		PluginName: "anonymous",
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := auth.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestNewAuthenticatorBuildsTLSCA(t *testing.T) {
	auth, err := plugin.NewAuthenticator(plugin.AuthenticatorArgs{
		PluginName: "tls-ca",
		TLSCA:      plugin.TLSCAArgs{CABundlePath: writeOneShotCAPEM(t)},
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := auth.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestNewAuthenticatorRejectsTLSCAWithoutBundlePath(t *testing.T) {
	_, err := plugin.NewAuthenticator(plugin.AuthenticatorArgs{
		PluginName: "tls-ca",
	})
	if err == nil {
		t.Fatalf("expected missing CABundlePath to fail")
	}
}

// writeOneShotCAPEM creates a tempfile containing a single self-signed
// CA certificate and returns its path. Sufficient for tests that only
// need the tls-ca constructor to succeed.
func writeOneShotCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "factory-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}
