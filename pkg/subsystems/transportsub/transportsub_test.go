package transportsub

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	stdhttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin"
)

func writeTestCertFiles(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func freeLocalPort(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	_ = l.Close()
	return fmt.Sprintf("127.0.0.1:%d", addr.Port)
}

// TestStart_StartsHTTPListener verifies the real New helper boots a
// live HTTPS listener that answers 404 to unknown paths.
func TestStart_StartsHTTPListener(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeTestCertFiles(t, dir)
	addr := freeLocalPort(t)

	snap := config.Snapshot{Root: config.Map{
		"listeners": config.Array{
			config.Map{
				"use":     "http",
				"address": addr,
				"http": config.Map{
					"tls": config.Map{
						"serverCertificate": config.Map{
							"source":              "file",
							"certificateFilePath": certPath,
							"keyFilePath":         keyPath,
						},
					},
				},
			},
		},
	}}

	ctx := t.Context()

	rt, err := New(ctx, snap, plugin.TransportDeps{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = rt.Stop() }()

	client := &stdhttp.Client{
		Transport: &stdhttp.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   3 * time.Second,
	}
	u := url.URL{Scheme: "https", Host: addr, Path: "/anything"}
	var resp *stdhttp.Response
	for range 50 {
		req, _ := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, u.String(), nil)
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close() // best effort
	if resp.StatusCode != stdhttp.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestStart_FailsFastOnBadListener(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"listeners": config.Array{
			config.Map{
				"use":     "http",
				"address": ":0",
				// No cert material -> http plugin refuses.
			},
		},
	}}
	ctx := t.Context()
	_, err := New(ctx, snap, plugin.TransportDeps{})
	if err == nil {
		t.Fatalf("expected failure for missing certificate material")
	}
	if !strings.Contains(err.Error(), "listeners[0]") {
		t.Fatalf("expected error to be indexed by listener, got: %v", err)
	}
}

// TestStart_FailsFastOnAddressInUse pins the contract that a bind
// failure (port already in use) surfaces synchronously from New, so
// main can exit non-zero rather than settling into the reload loop
// with no working listener.
func TestStart_FailsFastOnAddressInUse(t *testing.T) {
	var lc net.ListenConfig
	blocker, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("blocker listen: %v", err)
	}
	defer blocker.Close() // best effort
	addr := blocker.Addr().String()

	dir := t.TempDir()
	certPath, keyPath := writeTestCertFiles(t, dir)

	snap := config.Snapshot{Root: config.Map{
		"listeners": config.Array{
			config.Map{
				"use":     "http",
				"address": addr,
				"http": config.Map{
					"tls": config.Map{
						"serverCertificate": config.Map{
							"source":              "file",
							"certificateFilePath": certPath,
							"keyFilePath":         keyPath,
						},
					},
				},
			},
		},
	}}
	ctx := t.Context()
	_, err = New(ctx, snap, plugin.TransportDeps{})
	if err == nil {
		t.Fatalf("expected address-in-use to fail Start")
	}
	if !strings.Contains(err.Error(), "listeners[0]") {
		t.Fatalf("expected error indexed by listener, got: %v", err)
	}
}
