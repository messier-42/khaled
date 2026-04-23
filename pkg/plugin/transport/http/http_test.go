package http_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
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
	klog "github.com/messier-42/khaled/pkg/log"
	httpt "github.com/messier-42/khaled/pkg/plugin/transport/http"
	"github.com/messier-42/khaled/pkg/x509source"
)

// freePort asks the kernel for an available localhost TCP port,
// closes the probe socket, and returns the address string.
func freePort(ctx context.Context) (string, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().(*net.TCPAddr)
	if err := l.Close(); err != nil {
		return "", err
	}
	return fmt.Sprintf("127.0.0.1:%d", addr.Port), nil
}

// writeTestCert creates a self-signed ECDSA certificate/key pair in
// dir and returns their paths.
func writeTestCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

// fileCertSource builds a file-backed x509source.Source for tests
// and registers Close with t.Cleanup. The transport does not close
// its CertSource, so the test owns the lifetime.
func fileCertSource(t *testing.T, dir string) x509source.Source {
	t.Helper()
	cert, key := writeTestCert(t, dir)
	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: cert,
		KeyFilePath:         key,
	})
	if err != nil {
		t.Fatalf("x509source.New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })
	return src
}

func fileCertConfig(t *testing.T, dir string) httpt.Config {
	t.Helper()
	return httpt.Config{CertSource: fileCertSource(t, dir)}
}

func TestNewRejectsMissingAddress(t *testing.T) {
	dir := t.TempDir()
	cfg := fileCertConfig(t, dir)
	_, err := httpt.New(t.Context(), cfg)
	if err == nil {
		t.Fatalf("expected missing address to fail")
	}
}

func TestNewRejectsMissingCertSource(t *testing.T) {
	_, err := httpt.New(t.Context(), httpt.Config{Address: ":0"})
	if err == nil {
		t.Fatalf("expected missing CertSource to fail")
	}
}

// TestNewFailsWhenAddressInUse pins the contract that bind failures
// surface synchronously from New, not asynchronously from a later
// Run. Without this, main can proceed into the reload loop with no
// working listener and the daemon stays alive despite being unable
// to serve any traffic.
func TestNewFailsWhenAddressInUse(t *testing.T) {
	var lc net.ListenConfig
	blocker, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind blocker: %v", err)
	}
	defer blocker.Close() // best effort
	addr := blocker.Addr().String()

	dir := t.TempDir()
	cfg := fileCertConfig(t, dir)
	cfg.Address = addr

	tr, err := httpt.New(t.Context(), cfg)
	if err == nil {
		_ = tr.Close()
		t.Fatalf("expected address-in-use to fail synchronously")
	}
	if !strings.Contains(err.Error(), "listen") {
		t.Errorf("error does not mention listen: %v", err)
	}
}

func TestRunServesAndReturns404(t *testing.T) {
	dir := t.TempDir()
	addr, err := freePort(t.Context())
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	cfg := fileCertConfig(t, dir)
	cfg.Address = addr
	tr, err := httpt.New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer tr.Close() // best effort

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()

	client := &stdhttp.Client{
		Transport: &stdhttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
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

	cancel()
	select {
	case runErr := <-done:
		if runErr != nil {
			t.Fatalf("run returned: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("transport did not shut down")
	}
}

// TestCloseRacesRunNoDataRace drives concurrent Close/Run pairs so the
// race detector catches any unsynchronised access to t.server or the
// closed flag.
func TestCloseRacesRunNoDataRace(t *testing.T) {
	for i := range 10 {
		dir := t.TempDir()
		addr, err := freePort(t.Context())
		if err != nil {
			t.Fatalf("free port: %v", err)
		}
		cfg := fileCertConfig(t, dir)
		cfg.Address = addr
		tr, err := httpt.New(t.Context(), cfg)
		if err != nil {
			t.Fatalf("new: %v", err)
		}

		runDone := make(chan error, 1)
		go func() { runDone <- tr.Run(context.Background()) }()
		// Race Close against Run without waiting for Run to start.
		_ = tr.Close()

		select {
		case <-runDone:
		case <-time.After(2 * time.Second):
			t.Fatalf("Run did not return after Close (iteration %d)", i)
		}
	}
}

func TestRunLogsReceiveAndCompletion(t *testing.T) {
	dir := t.TempDir()
	addr, err := freePort(t.Context())
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	cfg := fileCertConfig(t, dir)
	cfg.Address = addr
	tr, err := httpt.New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer tr.Close() // best effort

	// Install a Debug-level JSON logger that writes into a buffer, so
	// we can introspect the middleware's output.
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(klog.NewCtxHandler(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))))
	defer slog.SetDefault(prev)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()

	client := &stdhttp.Client{
		Transport: &stdhttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}

	u := url.URL{Scheme: "https", Host: addr, Path: "/integration"}
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
	_ = resp.Body.Close()
	if resp.StatusCode != stdhttp.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}

	cancel()
	if runErr := <-done; runErr != nil {
		t.Fatalf("run returned: %v", runErr)
	}

	var recv, comp map[string]any
	for line := range strings.SplitSeq(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		switch rec["msg"] {
		case "http request received":
			recv = rec
		case "http request completed":
			comp = rec
		}
	}
	if recv == nil {
		t.Fatalf("no receive record; full output: %s", buf.String())
	}
	if comp == nil {
		t.Fatalf("no completion record; full output: %s", buf.String())
	}
	if recv["correlationID"] != comp["correlationID"] {
		t.Errorf("correlationID mismatch: recv=%v comp=%v", recv["correlationID"], comp["correlationID"])
	}
	if recv["path"] != "/integration" {
		t.Errorf("recv path = %v", recv["path"])
	}
	if comp["status"] != float64(stdhttp.StatusNotFound) {
		t.Errorf("comp status = %v, want 404", comp["status"])
	}
}

func TestKeyLogFileIsAppended(t *testing.T) {
	dir := t.TempDir()
	keylogPath := filepath.Join(dir, "keylog.txt")

	addr, err := freePort(t.Context())
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	cfg := fileCertConfig(t, dir)
	cfg.Address = addr

	fh, err := os.OpenFile(keylogPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open keylog: %v", err)
	}
	cfg.KeyLog = fh

	tr, err := httpt.New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer tr.Close() // best effort

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tr.Run(ctx) }()

	client := &stdhttp.Client{
		Transport: &stdhttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	u := url.URL{Scheme: "https", Host: addr, Path: "/"}
	for range 50 {
		req, _ := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, u.String(), nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	cancel()
	<-done

	info, err := os.Stat(keylogPath)
	if err != nil {
		t.Fatalf("stat keylog: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("keylog file is empty; expected TLS key material to be appended")
	}
}

func TestConfigFromSnapshotFileSource(t *testing.T) {
	entry := config.Map{
		"use":     "http",
		"address": ":5000",
		"http": config.Map{
			"tls": config.Map{
				"keylog": "/tmp/kl",
				"serverCertificate": config.Map{
					"source":              "file",
					"certificateFilePath": "/tmp/cert.pem",
					"keyFilePath":         "/tmp/key.pem",
				},
			},
		},
	}
	root := config.Map{"listeners": config.Array{entry}}
	cfg, err := httpt.ConfigFromSnapshot(entry, root)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if cfg.Address != ":5000" {
		t.Errorf("address = %q, want :5000", cfg.Address)
	}
	if got := httpt.KeyLogPathFromSnapshot(entry); got != "/tmp/kl" {
		t.Errorf("keylog = %q", got)
	}
	certCfg := httpt.CertConfigFromSnapshot(entry, root)
	if certCfg.Kind != x509source.KindFile {
		t.Errorf("kind = %q, want file", certCfg.Kind)
	}
	if certCfg.CertificateFilePath != "/tmp/cert.pem" {
		t.Errorf("cert path = %q", certCfg.CertificateFilePath)
	}
	if certCfg.KeyFilePath != "/tmp/key.pem" {
		t.Errorf("key path = %q", certCfg.KeyFilePath)
	}
}

func TestConfigFromSnapshotSPIFFESourcePullsSocketFromRoot(t *testing.T) {
	entry := config.Map{
		"use":     "http",
		"address": ":5000",
		"http": config.Map{
			"tls": config.Map{
				"serverCertificate": config.Map{
					"source": "spiffe",
				},
			},
		},
	}
	root := config.Map{
		"spiffe": config.Map{
			"workloadSocketPath": "/run/spire/agent.sock",
		},
	}
	certCfg := httpt.CertConfigFromSnapshot(entry, root)
	if certCfg.Kind != x509source.KindSPIFFE {
		t.Errorf("kind = %q, want spiffe", certCfg.Kind)
	}
	if certCfg.WorkloadSocketPath != "/run/spire/agent.sock" {
		t.Errorf("socket path = %q, want /run/spire/agent.sock", certCfg.WorkloadSocketPath)
	}
}

func TestConfigFromSnapshotRequiresAddress(t *testing.T) {
	entry := config.Map{"use": "http"}
	if _, err := httpt.ConfigFromSnapshot(entry, config.Map{}); err == nil {
		t.Fatalf("expected missing address to fail")
	}
}

func TestCertConfigFromSnapshotDefaultsSourceToFile(t *testing.T) {
	entry := config.Map{
		"use":     "http",
		"address": ":1",
	}
	certCfg := httpt.CertConfigFromSnapshot(entry, config.Map{})
	if certCfg.Kind != x509source.KindFile {
		t.Errorf("default kind = %q, want file", certCfg.Kind)
	}
}
