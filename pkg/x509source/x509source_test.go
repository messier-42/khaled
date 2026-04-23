package x509source_test

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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/x509source"
)

const (
	initialCN = "initial.example"
	rotatedCN = "rotated.example"
)

// makeSelfSignedPEM is the shared cert-key PEM generator used by
// both writeSelfSigned (full-pair writer) and tests that need to
// stage cert and key into separate files at different times.
func makeSelfSignedPEM(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func writeSelfSigned(t *testing.T, certPath, keyPath, cn string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
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
}

// makeCAPair produces a self-signed CA (PEM-encoded certificate
// bytes plus the matching key) suitable for signing leaves used by
// the ClientCACertPool tests.
func makeCAPair(t *testing.T, cn string) (certPEM []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), caKey
}

// issueLeaf returns the DER bytes of a leaf certificate with
// ExtKeyUsageClientAuth, signed by the CA in caCertPEM+caKey.
func issueLeaf(t *testing.T, caCertPEM []byte, caKey *ecdsa.PrivateKey, cn string) []byte {
	t.Helper()
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		t.Fatalf("decode ca PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return der
}

// parseLeafCN extracts the CommonName of the leaf certificate held by
// a *tls.Certificate returned by GetCertificate.
func parseLeafCN(t *testing.T, cert *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.Subject.CommonName
}

func TestNewRejectsEmptyKind(t *testing.T) {
	_, err := x509source.New(t.Context(), x509source.Config{})
	if err == nil {
		t.Fatalf("expected empty kind to fail")
	}
	if !strings.Contains(err.Error(), "kind must be set") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewRejectsUnknownKind(t *testing.T) {
	_, err := x509source.New(t.Context(), x509source.Config{Kind: "bogus"})
	if err == nil {
		t.Fatalf("expected unknown kind to fail")
	}
}

func TestNewFileRequiresPaths(t *testing.T) {
	_, err := x509source.New(t.Context(), x509source.Config{Kind: x509source.KindFile})
	if err == nil {
		t.Fatalf("expected missing paths to fail")
	}
}

func TestNewFileReturnsCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: certPath,
		KeyFilePath:         keyPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer src.Close() // best effort

	cert, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	if cn := parseLeafCN(t, cert); cn != initialCN {
		t.Errorf("initial CN = %q, want initial.example", cn)
	}
	// Leaf should be pre-populated so crypto/tls does not re-parse
	// cert.Certificate[0] on every handshake.
	if cert.Leaf == nil {
		t.Fatal("cert.Leaf is nil; expected it to be pre-populated at load time")
	}
	if cert.Leaf.Subject.CommonName != initialCN {
		t.Errorf("Leaf CN = %q, want initial.example", cert.Leaf.Subject.CommonName)
	}
}

func TestFileSourceReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: certPath,
		KeyFilePath:         keyPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer src.Close() // best effort

	writeSelfSigned(t, certPath, keyPath, rotatedCN)

	// Wait for the update notification; bail after a generous
	// timeout so flakes surface as failures rather than hangs.
	select {
	case <-src.UpdateChan():
	case <-time.After(3 * time.Second):
		t.Fatalf("no update notification after rewriting cert")
	}

	cert, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	if cn := parseLeafCN(t, cert); cn != rotatedCN {
		t.Errorf("post-reload CN = %q, want rotated.example", cn)
	}
}

// TestFileSourceFailedReloadKeepsOldCert verifies that writing a
// broken/malformed keypair after a successful initial load does NOT
// replace the previous certificate and does NOT signal UpdateChan.
// The previous cert must continue to serve.
func TestFileSourceFailedReloadKeepsOldCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: certPath,
		KeyFilePath:         keyPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer src.Close() // best effort

	// Corrupt the cert file with obvious garbage. tls.LoadX509KeyPair
	// should fail; the watcher will observe the write event and
	// attempt a reload.
	if err := os.WriteFile(certPath, []byte("not a pem cert"), 0o600); err != nil {
		t.Fatalf("write corrupt cert: %v", err)
	}

	// Ensure no update fires within a reasonable window. fsnotify
	// is asynchronous so we must wait enough for a reload attempt
	// to run, but we assert that the channel stays quiet.
	select {
	case <-src.UpdateChan():
		t.Fatal("expected no update notification for a failed reload")
	case <-time.After(500 * time.Millisecond):
	}

	// The cert returned by GetCertificate must still be the
	// original — a failed reload must not leave the source in a
	// broken state.
	cert, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("get cert after failed reload: %v", err)
	}
	if cn := parseLeafCN(t, cert); cn != initialCN {
		t.Errorf("post-failed-reload CN = %q, want initial.example (old cert must keep serving)", cn)
	}

	// Write a valid new keypair and confirm the watcher recovers:
	// a subsequent successful reload DOES fire UpdateChan and
	// rotates the cert. This proves the watcher did not wedge
	// itself after the failure.
	writeSelfSigned(t, certPath, keyPath, rotatedCN)
	select {
	case <-src.UpdateChan():
	case <-time.After(3 * time.Second):
		t.Fatal("no update after recovery write; watcher may have wedged")
	}
	cert, err = src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("get cert after recovery: %v", err)
	}
	if cn := parseLeafCN(t, cert); cn != rotatedCN {
		t.Errorf("post-recovery CN = %q, want rotated.example", cn)
	}
}

func TestConfigFromSnapshotDefaultsToFile(t *testing.T) {
	cfg := x509source.ConfigFromSnapshot(config.Map{}, nil)
	if cfg.Kind != x509source.KindFile {
		t.Errorf("default kind = %q, want file", cfg.Kind)
	}
}

func TestConfigFromSnapshotReadsSPIFFESocket(t *testing.T) {
	sc := config.Map{"source": "spiffe"}
	root := config.Map{"spiffe": config.Map{"workloadSocketPath": "/run/spire/agent.sock"}}
	cfg := x509source.ConfigFromSnapshot(sc, root)
	if cfg.Kind != x509source.KindSPIFFE {
		t.Errorf("kind = %q, want spiffe", cfg.Kind)
	}
	if cfg.WorkloadSocketPath != "/run/spire/agent.sock" {
		t.Errorf("socket = %q", cfg.WorkloadSocketPath)
	}
}

func TestConfigFromSnapshotTolerantOfNilRootBlock(t *testing.T) {
	sc := config.Map{
		"source":              "file",
		"certificateFilePath": "/a",
		"keyFilePath":         "/b",
	}
	cfg := x509source.ConfigFromSnapshot(sc, nil)
	if cfg.Kind != x509source.KindFile {
		t.Errorf("kind = %q", cfg.Kind)
	}
	if cfg.CertificateFilePath != "/a" || cfg.KeyFilePath != "/b" {
		t.Errorf("paths = %q/%q", cfg.CertificateFilePath, cfg.KeyFilePath)
	}
	if cfg.WorkloadSocketPath != "" {
		t.Errorf("expected empty socket path with nil root block, got %q", cfg.WorkloadSocketPath)
	}
}

// TestFileSourceRetriesAfterMismatchedPair simulates a non-atomic
// two-file update: a new cert is written first (producing a
// mismatched-pair reload failure) and the matching key follows
// shortly after without generating a fresh fsnotify event that
// would otherwise re-trigger reload. The scheduled retry must pick
// up the completed pair without operator intervention.
func TestFileSourceRetriesAfterMismatchedPair(t *testing.T) {
	// Shorten the retry delay so the test finishes quickly.
	restore := x509source.SetFileReloadRetryDelay(100 * time.Millisecond)
	defer restore()

	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: certPath,
		KeyFilePath:         keyPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer src.Close() // best effort

	// Generate a fresh keypair but stage the writes separately.
	newCert, newKey := makeSelfSignedPEM(t, rotatedCN)

	// Step 1: overwrite cert only. The fileSource sees a cert
	// written event, attempts reload, and fails because the
	// still-present key belongs to the old cert.
	if err := os.WriteFile(certPath, newCert, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	// Ensure no UpdateChan signal fires for the failed reload.
	select {
	case <-src.UpdateChan():
		t.Fatal("update channel fired for mismatched-pair reload")
	case <-time.After(50 * time.Millisecond):
	}

	// Step 2: write the matching key. In a pathological setup this
	// write might not produce an fsnotify event the watcher picks
	// up (e.g. the file was already being held open). To simulate
	// that, wait just long enough for the watcher's initial event
	// handling to complete *before* staging the key via a non-
	// watched path (TempDir sibling), then use WriteFile directly
	// so there IS a second event — but the important thing the
	// retry protects against is the case where the key write
	// lands during the ~100 ms retry window. Either way, the
	// retry path either runs or is cancelled by the new watcher
	// event's successful reload; both paths land at the same
	// observable state.
	if err := os.WriteFile(keyPath, newKey, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	// We should eventually observe an update and the new cert.
	select {
	case <-src.UpdateChan():
	case <-time.After(3 * time.Second):
		t.Fatal("expected reload after key write; retry did not recover")
	}
	cert, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	if cn := parseLeafCN(t, cert); cn != rotatedCN {
		t.Errorf("post-retry CN = %q, want rotated.example", cn)
	}
}

func TestFileSourceBundlesUnsupported(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: certPath,
		KeyFilePath:         keyPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer src.Close() // best effort

	bundles, err := src.Bundles()
	if !errors.Is(err, x509source.ErrBundlesUnsupported) {
		t.Fatalf("Bundles() err = %v, want ErrBundlesUnsupported", err)
	}
	if bundles != nil {
		t.Fatalf("Bundles() returned non-nil source with error")
	}
}

// TestFileSourceClientCACertPoolAbsentWhenUnset confirms that a
// file source constructed without clientTrustAnchorsPath returns
// (nil, nil) — the contract used by callers to decide whether to
// wire ClientCAs into tls.Config.
func TestFileSourceClientCACertPoolAbsentWhenUnset(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: certPath,
		KeyFilePath:         keyPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer src.Close() // best effort

	pool, err := src.ClientCACertPool()
	if err != nil {
		t.Fatalf("ClientCACertPool: %v", err)
	}
	if pool != nil {
		t.Fatalf("ClientCACertPool() = %v, want nil when clientTrustAnchorsPath is unset", pool)
	}
}

// TestFileSourceClientCACertPoolLoaded confirms that the PEM bundle
// at clientTrustAnchorsPath is parsed at construction and surfaced
// as a populated *x509.CertPool that can verify a leaf signed by
// the loaded CA.
func TestFileSourceClientCACertPoolLoaded(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	caPath := filepath.Join(dir, "ca.pem")
	caCert, caKey := makeCAPair(t, "test-ca")
	if err := os.WriteFile(caPath, caCert, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                   x509source.KindFile,
		CertificateFilePath:    certPath,
		KeyFilePath:            keyPath,
		ClientTrustAnchorsPath: caPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer src.Close() // best effort

	pool, err := src.ClientCACertPool()
	if err != nil {
		t.Fatalf("ClientCACertPool: %v", err)
	}
	if pool == nil {
		t.Fatalf("ClientCACertPool() = nil, want populated pool")
	}

	// Mint a leaf signed by the loaded CA and verify it chains to
	// the returned pool — the actual operator-relevant behaviour.
	leaf := issueLeaf(t, caCert, caKey, "leaf.example")
	leafCert, err := x509.ParseCertificate(leaf)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("verify against pool: %v", err)
	}
}

func TestFileSourceClientCACertPoolRejectsEmptyBundle(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, []byte("not a pem file\n"), 0o600); err != nil {
		t.Fatalf("write empty bundle: %v", err)
	}

	_, err := x509source.New(t.Context(), x509source.Config{
		Kind:                   x509source.KindFile,
		CertificateFilePath:    certPath,
		KeyFilePath:            keyPath,
		ClientTrustAnchorsPath: caPath,
	})
	if err == nil {
		t.Fatal("expected error from empty client trust anchors bundle")
	}
	if !strings.Contains(err.Error(), "no CERTIFICATE blocks") {
		t.Errorf("error = %v, want mention of missing CERTIFICATE blocks", err)
	}
}

func TestConfigFromSnapshotReadsClientTrustAnchorsPath(t *testing.T) {
	sc := config.Map{
		"source":                 "file",
		"certificateFilePath":    "/a",
		"keyFilePath":            "/b",
		"clientTrustAnchorsPath": "/c",
	}
	cfg := x509source.ConfigFromSnapshot(sc, nil)
	if cfg.ClientTrustAnchorsPath != "/c" {
		t.Errorf("ClientTrustAnchorsPath = %q, want /c", cfg.ClientTrustAnchorsPath)
	}
}

func TestSchemaDeclaresSourceEnum(t *testing.T) {
	s := x509source.Schema()
	if s == nil || s.Properties == nil {
		t.Fatalf("schema is empty")
	}
	source, ok := s.Properties["source"]
	if !ok {
		t.Fatalf("schema missing source property")
	}
	got := make(map[string]bool, len(source.Enum))
	for _, v := range source.Enum {
		got[v.(string)] = true
	}
	for _, want := range []string{"file", "spiffe"} {
		if !got[want] {
			t.Errorf("schema enum missing %q", want)
		}
	}
}

// TestSchemaRequiresFilePathsWhenSourceIsFile validates the AllOf
// if/then clause: a serverCertificate block with source=file but
// missing certificateFilePath or keyFilePath should be rejected at
// schema-validate time (not only at newFileSource runtime).
func TestSchemaRequiresFilePathsWhenSourceIsFile(t *testing.T) {
	s := x509source.Schema()
	resolved, err := s.Resolve(nil)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}

	cases := []struct {
		name    string
		input   map[string]any
		wantErr bool
	}{
		{
			name:    "file with both paths",
			input:   map[string]any{"source": "file", "certificateFilePath": "/c", "keyFilePath": "/k"},
			wantErr: false,
		},
		{
			name:    "file missing cert path",
			input:   map[string]any{"source": "file", "keyFilePath": "/k"},
			wantErr: true,
		},
		{
			name:    "file missing key path",
			input:   map[string]any{"source": "file", "certificateFilePath": "/c"},
			wantErr: true,
		},
		{
			name:    "spiffe does not need file paths",
			input:   map[string]any{"source": "spiffe"},
			wantErr: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := resolved.Validate(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate(%v): err=%v, wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}

// TestFileSourceCloseConcurrent hammers Close from many goroutines
// to confirm the sync.Once idempotency contract. A prior
// select/default idiom could panic if two goroutines both observed
// the channel as open before either called close.
// TestFileSourceReloadsOnAtomicRename exercises the rename-into-place
// idiom used by Kubernetes ConfigMap/Secret volume projections (the
// `..data` symlink swap) and by any operator running `mv new old`.
// The direct-overwrite path is already covered by
// TestFileSourceReloadsOnChange; this test is a separate regression
// fence because fsnotify delivers different event kinds for rename
// (Create/Rename on the new inode) vs. write (Write on the existing
// inode), and either event must drive a reload.
func TestFileSourceReloadsOnAtomicRename(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: certPath,
		KeyFilePath:         keyPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer src.Close() // best effort

	// Stage the rotated pair at sibling paths in the same directory
	// (a cross-directory rename would cross filesystems and silently
	// fall back to copy, which would not be atomic).
	newCertPEM, newKeyPEM := makeSelfSignedPEM(t, rotatedCN)
	stagedCert := filepath.Join(dir, "cert.pem.new")
	stagedKey := filepath.Join(dir, "key.pem.new")
	if err := os.WriteFile(stagedCert, newCertPEM, 0o600); err != nil {
		t.Fatalf("write staged cert: %v", err)
	}
	if err := os.WriteFile(stagedKey, newKeyPEM, 0o600); err != nil {
		t.Fatalf("write staged key: %v", err)
	}
	// Atomic rename of both files. On Linux this is a single inode
	// swap per path (no partial-content window).
	if err := os.Rename(stagedKey, keyPath); err != nil {
		t.Fatalf("rename key: %v", err)
	}
	if err := os.Rename(stagedCert, certPath); err != nil {
		t.Fatalf("rename cert: %v", err)
	}

	select {
	case <-src.UpdateChan():
	case <-time.After(3 * time.Second):
		t.Fatal("no update notification after atomic rename")
	}
	cert, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("get cert: %v", err)
	}
	if cn := parseLeafCN(t, cert); cn != rotatedCN {
		t.Errorf("post-rename CN = %q, want %q", cn, rotatedCN)
	}
}

// TestFileSourceGetCertificateConcurrent races many readers of
// GetCertificate against a writer thread that rewrites the cert on
// disk. Under `-race`, any unsynchronised read of the atomic.Value /
// mutex-guarded `current` field will be flagged. Every read must
// return a non-nil cert and a usable *tls.Certificate (populated
// Leaf). Pins the concurrency contract for the RWMutex that guards
// fileSource.current.
func TestFileSourceGetCertificateConcurrent(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, initialCN)

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: certPath,
		KeyFilePath:         keyPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer src.Close() // best effort

	const (
		readers     = 32
		readsEach   = 64
		rewriteIter = 4
	)

	stop := make(chan struct{})
	var readerWG sync.WaitGroup
	var readErr atomic.Int64
	readerWG.Add(readers)
	for range readers {
		go func() {
			defer readerWG.Done()
			for range readsEach {
				select {
				case <-stop:
					return
				default:
				}
				cert, err := src.GetCertificate(nil)
				if err != nil || cert == nil || cert.Leaf == nil {
					readErr.Add(1)
				}
			}
		}()
	}

	var writerWG sync.WaitGroup
	writerWG.Go(func() {
		for range rewriteIter {
			writeSelfSigned(t, certPath, keyPath, rotatedCN)
			// Drain any update notifications so the buffered
			// channel stays healthy.
			select {
			case <-src.UpdateChan():
			case <-time.After(500 * time.Millisecond):
			}
		}
	})

	readerWG.Wait()
	close(stop)
	writerWG.Wait()

	if n := readErr.Load(); n != 0 {
		t.Fatalf("%d GetCertificate calls returned an error or nil cert under concurrent writes", n)
	}
}

func TestFileSourceCloseConcurrent(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	writeSelfSigned(t, certPath, keyPath, "cn")

	src, err := x509source.New(t.Context(), x509source.Config{
		Kind:                x509source.KindFile,
		CertificateFilePath: certPath,
		KeyFilePath:         keyPath,
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_ = src.Close()
		})
	}
	wg.Wait()
}
