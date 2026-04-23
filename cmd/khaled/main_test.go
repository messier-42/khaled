package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/config/schema"
	"github.com/messier-42/khaled/pkg/plugin/configsource"
	"github.com/messier-42/khaled/pkg/server"
)

// TestMain installs a pre-cancelled runContext and a set of no-op
// subsystem mocks for every cobra-driven test in this package so that:
//
//   - the post-initial-load reload loop exits immediately,
//   - tests do not need real SQLite / TLS / Cedar material.
//
// Tests that need to exercise the real reload loop install their
// own runContext via the package-level var.
func TestMain(m *testing.M) {
	previousRunContext := runContext
	previousStarterSet := starterSet
	runContext = preCancelledContext
	ss := server.MockStarterSet()
	starterSet = &ss

	code := m.Run()

	starterSet = previousStarterSet
	runContext = previousRunContext
	os.Exit(code)
}

func preCancelledContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx, cancel
}

// validYAML is a minimal config that satisfies the schema registered
// by server.BuildRegistry. Used by tests that exercise the bootstrap
// path without caring about specific config values. The disk path
// and policy path do not need to exist because the TestMain stubs
// short-circuit every starter.
const validYAML = `
keyStorage:
  use: disk
  disk:
    path: /var/lib/khaled
policyEngine:
  use: cedar
policySource:
  use: file
  file:
    path: /etc/khaled/policy.cedar
clientAuthn:
  use: tls-spiffe
claimsMapping:
  use: k8s-attestation
listeners:
  - use: http
    address: ":5000"
`

// fakeConfigSource is a minimal in-memory configsource.Source for
// tests that swap configSourceFactory. UpdateChan returns a channel
// the test can use to signal reloads; Current returns the most
// recently-set snapshot.
type fakeConfigSource struct {
	currentSnap config.Snapshot
	currentErr  error
	closed      bool
	updates     chan error
}

var _ configsource.Source = (*fakeConfigSource)(nil)

func (f *fakeConfigSource) Current() (config.Snapshot, error) {
	return f.currentSnap, f.currentErr
}

func (f *fakeConfigSource) UpdateChan() <-chan error { return f.updates }

func (f *fakeConfigSource) Close() error {
	f.closed = true
	return nil
}

func swapConfigSourceFactory(factory func(options, *schema.Registry) (configsource.Source, error)) func() {
	previous := configSourceFactory
	configSourceFactory = factory
	return func() {
		configSourceFactory = previous
	}
}

func TestLoadConfigDefaultsToDiskSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "khaled.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("KHALED_CONFIG", path)

	if err := run([]string{}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestLoadConfigRejectsUnsupportedSource(t *testing.T) {
	t.Setenv("KHALED_CONFIG_SOURCE", "bogus")

	err := run([]string{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected unsupported source to fail")
	}

	if !strings.Contains(err.Error(), "unsupported config source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadConfigUsesDiskPluginForInitialLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := run([]string{"--config=" + path}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestDefaultOptionsUseDocumentedFallbacks(t *testing.T) {
	opts := defaultOptions()

	if opts.configSource != "disk" {
		t.Fatalf("unexpected config source default: %q", opts.configSource)
	}

	if opts.configPath != "/etc/khaled/khaled.yaml" {
		t.Fatalf("unexpected config path default: %q", opts.configPath)
	}

	if opts.k8sConfig != "" {
		t.Fatalf("unexpected k8s config default: %q", opts.k8sConfig)
	}

	if opts.k8sNamespace != "" {
		t.Fatalf("unexpected k8s namespace default: %q", opts.k8sNamespace)
	}
}

func TestDefaultOptionsUseK8sEnvironmentFallbacks(t *testing.T) {
	t.Setenv("KHALED_K8S_CONFIG", "configmap/test-config")
	t.Setenv("KHALED_K8S_NAMESPACE", "test-namespace")

	opts := defaultOptions()

	if opts.k8sConfig != "configmap/test-config" {
		t.Fatalf("unexpected k8s config default: %q", opts.k8sConfig)
	}

	if opts.k8sNamespace != "test-namespace" {
		t.Fatalf("unexpected k8s namespace default: %q", opts.k8sNamespace)
	}
}

func TestFlagOverridesConfigSourceEnvironment(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("KHALED_CONFIG_SOURCE", "k8s")

	if err := run([]string{"--config-source=disk", "--config=" + path}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestFlagOverridesConfigEnvironment(t *testing.T) {
	envDir := t.TempDir()
	envPath := filepath.Join(envDir, "env.yaml")
	if err := os.WriteFile(envPath, []byte("{\n"), 0o600); err != nil {
		t.Fatalf("write env config: %v", err)
	}

	flagDir := t.TempDir()
	flagPath := filepath.Join(flagDir, "flag.yaml")
	if err := os.WriteFile(flagPath, []byte(validYAML), 0o600); err != nil {
		t.Fatalf("write flag config: %v", err)
	}

	t.Setenv("KHALED_CONFIG", envPath)

	if err := run([]string{"--config=" + flagPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestConfigSchemaSubcommandEmitsValidJSONSchema(t *testing.T) {
	stdout := &bytes.Buffer{}
	if err := run([]string{"config-schema"}, stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run config-schema: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("emitted schema is not valid JSON: %v", err)
	}

	props, ok := parsed["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level properties object, got %T", parsed["properties"])
	}
	for _, want := range []string{"keyStorage", "policyEngine", "policySource", "clientAuthn", "claimsMapping", "listeners", "spiffe", "logging"} {
		if _, ok := props[want]; !ok {
			t.Errorf("emitted schema missing top-level property %q", want)
		}
	}
}

func TestRunHelpPrintsUsage(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	if err := run([]string{"--help"}, stdout, stderr); err != nil {
		t.Fatalf("run help: %v", err)
	}

	if !strings.Contains(stdout.String(), "--config-source") {
		t.Fatalf("expected help output to mention --config-source, got %q", stdout.String())
	}
}

func TestRunClosesConfigSourceAfterSuccessfulCurrent(t *testing.T) {
	source := &fakeConfigSource{}
	restore := swapConfigSourceFactory(func(options, *schema.Registry) (configsource.Source, error) {
		return source, nil
	})
	defer restore()

	if err := run([]string{}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if !source.closed {
		t.Fatalf("expected config source to be closed")
	}
}

func TestRunClosesConfigSourceAfterCurrentError(t *testing.T) {
	source := &fakeConfigSource{currentErr: errors.New("boom")}
	restore := swapConfigSourceFactory(func(options, *schema.Registry) (configsource.Source, error) {
		return source, nil
	})
	defer restore()

	err := run([]string{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected run to fail")
	}

	if !source.closed {
		t.Fatalf("expected config source to be closed")
	}
}

func TestRunRejectsConfigFailingSchemaValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Missing listeners + using unknown plugin name.
	bad := `
keyStorage:
  use: nonexistent
`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"--config=" + path}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestRunAcceptsValidLoggingBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := validYAML + `
logging:
  format: text
  severity: info
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := run([]string{"--config=" + path}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatalf("run: %v", err)
	}
}

func TestRunRejectsUppercaseLoggingSeverity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := validYAML + `
logging:
  severity: WARN
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"--config=" + path}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected uppercase severity to be rejected")
	}
	if !strings.Contains(err.Error(), "/logging/severity") && !strings.Contains(err.Error(), "logging") {
		t.Fatalf("expected error to point at /logging/severity, got: %v", err)
	}
}

func TestRunRejectsUppercaseLoggingFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := validYAML + `
logging:
  format: JSON
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"--config=" + path}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected uppercase format to be rejected")
	}
}

func TestRunRejectsInvalidLogFormat(t *testing.T) {
	err := run([]string{"--log-format=JSON"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected invalid log format to fail")
	}
	if !strings.Contains(err.Error(), "log format") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRejectsInvalidLogSeverity(t *testing.T) {
	err := run([]string{"--log-severity=WARN"}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected invalid log severity to fail")
	}
	if !strings.Contains(err.Error(), "log severity") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunRejectsInvalidLogFormatFromEnv(t *testing.T) {
	t.Setenv("KHALED_LOG_FORMAT", "Text")
	err := run([]string{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected invalid env log format to fail")
	}
}

func TestConfigSchemaExposesListenerTLSShape(t *testing.T) {
	stdout := &bytes.Buffer{}
	if err := run([]string{"config-schema"}, stdout, &bytes.Buffer{}); err != nil {
		t.Fatalf("run config-schema: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("emitted schema is not valid JSON: %v", err)
	}

	listeners := parsed["properties"].(map[string]any)["listeners"].(map[string]any)
	items := listeners["items"].(map[string]any)
	variants := items["oneOf"].([]any)
	if len(variants) == 0 {
		t.Fatalf("expected at least one listener variant")
	}
	httpVariant := variants[0].(map[string]any)
	httpProps := httpVariant["properties"].(map[string]any)
	httpBlock := httpProps["http"].(map[string]any)
	tlsBlock := httpBlock["properties"].(map[string]any)["tls"].(map[string]any)
	tlsProps := tlsBlock["properties"].(map[string]any)
	if _, ok := tlsProps["keylog"]; !ok {
		t.Fatalf("expected tls.keylog in schema")
	}
	sc := tlsProps["serverCertificate"].(map[string]any)
	scProps := sc["properties"].(map[string]any)
	source := scProps["source"].(map[string]any)
	enum := source["enum"].([]any)
	got := make([]string, 0, len(enum))
	for _, v := range enum {
		got = append(got, v.(string))
	}
	want := map[string]struct{}{"file": {}, "spiffe": {}}
	if len(got) != len(want) {
		t.Fatalf("serverCertificate.source enum = %v, want %v", got, want)
	}
	for _, g := range got {
		if _, ok := want[g]; !ok {
			t.Errorf("unexpected enum value %q", g)
		}
	}
}

func TestRunRejectsListenerWithInvalidCertificateSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
keyStorage:
  use: disk
  disk:
    path: /var/lib/khaled
policyEngine:
  use: cedar
policySource:
  use: file
  file:
    path: /etc/khaled/policy.cedar
clientAuthn:
  use: tls-spiffe
claimsMapping:
  use: k8s-attestation
listeners:
  - use: http
    address: ":5000"
    http:
      tls:
        serverCertificate:
          source: bogus
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"--config=" + path}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected invalid source to be rejected")
	}
}

func TestRunRejectsConfigWithNoListeners(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	noListeners := `
keyStorage:
  use: disk
  disk:
    path: /var/lib/khaled
policyEngine:
  use: cedar
policySource:
  use: file
  file:
    path: /etc/khaled/policy.cedar
clientAuthn:
  use: tls-spiffe
claimsMapping:
  use: k8s-attestation
`
	if err := os.WriteFile(path, []byte(noListeners), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	err := run([]string{"--config=" + path}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected listeners validator error")
	}
	if !strings.Contains(err.Error(), "listeners") {
		t.Fatalf("unexpected error: %v", err)
	}
}
