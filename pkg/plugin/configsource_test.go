package plugin_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/messier-42/khaled/pkg/plugin"
)

func TestNewConfigSourceCreatesDiskSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("policyEngine:\n  use: cedar\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	args := plugin.ConfigSourceArgs{
		PluginName: "disk",
	}
	args.Disk.Path = path

	source, err := plugin.NewConfigSource(args)
	if err != nil {
		t.Fatalf("new config source: %v", err)
	}

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current: %v", err)
	}

	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}

	if got, ok := policyEngine.GetString("use"); !ok || got != "cedar" {
		t.Fatalf("unexpected policyEngine.use: got %q, ok=%v", got, ok)
	}
}

func TestNewConfigSourceRejectsUnsupportedPlugin(t *testing.T) {
	_, err := plugin.NewConfigSource(plugin.ConfigSourceArgs{PluginName: "bogus"})
	if err == nil {
		t.Fatalf("expected unsupported plugin to fail")
	}

	if !strings.Contains(err.Error(), "unsupported config source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestConfigSourceArgsExposeK8sFields(t *testing.T) {
	args := plugin.ConfigSourceArgs{
		PluginName: "k8s",
	}
	args.K8s.Config = "configmap/test-config"
	args.K8s.Namespace = "test-namespace"

	if args.K8s.Config != "configmap/test-config" {
		t.Fatalf("unexpected k8s config arg: %q", args.K8s.Config)
	}

	if args.K8s.Namespace != "test-namespace" {
		t.Fatalf("unexpected k8s namespace arg: %q", args.K8s.Namespace)
	}
}
