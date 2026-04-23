package plugin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

const samplePolicy = `permit(principal, action, resource);`

func writePolicy(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.cedar")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestNewPolicySource_UnknownSource(t *testing.T) {
	args := plugin.PolicySourceArgs{PluginName: "bogus", EngineName: "cedar"}
	if _, err := plugin.NewPolicySource(t.Context(), args); err == nil {
		t.Fatalf("expected error for unknown source")
	}
}

func TestNewPolicySource_UnknownEngine(t *testing.T) {
	path := writePolicy(t, samplePolicy)
	args := plugin.PolicySourceArgs{PluginName: "file", EngineName: "bogus"}
	args.File.Path = path
	if _, err := plugin.NewPolicySource(t.Context(), args); err == nil {
		t.Fatalf("expected error for unknown engine")
	}
}

func TestNewPolicySource_MissingEngineName(t *testing.T) {
	path := writePolicy(t, samplePolicy)
	args := plugin.PolicySourceArgs{PluginName: "file"}
	args.File.Path = path
	if _, err := plugin.NewPolicySource(t.Context(), args); err == nil {
		t.Fatalf("expected error for missing engine name")
	}
}

func TestNewPolicySource_FileCedar(t *testing.T) {
	path := writePolicy(t, samplePolicy)
	args := plugin.PolicySourceArgs{PluginName: "file", EngineName: "cedar"}
	args.File.Path = path

	src, err := plugin.NewPolicySource(t.Context(), args)
	if err != nil {
		t.Fatalf("NewPolicySource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	eng, err := src.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	set, err := attrset.New(nil)
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}
	d, err := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p"},
		AttributeSet: set,
	})
	if err != nil {
		t.Fatalf("DecideEncapsulate: %v", err)
	}
	if !d.Allow {
		t.Errorf("expected allow from sample policy, got deny")
	}
}

func TestNewPolicySource_FileCedarInvalid(t *testing.T) {
	path := writePolicy(t, "not cedar syntax")
	args := plugin.PolicySourceArgs{PluginName: "file", EngineName: "cedar"}
	args.File.Path = path

	src, err := plugin.NewPolicySource(t.Context(), args)
	if err != nil {
		t.Fatalf("NewPolicySource: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if _, err := src.Current(); err == nil {
		t.Fatalf("expected parse error on Current()")
	}
}
