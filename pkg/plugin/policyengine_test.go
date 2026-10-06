package plugin_test

import (
	"context"
	"testing"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

func TestNewPolicyEngine_UnknownPlugin(t *testing.T) {
	if _, err := plugin.NewPolicyEngine(plugin.PolicyEngineArgs{PluginName: unknownPlugin}); err == nil {
		t.Fatalf("expected error for unknown plugin")
	}
}

func TestNewPolicyEngine_Cedar(t *testing.T) {
	args := plugin.PolicyEngineArgs{PluginName: cedarEngine}
	args.Cedar.PolicyText = []byte(`permit(principal, action, resource);`)

	eng, err := plugin.NewPolicyEngine(args)
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}
	t.Cleanup(func() { _ = eng.Close() })

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
		t.Errorf("expected allow, got deny")
	}
}

func TestNewPolicyEngine_CedarBadPolicy(t *testing.T) {
	args := plugin.PolicyEngineArgs{PluginName: cedarEngine}
	args.Cedar.PolicyText = []byte(`not cedar`)
	if _, err := plugin.NewPolicyEngine(args); err == nil {
		t.Fatalf("expected parse error")
	}
}
