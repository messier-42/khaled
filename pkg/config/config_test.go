package config_test

import (
	"testing"

	"github.com/messier-42/khaled/pkg/config"
)

const (
	customPlugin   = "custom"
	pluginSelector = "use"
)

func TestObjectPreservesUnknownPluginSections(t *testing.T) {
	cfg := config.Map{
		"keyStorage": config.Map{
			pluginSelector: "disk",
			"disk": config.Map{
				"path": "/var/lib/khaled/keys",
			},
		},
		"futurePlugin": config.Map{
			pluginSelector: customPlugin,
			customPlugin: config.Map{
				"flag":  true,
				"ports": config.Array{9000, 9001},
			},
		},
	}

	futurePlugin, ok := cfg.GetMap("futurePlugin")
	if !ok {
		t.Fatalf("expected futurePlugin object to be present")
	}

	if got, ok := futurePlugin.GetString(pluginSelector); !ok || got != customPlugin {
		t.Fatalf("unexpected plugin selector: got %q, ok=%v", got, ok)
	}

	custom, ok := futurePlugin.GetMap(customPlugin)
	if !ok {
		t.Fatalf("expected custom subsection to be preserved")
	}

	if got, ok := custom.GetBool("flag"); !ok || !got {
		t.Fatalf("unexpected flag value: got %v, ok=%v", got, ok)
	}

	ports, ok := custom.GetArray("ports")
	if !ok {
		t.Fatalf("expected ports list to be preserved")
	}

	port0, ok := ports.Index(0)
	if !ok {
		t.Fatalf("expected first port to be available as int64")
	}

	port1, ok := ports.Index(1)
	if !ok {
		t.Fatalf("expected second port to be available as int64")
	}

	if len(ports) != 2 || port0 != 9000 || port1 != 9001 {
		t.Fatalf("unexpected ports list: %#v", ports)
	}
}

func TestObjectAccessorsRejectWrongTypes(t *testing.T) {
	cfg := config.Map{
		"listeners": config.Array{
			config.Map{pluginSelector: "http"},
		},
		"spiffe": "unix:///tmp/socket",
	}

	if _, ok := cfg.GetMap("listeners"); ok {
		t.Fatalf("expected listeners not to decode as object")
	}

	if _, ok := cfg.GetArray("spiffe"); ok {
		t.Fatalf("expected spiffe not to decode as list")
	}
}
