package server

import (
	"context"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
)

const (
	pathKey              = "path"
	testStoragePath      = "/tmp"
	diskPlugin           = "disk"
	filePlugin           = "file"
	k8sAttestationPlugin = "k8s-attestation"
	pluginSelector       = "use"
)

// TestKeyStorageRuntimeKnobsValidate ensures the new domainName /
// rootRotationInterval / leaseDuration common knobs accept valid
// values and reject the wrong type.
func TestKeyStorageRuntimeKnobsValidate(t *testing.T) {
	registry, err := BuildRegistry()
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	base := func() map[string]any {
		return map[string]any{
			"policyEngine":  map[string]any{pluginSelector: "cedar"},
			"policySource":  map[string]any{pluginSelector: filePlugin, filePlugin: map[string]any{pathKey: "/tmp/x"}},
			"clientAuthn":   map[string]any{pluginSelector: "tls-spiffe"},
			"claimsMapping": map[string]any{pluginSelector: k8sAttestationPlugin},
			"listeners":     []any{map[string]any{pluginSelector: "http", "address": ":0"}},
		}
	}

	good := base()
	good["keyStorage"] = map[string]any{
		pluginSelector:         diskPlugin,
		diskPlugin:             map[string]any{pathKey: testStoragePath},
		"domainName":           "prod",
		"rootRotationInterval": "12h",
		"leaseDuration":        "90s",
	}
	snap, err := config.NewSnapshot(good)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := registry.Validate(context.Background(), nil, snap); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}

	bad := base()
	bad["keyStorage"] = map[string]any{
		pluginSelector:  diskPlugin,
		diskPlugin:      map[string]any{pathKey: testStoragePath},
		"leaseDuration": 42, // must be a string
	}
	snap, err = config.NewSnapshot(bad)
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if err := registry.Validate(context.Background(), nil, snap); err == nil {
		t.Fatal("expected validation error for non-string leaseDuration")
	}
}

// TestK8sAttestationCacheSchema ensures the cache fields accept valid
// shapes and reject obvious mistyping.
func TestK8sAttestationCacheSchema(t *testing.T) {
	registry, err := BuildRegistry()
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	base := func() map[string]any {
		return map[string]any{
			"keyStorage":   map[string]any{pluginSelector: diskPlugin, diskPlugin: map[string]any{pathKey: testStoragePath}},
			"policyEngine": map[string]any{pluginSelector: "cedar"},
			"policySource": map[string]any{pluginSelector: filePlugin, filePlugin: map[string]any{pathKey: "/tmp/x"}},
			"clientAuthn":  map[string]any{pluginSelector: "tls-spiffe"},
			"listeners":    []any{map[string]any{pluginSelector: "http", "address": ":0"}},
		}
	}

	good := base()
	good["claimsMapping"] = map[string]any{
		pluginSelector: k8sAttestationPlugin,
		k8sAttestationPlugin: map[string]any{
			"cache": map[string]any{
				"ttl":         "30s",
				"negativeTTL": "5s",
				"maxEntries":  int64(4096),
			},
		},
	}
	snap, _ := config.NewSnapshot(good)
	if err := registry.Validate(context.Background(), nil, snap); err != nil {
		t.Fatalf("valid cache config rejected: %v", err)
	}

	bad := base()
	bad["claimsMapping"] = map[string]any{
		pluginSelector: k8sAttestationPlugin,
		k8sAttestationPlugin: map[string]any{
			"cache": map[string]any{
				"ttl": 30, // must be a string duration
			},
		},
	}
	snap, _ = config.NewSnapshot(bad)
	if err := registry.Validate(context.Background(), nil, snap); err == nil {
		t.Fatal("expected validation error for non-string ttl")
	}
}
