package server

import (
	"context"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
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
			"policyEngine":  map[string]any{"use": "cedar"},
			"policySource":  map[string]any{"use": "file", "file": map[string]any{"path": "/tmp/x"}},
			"clientAuthn":   map[string]any{"use": "tls-spiffe"},
			"claimsMapping": map[string]any{"use": "k8s-attestation"},
			"listeners":     []any{map[string]any{"use": "http", "address": ":0"}},
		}
	}

	good := base()
	good["keyStorage"] = map[string]any{
		"use":                  "disk",
		"disk":                 map[string]any{"path": "/tmp"},
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
		"use":           "disk",
		"disk":          map[string]any{"path": "/tmp"},
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
			"keyStorage":   map[string]any{"use": "disk", "disk": map[string]any{"path": "/tmp"}},
			"policyEngine": map[string]any{"use": "cedar"},
			"policySource": map[string]any{"use": "file", "file": map[string]any{"path": "/tmp/x"}},
			"clientAuthn":  map[string]any{"use": "tls-spiffe"},
			"listeners":    []any{map[string]any{"use": "http", "address": ":0"}},
		}
	}

	good := base()
	good["claimsMapping"] = map[string]any{
		"use": "k8s-attestation",
		"k8s-attestation": map[string]any{
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
		"use": "k8s-attestation",
		"k8s-attestation": map[string]any{
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
