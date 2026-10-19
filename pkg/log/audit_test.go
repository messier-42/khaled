package log

import (
	"reflect"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/config/schema"
)

func TestAuditConfiguration(t *testing.T) {
	r := schema.New()
	if err := RegisterSchema(r); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Build(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		audit any
		valid bool
	}{
		{"empty", map[string]any{}, true},
		{"all", map[string]any{"principalClaims": []string{"team"}, "clientIP": true, "fullAttributeSet": true, "policyHashes": true, "diagnostics": true}, true},
		{"not object", true, false},
		{"not boolean", map[string]any{"clientIP": "true"}, false},
		{"claims not array", map[string]any{"principalClaims": true}, false},
		{"claims not string", map[string]any{"principalClaims": []any{true}}, false},
		{"empty claim name", map[string]any{"principalClaims": []string{""}}, false},
		{"unknown option", map[string]any{"claims": true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snap, err := config.NewSnapshot(map[string]any{"logging": map[string]any{"audit": tc.audit}})
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Validate(t.Context(), nil, snap); (err == nil) != tc.valid {
				t.Fatalf("schema validity: %v", err)
			}
			cfg, err := AuditConfigFromSnapshot(snap)
			if (err == nil) != tc.valid {
				t.Fatalf("parser validity: %v", err)
			}
			if tc.name == "all" && !reflect.DeepEqual(cfg, AuditConfig{PrincipalClaims: []string{"team"}, ClientIP: true, FullAttributeSet: true, PolicyHashes: true, Diagnostics: true}) {
				t.Fatal(cfg)
			}
		})
	}
	cfg, err := AuditConfigFromSnapshot(config.Snapshot{})
	if err != nil || !reflect.DeepEqual(cfg, AuditConfig{}) {
		t.Fatalf("wrong defaults: %v %v", cfg, err)
	}
}

func TestAuditValueNestedSecrets(t *testing.T) {
	cyclic := map[string]any{}
	cyclic["self"] = cyclic
	for _, name := range []string{"access_token", "client-secret", "Private.Key", "CEK", "plaintext", "Authorization", "sessionCookie", "LKAT", "credentials"} {
		if got := AuditValue(name, "secret"); got != "[REDACTED]" {
			t.Errorf("%s: %v", name, got)
		}
	}
	got := AuditValue("metadata", []any{map[string]any{"password": "secret", "team": "blue"}, []byte("secret"), cyclic}).([]any)
	if got[0].(map[string]any)["password"] != "[REDACTED]" || got[0].(map[string]any)["team"] != "blue" || got[1] != "[REDACTED]" {
		t.Fatal(got)
	}
}
