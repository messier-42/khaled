package log

import (
	"reflect"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/config/schema"
)

const auditTestClaim = "team"

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
		{"all", map[string]any{auditPrincipalClaims: []string{auditTestClaim}, "clientIP": true, "fullAttributeSet": true, "policyHashes": true, "diagnostics": true}, true},
		{"not object", true, false},
		{"not boolean", map[string]any{"clientIP": "true"}, false},
		{"claims not array", map[string]any{auditPrincipalClaims: true}, false},
		{"claims not string", map[string]any{auditPrincipalClaims: []any{true}}, false},
		{"empty claim name", map[string]any{auditPrincipalClaims: []string{""}}, false},
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
			if tc.name == "all" && !reflect.DeepEqual(cfg, AuditConfig{PrincipalClaims: []string{auditTestClaim}, ClientIP: true, FullAttributeSet: true, PolicyHashes: true, Diagnostics: true}) {
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
		if got := AuditValue(name, "secret"); got != auditRedacted {
			t.Errorf("%s: %v", name, got)
		}
	}
	got := AuditValue("metadata", []any{map[string]any{"password": "secret", auditTestClaim: "blue"}, []byte("secret"), secretMarshaler{}, cyclic}).([]any)
	want := []any{map[string]any{"password": auditRedacted, auditTestClaim: "blue"}, auditRedacted, auditRedacted}
	if !reflect.DeepEqual(got[:3], want) {
		t.Fatal(got)
	}
}

// A metadata value must not invoke custom JSON conversion during auditing.
type secretMarshaler struct{}

func (secretMarshaler) MarshalJSON() ([]byte, error) { return []byte(`"marshaler-secret"`), nil }
