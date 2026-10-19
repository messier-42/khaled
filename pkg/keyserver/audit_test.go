package keyserver_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/keyserver"
	klog "github.com/messier-42/khaled/pkg/log"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

const (
	auditOperationPrograde   = "Prograde"
	auditDecisionDeny        = "deny"
	auditOutcomeDenied       = "denied"
	auditAttributeName       = "classification"
	auditOperationRetrograde = "Retrograde"
	auditDecisionAllow       = "allow"
	auditOutcomeSuccess      = "success"
	auditAttributeValue      = "restricted"
	auditClaimTeam           = "team"
)

func captureAudit(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(klog.New(&buf, klog.Config{Format: klog.FormatJSON, Severity: slog.LevelInfo}))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func auditRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var record map[string]any
	if err := json.Unmarshal(buf.Bytes(), &record); err != nil {
		t.Fatalf("want exactly one JSON record: %v; got %s", err, buf.String())
	}
	if record["event"] != "key_access" || record["level"] != "INFO" {
		t.Fatalf("not an INFO audit event: %v", record)
	}
	if _, err := time.Parse(time.RFC3339Nano, record["time"].(string)); err != nil {
		t.Fatal(err)
	}
	return record
}

func digestForTest(s string) string {
	d := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(d[:])
}

func TestKeyAccessAudit(t *testing.T) {
	for _, tc := range []struct {
		operation, decision, outcome string
		captive                      bool
	}{
		{auditOperationPrograde, auditDecisionAllow, auditOutcomeSuccess, false},
		{auditOperationPrograde, auditDecisionDeny, auditOutcomeDenied, false},
		{auditOperationRetrograde, auditDecisionAllow, auditOutcomeSuccess, true},
		{auditOperationRetrograde, auditDecisionDeny, auditOutcomeDenied, true},
	} {
		t.Run(tc.operation+"/"+tc.outcome, func(t *testing.T) {
			f := newFixture(t)
			as := mustSet(t, map[string]any{auditAttributeName: auditAttributeValue, "project": "audit"})
			var ref []byte
			if tc.operation == auditOperationRetrograde {
				seed, err := f.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: f.principal, AttributeSet: as})
				if err != nil {
					t.Fatal(err)
				}
				ref = seed.Lease.LeaseRef
			}
			allow := tc.decision == auditDecisionAllow
			d := policyengine.Decision{Allow: allow, RequireCaptive: tc.captive, Reason: "sensitive reason", DeterminingPolicies: []string{"sensitive-policy"}, Diagnostics: []string{"sensitive diagnostic"}}
			f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) { return d, nil }
			f.engine.decap = func(policyengine.DecapsulateRequest) (policyengine.Decision, error) { return d, nil }
			f.principal.Claims = map[string]any{auditClaimTeam: "sensitive claim"}
			buf := captureAudit(t)
			ctx := klog.WithCorrelationID(t.Context(), "correlation-1")
			ctx = klog.WithClientIP(ctx, netip.MustParseAddr("192.0.2.1"))
			var lease keyserver.Lease
			var err error
			if tc.operation == auditOperationPrograde {
				resp, e := f.srv.Prograde(ctx, keyserver.ProgradeRequest{Principal: f.principal, AttributeSet: as, ARINToken: []byte("arin-secret")})
				lease, err = resp.Lease, e
			} else {
				resp, e := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{Principal: f.principal, AttributeSet: as, LeaseRef: ref})
				lease, err = resp.Lease, e
			}
			if (allow && err != nil) || (!allow && !errors.Is(err, keyserver.ErrDenied)) {
				t.Fatalf("unexpected operation result: %v", err)
			}
			r := auditRecord(t, buf)
			want := map[string]any{
				"operation": tc.operation, "policyDecision": tc.decision, "outcome": tc.outcome,
				"principalURI": f.principal.URI, "correlationID": "correlation-1",
				"attributeSetDigest":     digestForTest(string(as.Repr())),
				"determiningPolicyCount": float64(1), "requireCaptive": tc.captive,
			}
			for field, value := range want {
				if r[field] != value {
					t.Errorf("%s = %v, want %v", field, r[field], value)
				}
			}
			if allow {
				if r["leaseExpiry"] != lease.Expiry.UTC().Format(time.RFC3339Nano) {
					t.Errorf("wrong expiry: %v", r)
				}
			} else if _, ok := r["leaseExpiry"]; ok {
				t.Error("denial has expiry")
			}
			for _, field := range []string{"principalClaims", "clientIP", "attributeSet", "determiningPolicyHashes", "diagnosticCount", "diagnosticHashes", "reasonHash"} {
				if _, ok := r[field]; ok {
					t.Errorf("default exposes %s", field)
				}
			}
			secrets := []string{auditAttributeValue, "sensitive", "arin-secret", "192.0.2.1"}
			if len(ref) > 0 {
				secrets = append(secrets, base64.StdEncoding.EncodeToString(ref))
			}
			if lease.LKAI.NonCaptive != nil {
				key := lease.LKAI.NonCaptive.LeaseKey[-1].([]byte)
				secrets = append(secrets, base64.StdEncoding.EncodeToString(key), hex.EncodeToString(key))
			}
			for _, secret := range secrets {
				if strings.Contains(buf.String(), secret) {
					t.Errorf("secret leaked: %q", secret)
				}
			}
		})
	}
}

func TestAuditOptionalDetailsAndRedaction(t *testing.T) {
	const (
		credential = "credential-secret"
		tokenClaim = "authToken"
		policyA    = "policy-a"
		policyB    = "policy-b"
	)
	f := newFixture(t)
	cfg := klog.AuditConfig{PrincipalClaims: []string{auditClaimTeam, tokenClaim}, ClientIP: true, FullAttributeSet: true, PolicyHashes: true, Diagnostics: true}
	f.srv.SetAuditConfig(cfg)
	cfg.PrincipalClaims[0] = "unlisted" // Server must own its allowlist.
	f.principal.Claims = map[string]any{auditClaimTeam: "blue", "unlisted": "omit-me", tokenClaim: credential}
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, DeterminingPolicies: []string{policyB, policyA, policyA}, Reason: credential, Diagnostics: []string{"token-secret"}}, nil
	}
	buf := captureAudit(t)
	ctx := klog.WithClientIP(t.Context(), netip.MustParseAddr("2001:db8::1"))
	as := mustSet(t, map[string]any{auditAttributeName: auditAttributeValue, "credentials": "attribute-secret"})
	if _, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{Principal: f.principal, AttributeSet: as, ARINToken: []byte("arin-secret")}); err != nil {
		t.Fatal(err)
	}
	r := auditRecord(t, buf)
	want := map[string]any{
		"clientIP":                "2001:db8::1",
		"principalClaims":         map[string]any{auditClaimTeam: "blue", tokenClaim: "[REDACTED]"},
		"attributeSet":            map[string]any{auditAttributeName: auditAttributeValue, "credentials": "[REDACTED]"},
		"determiningPolicyHashes": []any{digestForTest(policyB), digestForTest(policyA)},
		"diagnosticCount":         float64(1), "diagnosticHashes": []any{digestForTest("token-secret")},
		"reasonHash": digestForTest(credential),
	}
	for field, value := range want {
		if !reflect.DeepEqual(r[field], value) {
			t.Errorf("%s = %v, want %v", field, r[field], value)
		}
	}
	for _, secret := range []string{"omit-me", credential, "attribute-secret", "arin-secret", "token-secret", policyA, policyB} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("leaked %q", secret)
		}
	}
}

func TestAuditErrorsDoNotLookSuccessful(t *testing.T) {
	for _, tc := range []struct{ name, policyDecision string }{
		{"policy", "unavailable"},
		{"invalidRef", "unavailable"},
		{"after authorization", auditDecisionAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			buf := captureAudit(t)
			var err error
			switch tc.name {
			case "policy":
				f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
					return policyengine.Decision{Allow: true}, errors.New("error-secret")
				}
				_, err = f.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: f.principal})
			case "invalidRef":
				_, err = f.srv.Retrograde(t.Context(), keyserver.RetrogradeRequest{Principal: f.principal, LeaseRef: []byte("ref-secret")})
			case "after authorization":
				srv, e := keyserver.New(keyserver.Config{DomainName: "test", Schedule: f.sched, Policy: f.engine, RefWrapper: stubWrapper{}})
				if e != nil {
					t.Fatal(e)
				}
				_, err = srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: f.principal})
			}
			if err == nil {
				t.Fatal("expected error")
			}
			r := auditRecord(t, buf)
			if r["outcome"] != "error" || r["policyDecision"] != tc.policyDecision {
				t.Fatalf("misleading result: %v", r)
			}
			if _, ok := r["leaseExpiry"]; ok {
				t.Fatal("failed operation has expiry")
			}
			if strings.Contains(buf.String(), "secret") {
				t.Fatal("error/ref text leaked")
			}
		})
	}
}
