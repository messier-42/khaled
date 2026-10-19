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
	"strings"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/khaled/pkg/federation"
	"github.com/messier-42/khaled/pkg/keyserver"
	klog "github.com/messier-42/khaled/pkg/log"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
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
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly one record, got %s", buf.String())
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
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
	for _, op := range []string{"Prograde", "Retrograde"} {
		for _, allow := range []bool{false, true} {
			for _, captive := range []bool{false, true} {
				t.Run(op+"/"+map[bool]string{true: "allow", false: "deny"}[allow]+"/"+map[bool]string{true: "captive", false: "noncaptive"}[captive], func(t *testing.T) {
					f := newFixture(t)
					as := mustSet(t, map[string]any{"classification": "restricted"})
					seed, err := f.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: f.principal, AttributeSet: as})
					if err != nil {
						t.Fatal(err)
					}
					d := policyengine.Decision{Allow: allow, RequireCaptive: captive, Reason: "sensitive reason", DeterminingPolicies: []string{"sensitive-policy"}, Diagnostics: []string{"sensitive diagnostic"}}
					f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) { return d, nil }
					f.engine.decap = func(policyengine.DecapsulateRequest) (policyengine.Decision, error) { return d, nil }
					f.principal.Claims = map[string]any{"team": "sensitive claim"}
					buf := captureAudit(t)
					ctx := klog.WithCorrelationID(t.Context(), "correlation-1")
					ctx = klog.WithClientIP(ctx, netip.MustParseAddr("192.0.2.1"))
					var lease keyserver.Lease
					if op == "Prograde" {
						resp, e := f.srv.Prograde(ctx, keyserver.ProgradeRequest{Principal: f.principal, AttributeSet: as, ARINToken: []byte("arin-secret")})
						lease, err = resp.Lease, e
					} else {
						resp, e := f.srv.Retrograde(ctx, keyserver.RetrogradeRequest{Principal: f.principal, AttributeSet: as, LeaseRef: seed.Lease.LeaseRef})
						lease, err = resp.Lease, e
					}
					if allow && err != nil {
						t.Fatal(err)
					}
					if !allow && err != keyserver.ErrDenied {
						t.Fatalf("denial changed: %v", err)
					}
					r := auditRecord(t, buf)
					want := map[string]any{"operation": op, "policyDecision": map[bool]string{true: "allow", false: "deny"}[allow], "outcome": map[bool]string{true: "success", false: "denied"}[allow], "principalURI": f.principal.URI, "correlationID": "correlation-1", "attributeSetDigest": digestForTest(string(as.Repr())), "determiningPolicyCount": float64(1)}
					for k, v := range want {
						if r[k] != v {
							t.Errorf("%s = %v, want %v", k, r[k], v)
						}
					}
					if allow {
						if r["leaseExpiry"] != lease.Expiry.UTC().Format(time.RFC3339Nano) {
							t.Errorf("wrong expiry: %v", r)
						}
					} else if _, ok := r["leaseExpiry"]; ok {
						t.Error("denial has expiry")
					}
					for _, field := range []string{"principalClaims", "clientIP", "attributeSet", "determiningPolicyHashes", "diagnosticCount", "reasonHash"} {
						if _, ok := r[field]; ok {
							t.Errorf("default exposes %s", field)
						}
					}
					for _, secret := range []string{"restricted", "sensitive", "arin-secret", "192.0.2.1", base64.StdEncoding.EncodeToString(seed.Lease.LeaseRef)} {
						if strings.Contains(buf.String(), secret) {
							t.Errorf("secret leaked: %q", secret)
						}
					}
					if lease.LKAI.NonCaptive != nil {
						key := lease.LKAI.NonCaptive.LeaseKey[-1].([]byte)
						if strings.Contains(buf.String(), base64.StdEncoding.EncodeToString(key)) || strings.Contains(buf.String(), hex.EncodeToString(key)) {
							t.Error("lease key leaked")
						}
					}
				})
			}
		}
	}
}

func TestAuditOptionalDetailsAndRedaction(t *testing.T) {
	f := newFixture(t)
	cfg := klog.AuditConfig{PrincipalClaims: []string{"team", "nested", "authToken", "binary", "custom"}, ClientIP: true, FullAttributeSet: true, PolicyHashes: true, Diagnostics: true}
	f.srv.SetAuditConfig(cfg)
	cfg.PrincipalClaims[0] = "unlisted" // Server must own its allowlist.
	f.principal.Claims = map[string]any{"team": "blue", "unlisted": "omit-me", "authToken": "credential-secret", "nested": map[string]any{"password": "nested-secret", "region": "west"}, "binary": []byte("key-secret"), "custom": secretMarshaler{}}
	f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, DeterminingPolicies: []string{"policy-b", "policy-a", "policy-a"}, Reason: "credential-secret", Diagnostics: []string{"token-secret"}}, nil
	}
	buf := captureAudit(t)
	ctx := klog.WithClientIP(t.Context(), netip.MustParseAddr("2001:db8::1"))
	as := mustSet(t, map[string]any{"classification": "restricted", "credentials": "attribute-secret", "payload": []byte("byte-secret")})
	_, err := f.srv.Prograde(ctx, keyserver.ProgradeRequest{Principal: f.principal, AttributeSet: as, ARINToken: []byte("arin-secret")})
	if err != nil {
		t.Fatal(err)
	}
	r := auditRecord(t, buf)
	if r["clientIP"] != "2001:db8::1" || r["diagnosticCount"] != float64(1) || r["reasonHash"] != digestForTest("credential-secret") {
		t.Fatalf("missing options: %v", r)
	}
	claims := r["principalClaims"].(map[string]any)
	if claims["team"] != "blue" || claims["authToken"] != "[REDACTED]" {
		t.Fatalf("bad claims: %v", claims)
	}
	attributes := r["attributeSet"].(map[string]any)
	if attributes["classification"] != "restricted" || attributes["credentials"] != "[REDACTED]" {
		t.Fatalf("bad attributes: %v", attributes)
	}
	if len(r["determiningPolicyHashes"].([]any)) != 2 {
		t.Fatal("policy hashes not deduplicated")
	}
	for _, secret := range []string{"omit-me", "credential-secret", "nested-secret", "key-secret", "attribute-secret", "byte-secret", "arin-secret", "token-secret", "policy-a", "policy-b", "marshaler-secret"} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("leaked %q", secret)
		}
	}
	f.srv.SetAuditConfig(klog.AuditConfig{})
	buf.Reset()
	if _, err = f.srv.Prograde(ctx, keyserver.ProgradeRequest{Principal: f.principal, AttributeSet: as}); err != nil {
		t.Fatal(err)
	}
	r = auditRecord(t, buf)
	if _, ok := r["principalClaims"]; ok {
		t.Fatal("detail remained enabled after reset")
	}
}

type secretMarshaler struct{}

func (secretMarshaler) MarshalJSON() ([]byte, error) { return []byte(`"marshaler-secret"`), nil }

func TestAuditErrorsDoNotLookSuccessful(t *testing.T) {
	for _, mode := range []string{"policy", "invalidRef", "afterAllow"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			buf := captureAudit(t)
			var err error
			switch mode {
			case "policy":
				f.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
					return policyengine.Decision{Allow: true}, errors.New("error-secret")
				}
				_, err = f.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: f.principal})
			case "invalidRef":
				_, err = f.srv.Retrograde(t.Context(), keyserver.RetrogradeRequest{Principal: f.principal, LeaseRef: []byte("ref-secret")})
			case "afterAllow":
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
			want := "unavailable"
			if mode == "afterAllow" {
				want = "allow"
			}
			if r["outcome"] != "error" || r["policyDecision"] != want {
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

func TestForeignRetrogradeAuditDenial(t *testing.T) {
	f := newFixture(t)
	runtime, err := federation.New(t.Context(), f.domain.(keystorage.FederationDomain), federation.Config{DomainID: testTargetDomain})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.SetFederation(runtime); err != nil {
		t.Fatal(err)
	}
	for _, d := range []policyengine.Decision{{Allow: false}, {Allow: true, RequireCaptive: true}, {Allow: true, Diagnostics: []string{"sensitive diagnostic"}}} {
		f.engine.decap = func(policyengine.DecapsulateRequest) (policyengine.Decision, error) { return d, nil }
		buf := captureAudit(t)
		_, err := f.srv.Retrograde(t.Context(), keyserver.RetrogradeRequest{Principal: f.principal, Federation: &ckap.RetrogradeFederation{OriginDomain: testOriginDomain}})
		if err != keyserver.ErrDenied {
			t.Fatal(err)
		}
		r := auditRecord(t, buf)
		if r["outcome"] != "denied" || r["operation"] != "Retrograde" {
			t.Fatal(r)
		}
		if d.Allow && r["policyDecision"] != "allow" {
			t.Fatal("policy verdict lost")
		}
	}
}

func TestAuditRespectsLoggingSeverity(t *testing.T) {
	f := newFixture(t)
	buf := captureAudit(t)
	for _, level := range []slog.Level{slog.LevelWarn, slog.LevelError} {
		slog.SetDefault(klog.New(buf, klog.Config{Format: klog.FormatJSON, Severity: level}))
		if _, err := f.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: f.principal}); err != nil {
			t.Fatal(err)
		}
		if buf.Len() != 0 {
			t.Fatalf("audit bypassed severity %v: %s", level, buf.String())
		}
	}
}

func TestAttributeSetAuditDigestCanonical(t *testing.T) {
	f := newFixture(t)
	buf := captureAudit(t)
	var previous any
	for _, data := range []map[string]any{{"a": "one", "z": "two"}, {"z": "two", "a": "one"}} {
		as := mustSet(t, data)
		if _, err := f.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: f.principal, AttributeSet: as}); err != nil {
			t.Fatal(err)
		}
		r := auditRecord(t, buf)
		if previous != nil && r["attributeSetDigest"] != previous {
			t.Fatal("noncanonical digest")
		}
		previous = r["attributeSetDigest"]
		buf.Reset()
	}
}
