package keyserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	klog "github.com/messier-42/khaled/pkg/log"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// SetAuditConfig applies detail changes to subsequent requests without
// rebuilding the key storage stack. In-flight requests retain their settings.
func (s *Server) SetAuditConfig(cfg klog.AuditConfig) {
	cfg.PrincipalClaims = slices.Clone(cfg.PrincipalClaims)
	s.audit.Store(&cfg)
}

// accessAudit holds only decision metadata, never request/response key material.
type accessAudit struct {
	config   *klog.AuditConfig
	decision *policyengine.Decision
}

func (a *accessAudit) decided(d policyengine.Decision, err error) {
	if err == nil {
		a.decision = &d
	}
}

func (s *Server) auditAccess(ctx context.Context, a accessAudit, op string, principal policyengine.Principal, as attrset.Set, expiry time.Time, err error) {
	if !slog.Default().Enabled(ctx, slog.LevelInfo) {
		return
	}
	outcome := "error"
	if errors.Is(err, ErrDenied) {
		outcome = "denied"
	} else if err == nil && !expiry.IsZero() {
		outcome = "success"
	}
	verdict := "unavailable"
	attrs := []slog.Attr{
		slog.String("event", "key_access"),
		slog.String("operation", op),
		slog.String("outcome", outcome),
		slog.String("domainName", s.domainName),
		slog.String("attributeSetDigest", auditDigest(string(as.Repr()))),
	}
	if principal.URI != "" {
		attrs = append(attrs, slog.String("principalURI", principal.URI))
	}
	if d := a.decision; d != nil {
		verdict = "deny"
		if d.Allow {
			verdict = "allow"
		}
		attrs = append(attrs, slog.Int("determiningPolicyCount", len(d.DeterminingPolicies)), slog.Bool("requireCaptive", d.RequireCaptive))
		if a.config.PolicyHashes {
			attrs = append(attrs, slog.Any("determiningPolicyHashes", auditDigests(d.DeterminingPolicies)))
		}
		if a.config.Diagnostics {
			attrs = append(attrs, slog.Int("diagnosticCount", len(d.Diagnostics)), slog.Any("diagnosticHashes", auditDigests(d.Diagnostics)))
			if d.Reason != "" {
				attrs = append(attrs, slog.String("reasonHash", auditDigest(d.Reason)))
			}
		}
	}
	attrs = append(attrs, slog.String("policyDecision", verdict))
	if outcome == "success" {
		attrs = append(attrs, slog.Time("leaseExpiry", expiry.UTC()))
	}
	if a.config.ClientIP {
		if ip, ok := klog.ClientIP(ctx); ok {
			attrs = append(attrs, slog.String("clientIP", ip.String()))
		}
	}
	if len(a.config.PrincipalClaims) > 0 {
		claims := make(map[string]any)
		for _, name := range a.config.PrincipalClaims {
			if v, ok := principal.Claims[name]; ok {
				claims[name] = klog.AuditValue(name, v)
			}
		}
		attrs = append(attrs, slog.Any("principalClaims", claims))
	}
	if a.config.FullAttributeSet {
		values := make(map[string]any, as.Len())
		as.Range(func(k string, v any) bool { values[k] = klog.AuditValue(k, v); return true })
		attrs = append(attrs, slog.Any("attributeSet", values))
	}
	// The existing context handler supplies correlationID/requestID, and slog
	// supplies the event timestamp. Do not log errors or whole request/lease objects.
	slog.LogAttrs(ctx, slog.LevelInfo, "key-access decision", attrs...)
}

func auditDigest(s string) string {
	digest := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func auditDigests(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, auditDigest(value))
	}
	slices.Sort(out)
	return slices.Compact(out)
}
