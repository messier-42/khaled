package log

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/messier-42/khaled/pkg/config"
)

const (
	auditRedacted        = "[REDACTED]"
	auditPrincipalClaims = "principalClaims"
)

// AuditConfig selects optional key-access audit fields. The zero value emits
// only the baseline fields. PrincipalClaims is an allowlist of claim names.
type AuditConfig struct {
	PrincipalClaims  []string
	ClientIP         bool
	FullAttributeSet bool
	PolicyHashes     bool
	Diagnostics      bool
}

// AuditConfigFromSnapshot reads logging.audit. Schema validation normally runs
// first; type checks here also protect direct subsystem callers.
func AuditConfigFromSnapshot(snap config.Snapshot) (AuditConfig, error) {
	var cfg AuditConfig
	logging, _ := snap.Root.GetMap("logging")
	raw, present := logging.Get("audit")
	if !present {
		return cfg, nil
	}
	block, ok := raw.(config.Map)
	if !ok {
		return cfg, errors.New("logging.audit must be an object")
	}
	for name, value := range block {
		var dest *bool
		switch name {
		case auditPrincipalClaims:
			list, ok := value.(config.Array)
			if !ok {
				return cfg, errors.New("logging.audit.principalClaims must be an array of strings")
			}
			for _, item := range list {
				name, ok := item.(string)
				if !ok || name == "" {
					return cfg, errors.New("logging.audit.principalClaims must contain non-empty strings")
				}
				cfg.PrincipalClaims = append(cfg.PrincipalClaims, name)
			}
			continue
		case "clientIP":
			dest = &cfg.ClientIP
		case "fullAttributeSet":
			dest = &cfg.FullAttributeSet
		case "policyHashes":
			dest = &cfg.PolicyHashes
		case "diagnostics":
			dest = &cfg.Diagnostics
		default:
			return cfg, fmt.Errorf("unknown logging.audit option %q", name)
		}
		flag, ok := value.(bool)
		if !ok {
			return cfg, fmt.Errorf("logging.audit.%s must be a boolean", name)
		}
		*dest = flag
	}
	return cfg, nil
}

type clientIPKey struct{}

// WithClientIP carries a transport-observed peer address without adding it to
// ordinary log attributes. Forwarded headers must not be passed here.
func WithClientIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIP returns the transport-observed peer address, when available.
func ClientIP(ctx context.Context) (netip.Addr, bool) {
	ip, ok := ctx.Value(clientIPKey{}).(netip.Addr)
	return ip, ok && ip.IsValid()
}

// AuditValue copies JSON-compatible metadata without invoking arbitrary
// Stringer, LogValuer or marshaler methods. Reserved secret-bearing names,
// byte strings, unsupported values and excessive nesting are redacted.
// Application metadata must not contain secrets under unrelated names.
func AuditValue(name string, value any) any {
	return auditValue(name, value, 0)
}

func auditValue(name string, value any, depth int) any {
	normalized := strings.ToLower(strings.Map(func(r rune) rune {
		if r == '-' || r == '_' || r == '.' {
			return -1
		}
		return r
	}, name))
	for _, secret := range []string{"token", "password", "credential", "secret", "privatekey", "leasekey", "plaintext", "authorization", "cookie", "lkat"} {
		if strings.Contains(normalized, secret) {
			return auditRedacted
		}
	}
	if normalized == "key" || normalized == "cek" || depth > 16 {
		return auditRedacted
	}
	switch v := value.(type) {
	case nil, string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return v
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = auditValue(k, item, depth+1)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = auditValue("", item, depth+1)
		}
		return out
	case []string:
		return append([]string(nil), v...)
	default:
		return auditRedacted
	}
}
