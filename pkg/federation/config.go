package federation

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/config/schema"
)

const (
	identityMaxAgeField = "identityMaxAge"
	cacheBytesField     = "cacheBytes"
	domainIDField       = "domainID"
	cacheTTLField       = "cacheTTL"
	schemaTypeString    = "string"
)

// ConfigFromSnapshot parses federation policy. Private keys and lifecycle
// schedules are deliberately absent: those belong to the unified key store.
// Provisioned peer identities use base64-encoded CKAP FederationIdentity CBOR.
func ConfigFromSnapshot(snap config.Snapshot) (*Config, error) {
	v, exists := snap.Root.Get("federation")
	if !exists {
		return nil, nil
	}
	block, ok := v.(config.Map)
	if !ok {
		return nil, errors.New("federation must be an object")
	}
	allowed := map[string]bool{domainIDField: true, "curve": true, "algorithm": true, identityMaxAgeField: true, cacheBytesField: true, cacheTTLField: true, "peers": true}
	for k := range block {
		if !allowed[k] {
			return nil, fmt.Errorf("federation: unknown field %q", k)
		}
	}
	c := &Config{CacheBytes: 8 << 20, CacheTTL: 5 * time.Minute, IdentityMaxAge: time.Minute}
	c.DomainID, _ = block.GetString(domainIDField)
	if c.DomainID == "" {
		return nil, errors.New("federation.domainID required")
	}
	curve, _ := block.GetString("curve")
	switch curve {
	case "", "P-256":
		c.KeyOptions.Curve = iana.EllipticCurveP_256
	case "P-384":
		c.KeyOptions.Curve = iana.EllipticCurveP_384
	case "P-521":
		c.KeyOptions.Curve = iana.EllipticCurveP_521
	default:
		return nil, errors.New("federation: curve must be P-256, P-384 or P-521")
	}
	alg, _ := block.GetString("algorithm")
	switch alg {
	case "", "ECDH-ES+A256KW":
		c.KeyOptions.Algorithm = iana.AlgorithmECDH_ES_A256KW
	case "ECDH-ES+A128KW":
		c.KeyOptions.Algorithm = iana.AlgorithmECDH_ES_A128KW
	case "ECDH-ES+A192KW":
		c.KeyOptions.Algorithm = iana.AlgorithmECDH_ES_A192KW
	default:
		return nil, errors.New("federation: invalid recipient algorithm")
	}
	for name, dest := range map[string]*time.Duration{identityMaxAgeField: &c.IdentityMaxAge, cacheTTLField: &c.CacheTTL} {
		if v, present := block.Get(name); present {
			raw, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("federation.%s must be a duration", name)
			}
			d, e := time.ParseDuration(raw)
			if e != nil || d < 0 || d > 365*24*time.Hour {
				return nil, fmt.Errorf("federation.%s invalid duration", name)
			}
			*dest = d
		}
	}
	if v, present := block.Get(cacheBytesField); present {
		n, ok := v.(int64)
		if !ok || n < 0 || n > 1<<30 {
			return nil, errors.New("federation.cacheBytes must be between 0 and 1073741824")
		}
		c.CacheBytes = int(n)
	}
	if c.CacheBytes > 0 && c.CacheTTL == 0 {
		return nil, errors.New("federation.cacheTTL must be positive when cache is enabled")
	}
	if v, present := block.Get("peers"); present {
		peers, ok := v.(config.Array)
		if !ok {
			return nil, errors.New("federation.peers must be an array")
		}
		seen := map[string]bool{}
		for _, v := range peers {
			m, ok := v.(config.Map)
			if !ok {
				return nil, errors.New("federation peer must be an object")
			}
			for k := range m {
				if k != domainIDField && k != "identity" && k != "url" && k != "caFile" {
					return nil, fmt.Errorf("federation peer: unknown field %q", k)
				}
			}
			p := Peer{}
			p.DomainID, _ = m.GetString(domainIDField)
			p.URL, _ = m.GetString("url")
			p.CAFile, _ = m.GetString("caFile")
			if p.DomainID == "" || p.DomainID == c.DomainID || seen[p.DomainID] {
				return nil, errors.New("federation: invalid or duplicate peer domainID")
			}
			seen[p.DomainID] = true
			if raw, present := m.Get("identity"); present {
				str, ok := raw.(string)
				if !ok {
					return nil, errors.New("federation peer identity must be base64 CBOR")
				}
				b, e := base64.StdEncoding.DecodeString(str)
				if e != nil {
					return nil, e
				}
				var id ckapraw.FederationIdentity
				if e = key.UnmarshalCBOR(b, &id); e != nil {
					return nil, e
				}
				if e = validateIdentity(p.DomainID, &id); e != nil {
					return nil, e
				}
				p.Identity = &id
			}
			if (p.Identity == nil) == (p.URL == "") || (p.Identity != nil && p.CAFile != "") {
				return nil, errors.New("federation peer requires either identity or URL with optional caFile")
			}
			c.Peers = append(c.Peers, p)
		}
	}
	return c, nil
}

// RegisterSchema installs structural and semantic validation together.
func RegisterSchema(r *schema.Registry) error {
	minOne := 1
	zero := float64(0)
	maxBytes := float64(1 << 30)
	str := func() *jsonschema.Schema { return &jsonschema.Schema{Type: schemaTypeString, MinLength: &minOne} }
	noExtras := func() *jsonschema.Schema { return &jsonschema.Schema{Not: &jsonschema.Schema{}} }
	peer := &jsonschema.Schema{Type: "object", Required: []string{domainIDField}, AdditionalProperties: noExtras(), Properties: map[string]*jsonschema.Schema{domainIDField: str(), "identity": str(), "url": str(), "caFile": str()}}
	err := r.RegisterPath("federation", &jsonschema.Schema{Type: "object", Required: []string{domainIDField}, AdditionalProperties: noExtras(), Properties: map[string]*jsonschema.Schema{
		domainIDField: str(), "curve": {Type: schemaTypeString, Enum: []any{"P-256", "P-384", "P-521"}}, "algorithm": {Type: schemaTypeString, Enum: []any{"ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"}}, identityMaxAgeField: str(), cacheTTLField: str(), cacheBytesField: {Type: "integer", Minimum: &zero, Maximum: &maxBytes}, "peers": {Type: "array", Items: peer},
	}})
	if err != nil {
		return err
	}
	return r.RegisterValidator(func(_ context.Context, old *config.Snapshot, next config.Snapshot) error {
		c, err := ConfigFromSnapshot(next)
		if err != nil {
			return err
		}
		if old != nil && c != nil {
			prev, err := ConfigFromSnapshot(*old)
			if err != nil {
				return err
			}
			if prev != nil && c.DomainID != prev.DomainID {
				return errors.New("federation.domainID cannot change on reload")
			}
		}
		return nil
	})
}
