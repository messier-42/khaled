// Package cedar implements the policyengine.Engine interface using the Cedar
// policy language (https://www.cedarpolicy.com/).
package cedar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	cedar "github.com/cedar-policy/cedar-go"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

const contextKeyNow = "now"

// Entity types used in Cedar requests built from policyengine.Request.
const (
	entityTypePrincipal    = "Principal"
	entityTypeAction       = "Action"
	entityTypeAttributeSet = "AttributeSet"

	actionIDEncapsulate = "Encapsulate"
	actionIDDecapsulate = "Decapsulate"

	// resourceID is a fixed identifier for the per-request AttributeSet
	// resource entity. Policies match on resource attributes, not identity,
	// so a stable literal is sufficient.
	resourceID = "current"
)

// Config configures a Cedar Engine.
type Config struct {
	// PolicyText is the Cedar policy source code (UTF-8). Required.
	PolicyText []byte
}

// Engine is a Cedar-backed policyengine.Engine. It is immutable after
// construction and safe for concurrent use.
type Engine struct {
	policySet *cedar.PolicySet
}

var _ policyengine.Engine = &Engine{}

// New parses cfg.PolicyText and returns a ready-to-use Engine. Empty policy
// text is allowed (the resulting engine denies everything by default).
func New(cfg Config) (*Engine, error) {
	ps, err := cedar.NewPolicySetFromBytes("", cfg.PolicyText)
	if err != nil {
		return nil, fmt.Errorf("cedar: parse policy: %w", err)
	}
	return &Engine{policySet: ps}, nil
}

// Close is a no-op. It exists to satisfy policyengine.Engine.
func (e *Engine) Close() error {
	return nil
}

// DecideEncapsulate evaluates the engine's policy set for an
// encapsulation request. A non-nil error indicates a value-conversion
// failure; callers SHOULD treat any non-nil error as deny-by-default.
//
// The Cedar Context carries `now` (current wall clock as Unix
// microseconds, Long). Policies can reference it as
// `context.now`.
func (e *Engine) DecideEncapsulate(_ context.Context, req policyengine.EncapsulateRequest) (policyengine.Decision, error) {
	ctxRec := cedar.NewRecord(cedar.RecordMap{
		contextKeyNow: cedar.Long(req.Now.UnixMicro()),
	})
	return e.decide(req.Principal, req.AttributeSet, actionIDEncapsulate, ctxRec)
}

// DecideDecapsulate evaluates the engine's policy set for a
// decapsulation request.
//
// The context includes now and, for a known local issuance time, leaseTime
// as Unix microseconds. Foreign requests omit leaseTime and expose federated
// and the unauthenticated claimed originDomain. Foreign evaluation errors
// deny access, including errors in forbid expressions alongside permits.
func (e *Engine) DecideDecapsulate(_ context.Context, req policyengine.DecapsulateRequest) (policyengine.Decision, error) {
	fields := cedar.RecordMap{contextKeyNow: cedar.Long(req.Now.UnixMicro()), "federated": cedar.Boolean(req.Federated)}
	if req.LeaseTime != nil && !req.Federated {
		fields["leaseTime"] = cedar.Long(req.LeaseTime.UnixMicro())
	}
	if req.Federated {
		fields["originDomain"] = cedar.String(req.OriginDomain)
	}
	d, err := e.decide(req.Principal, req.AttributeSet, actionIDDecapsulate, cedar.NewRecord(fields))
	if req.Federated && len(d.Diagnostics) > 0 {
		d.Allow = false
		d.Reason = "foreign policy evaluation failed"
	}
	return d, err
}

// DecideFederate independently authorizes release to one target. Evaluation
// errors fail closed, including an erroneous forbid alongside a permit.
func (e *Engine) DecideFederate(_ context.Context, req policyengine.FederateRequest) (policyengine.Decision, error) {
	d, err := e.decide(req.Principal, req.AttributeSet, "Federate", cedar.NewRecord(cedar.RecordMap{
		contextKeyNow: cedar.Long(req.Now.UnixMicro()), "targetDomain": cedar.String(req.TargetDomain),
	}))
	if len(d.Diagnostics) > 0 {
		return policyengine.Decision{}, errors.New("cedar: federation policy evaluation failed")
	}
	return d, err
}

func (e *Engine) decide(principal policyengine.Principal, as attrset.Set, actionID string, ctxRec cedar.Record) (policyengine.Decision, error) {
	principalEntity, err := buildPrincipalEntity(principal)
	if err != nil {
		return policyengine.Decision{}, fmt.Errorf("cedar: principal: %w", err)
	}

	resourceEntity, err := buildResourceEntity(as)
	if err != nil {
		return policyengine.Decision{}, fmt.Errorf("cedar: resource: %w", err)
	}

	actionUID := cedar.NewEntityUID(entityTypeAction, cedar.String(actionID))

	entities := cedar.EntityMap{
		principalEntity.UID: principalEntity,
		resourceEntity.UID:  resourceEntity,
		actionUID:           cedar.Entity{UID: actionUID},
	}

	cedarReq := cedar.Request{
		Principal: principalEntity.UID,
		Action:    actionUID,
		Resource:  resourceEntity.UID,
		Context:   ctxRec,
	}

	verdict, diag := cedar.Authorize(e.policySet, entities, cedarReq)
	return buildDecision(verdict, diag), nil
}

func buildPrincipalEntity(p policyengine.Principal) (cedar.Entity, error) {
	if p.URI == "" {
		return cedar.Entity{}, errors.New("principal URI is empty")
	}

	attrs, err := toCedarRecord(p.Claims)
	if err != nil {
		return cedar.Entity{}, err
	}

	return cedar.Entity{
		UID:        cedar.NewEntityUID(entityTypePrincipal, cedar.String(p.URI)),
		Attributes: attrs,
	}, nil
}

func buildResourceEntity(s attrset.Set) (cedar.Entity, error) {
	m := make(map[string]any, s.Len())
	s.Range(func(k string, v any) bool {
		m[k] = v
		return true
	})

	attrs, err := toCedarRecord(m)
	if err != nil {
		return cedar.Entity{}, err
	}

	return cedar.Entity{
		UID:        cedar.NewEntityUID(entityTypeAttributeSet, resourceID),
		Attributes: attrs,
	}, nil
}

func buildDecision(verdict cedar.Decision, diag cedar.Diagnostic) policyengine.Decision {
	d := policyengine.Decision{Allow: bool(verdict)}

	if n := len(diag.Reasons); n > 0 {
		d.DeterminingPolicies = make([]string, n)
		for i, r := range diag.Reasons {
			d.DeterminingPolicies[i] = string(r.PolicyID)
		}
	}

	if n := len(diag.Errors); n > 0 {
		d.Diagnostics = make([]string, n)
		for i, e := range diag.Errors {
			d.Diagnostics[i] = e.String()
		}
	}

	switch {
	case d.Allow && len(d.DeterminingPolicies) > 0:
		d.Reason = "permitted by policy " + d.DeterminingPolicies[0]
	case !d.Allow && len(d.DeterminingPolicies) > 0:
		d.Reason = "forbidden by policy " + d.DeterminingPolicies[0]
	case !d.Allow:
		d.Reason = "no policy permitted access"
	}

	return d
}

// toCedarRecord converts a Go map to a Cedar Record. The input is
// treated as a set of named attributes.
func toCedarRecord(m map[string]any) (cedar.Record, error) {
	if len(m) == 0 {
		return cedar.NewRecord(cedar.RecordMap{}), nil
	}

	rm := make(cedar.RecordMap, len(m))
	for k, v := range m {
		cv, err := toCedarValue(v)
		if err != nil {
			return cedar.Record{}, fmt.Errorf("attribute %q: %w", k, err)
		}
		rm[cedar.String(k)] = cv
	}

	return cedar.NewRecord(rm), nil
}

// toCedarValue converts a Go-native value into a Cedar value.
func toCedarValue(v any) (cedar.Value, error) {
	switch x := v.(type) {
	case nil:
		return nil, errors.New("nil values are not representable in Cedar")
	case string:
		return cedar.String(x), nil
	case bool:
		return cedar.Boolean(x), nil
	case int:
		return cedar.Long(x), nil
	case int8:
		return cedar.Long(x), nil
	case int16:
		return cedar.Long(x), nil
	case int32:
		return cedar.Long(x), nil
	case int64:
		return cedar.Long(x), nil
	case uint:
		if uint64(x) > math.MaxInt64 {
			return nil, fmt.Errorf("uint value %d overflows Cedar Long", x)
		}
		return cedar.Long(x), nil
	case uint8:
		return cedar.Long(x), nil
	case uint16:
		return cedar.Long(x), nil
	case uint32:
		return cedar.Long(x), nil
	case uint64:
		if x > math.MaxInt64 {
			return nil, fmt.Errorf("uint64 value %d overflows Cedar Long", x)
		}
		return cedar.Long(x), nil
	case float32:
		d, err := cedar.NewDecimalFromFloat(x)
		if err != nil {
			return nil, fmt.Errorf("float32 %v not representable as Cedar Decimal: %w", x, err)
		}
		return d, nil
	case float64:
		d, err := cedar.NewDecimalFromFloat(x)
		if err != nil {
			return nil, fmt.Errorf("float64 %v not representable as Cedar Decimal: %w", x, err)
		}
		return d, nil
	case []byte:
		return cedar.String(hex.EncodeToString(x)), nil
	case []any:
		vs := make([]cedar.Value, 0, len(x))
		for i, elem := range x {
			cv, err := toCedarValue(elem)
			if err != nil {
				return nil, fmt.Errorf("[%d]: %w", i, err)
			}
			vs = append(vs, cv)
		}
		return cedar.NewSet(vs...), nil
	case map[string]any:
		return toCedarRecord(x)
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}
}
