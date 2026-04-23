// Package policyengine defines the Policy Engine plugin interface.
//
// A Policy Engine evaluates access-control policy. Given a
// Principal, an Attribute Set, and (for Decapsulate) an authenticated
// Lease issuance time, it returns ALLOW or DENY, plus ancillary
// flags such as RequireCaptive.
//
// An Engine is immutable once constructed. To apply a policy change,
// the caller constructs a new Engine and atomically swaps it for the
// old one. This keeps the interface narrow and keeps the concurrency
// reasoning obvious at the use site.
//
// # Temporal policy
//
// The Decapsulate path receives LeaseTime, the wall-clock issuance time
// of the Lease being resolved. Policies can compare it against
// mission-specific temporal Claims on the Principal (for example,
// a claim like grantedSecretClearanceAtTime) to enforce "no access
// before authorization" and similar temporal invariants.
//
// # Plane boundary
//
// The Engine is the authorization plane. It must not import or
// consume anything from the cryptography plane (keystorage, keyschedule,
// refwrapper). The keyserver package is the only place the two
// planes meet.
package policyengine

import (
	"context"
	"io"
	"time"

	"github.com/messier-42/cabe-go/attrset"
)

// Principal identifies the authenticated caller as perceived by the Key
// Server. URI is the stable Principal identifier (required).
// Claims are arbitrary facts attached by the Claims Mapping plugin;
// keys are unconstrained textual strings and values are CBOR-mappable
// Go-native types.
type Principal struct {
	URI    string
	Claims map[string]any
}

// EncapsulateRequest is the input to Engine.DecideEncapsulate. It
// authorizes creating new envelopes for an Attribute Set (CKAP
// Prograde / AssistedEncapsulate).
type EncapsulateRequest struct {
	Principal    Principal
	AttributeSet attrset.Set

	// Now is the Key Server's perception of wall-clock time at the
	// moment of the decision. Policies may compare Now against
	// temporal Claims on the Principal.
	Now time.Time
}

// DecapsulateRequest is the input to Engine.DecideDecapsulate. It
// authorizes reading envelopes for an Attribute Set (CKAP Retrograde
// / AssistedDecapsulate). LeaseTime is the authenticated wall-clock
// issuance time of the Lease being resolved.
type DecapsulateRequest struct {
	Principal    Principal
	AttributeSet attrset.Set

	// Now is the Key Server's perception of wall-clock time at the
	// moment of the decision.
	Now time.Time

	// LeaseTime is the wall-clock issuance time of the Lease whose
	// decapsulation is being authorized. Policies may compare
	// LeaseTime against temporal Claims on the Principal (e.g.
	// "deny if LeaseTime < Principal.secretGrantedTime").
	LeaseTime time.Time
}

// Decision is the output of DecideEncapsulate / DecideDecapsulate.
//
// Allow is the binary verdict defined by CABE. The remaining fields
// are advisory diagnostics for logging and audit. Engines fill in what
// they can; callers tolerate empty values.
type Decision struct {
	// Allow is true for ALLOW, false for DENY.
	Allow bool

	// RequireCaptive directs the keyserver to issue LKAI_Captive rather
	// than LKAI_NonCaptive for this access. Ignored when Allow is false.
	RequireCaptive bool

	// Reason is a short human-readable summary of the decision, engine-
	// specific in format.
	Reason string

	// DeterminingPolicies lists the IDs of policies that caused the
	// decision (e.g. matching permit/forbid rules).
	DeterminingPolicies []string

	// Diagnostics lists non-fatal evaluation warnings.
	Diagnostics []string
}

// Engine evaluates policy. Both methods are safe for concurrent use from
// multiple goroutines.
//
// The error return is reserved for engine-internal failures (e.g. a
// value conversion error, evaluator crash) and is distinct from a DENY
// decision. Callers SHOULD treat any non-nil error as deny-by-default
// and log it.
type Engine interface {
	io.Closer

	DecideEncapsulate(ctx context.Context, req EncapsulateRequest) (Decision, error)
	DecideDecapsulate(ctx context.Context, req DecapsulateRequest) (Decision, error)
}
