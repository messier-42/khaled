// Package keyserver is the per-domain CKAP orchestrator. Given
// authenticated requests from a transport layer, it gates access
// through the policy engine, drives the keyschedule to mint or
// resolve Lease Keys, and assembles CKAP responses.
//
// One Server serves one CABE domain. A multi-domain deployment
// instantiates multiple Servers.
//
// The Server is the only place where the identity plane
// (authn, principal mapping, policy engine) and the crypto plane
// (keyschedule,refwrapper, keywrap) converge. Neither plane directly
// depends on the other.
//
// The Lease's mint time is authenticated inside the LeaseRef and
// passed to DecideDecapsulate as LeaseTime. Policies can compare it
// against temporal Claims on the Principal (e.g.
// grantedSecretClearanceAtTime). The Server assumes the Key Server's
// clock is monotonic and NTP-synchronised.
//
// Every CKAP operation except GetSelf consults the policy engine,
// including AssistedEncapsulate and AssistedDecapsulate on every
// message.
package keyserver

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/khaled/pkg/federation"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/keyschedule"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/refwrapper"
	"github.com/messier-42/khaled/pkg/wrapper"
)

var (
	// ErrDenied is returned when policy denies a request.
	ErrDenied = errors.New("keyserver: access denied")

	// ErrInvalidRef is returned when a LeaseRef or LKAT cannot be
	// authenticated or does not have the expected type.
	ErrInvalidRef = refwrapper.ErrInvalidRef
)

// PolicySource supplies the currently active Policy Engine. A source
// (rather than a direct engine) lets the Key Server pick up policy
// reloads atomically without being rebuilt itself. Engine() may
// return nil when no engine is currently available (e.g. initial
// load failed), which results in a default deny.
type PolicySource interface {
	Engine() policyengine.Engine
}

// Config configures a Server.
type Config struct {
	// DomainName is the name of the CABE domain this Server serves.
	// Echoed back in GetSelf responses. Required.
	DomainName string

	// Schedule provides access to the key schedule layer. Required.
	Schedule *keyschedule.Schedule

	// Policy is the authorization engine source. Required. The
	// Server re-reads Policy.Engine() on every request so policy
	// reloads take effect immediately.
	Policy PolicySource

	// RefWrapper provides a cryptographic means of wrapping and unwrapping
	// LeaseRef/LKAT byte strings. Required.
	RefWrapper wrapper.Wrapper

	// LeaseDuration is the wall-clock lifetime of each minted Lease.
	// Zero uses the package default.
	LeaseDuration time.Duration

	// Now allows a custom clock source to be used for testing. If zero,
	// time.Now is used.
	Now func() time.Time

	// VersionString overrides the server version string reported in
	// GetSelf. Optional.
	VersionString string
}

const defaultLeaseDuration = 5 * time.Minute

// Server is the per-domain CKAP orchestrator.
type Server struct {
	federationDomainID atomic.Pointer[string]
	federation         atomic.Pointer[federation.Runtime]
	domainName         string
	schedule           *keyschedule.Schedule
	policy             PolicySource
	refs               *refwrapper.Codec
	leaseDuration      time.Duration
	now                func() time.Time
	version            string
}

// New constructs a Server from cfg and validates it.
func New(cfg Config) (*Server, error) {
	if cfg.DomainName == "" {
		return nil, errors.New("keyserver: Config.DomainName is required")
	}
	if cfg.Schedule == nil {
		return nil, errors.New("keyserver: Config.Schedule is required")
	}
	if cfg.Policy == nil {
		return nil, errors.New("keyserver: Config.Policy is required")
	}
	if cfg.RefWrapper == nil {
		return nil, errors.New("keyserver: Config.RefWrapper is required")
	}
	if cfg.LeaseDuration < 0 {
		return nil, errors.New("keyserver: Config.LeaseDuration must be non-negative")
	}
	leaseDur := cfg.LeaseDuration
	if leaseDur == 0 {
		leaseDur = defaultLeaseDuration
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	version := cfg.VersionString
	if version == "" {
		version = defaultVersionString()
	}
	codec, err := refwrapper.New(cfg.RefWrapper)
	if err != nil {
		return nil, err
	}
	return &Server{
		domainName:    cfg.DomainName,
		schedule:      cfg.Schedule,
		policy:        cfg.Policy,
		refs:          codec,
		leaseDuration: leaseDur,
		now:           now,
		version:       version,
	}, nil
}

// Request and response types. Transport layers translate to/from
// CBOR.

type ProgradeRequest struct {
	Principal    policyengine.Principal
	AttributeSet attrset.Set
	ARINToken    []byte
}

type ProgradeResponse struct {
	Lease Lease
}

type RetrogradeRequest struct {
	Federation   *ckap.RetrogradeFederation
	Principal    policyengine.Principal
	AttributeSet attrset.Set
	LeaseRef     []byte
}

type RetrogradeResponse struct {
	Lease Lease
}

type AssistedEncapsulateRequest struct {
	Principal policyengine.Principal
	LKAT      []byte
	CEK       []byte
}

type AssistedEncapsulateResponse struct {
	WrappedCEK []byte
}

type AssistedDecapsulateRequest struct {
	Principal  policyengine.Principal
	LKAT       []byte
	WrappedCEK []byte
}

type AssistedDecapsulateResponse struct {
	CEK []byte
}

type GetSelfRequest struct {
	Principal policyengine.Principal
}

type GetSelfResponse struct {
	Principal  policyengine.Principal
	ServerInfo map[string]any
}

// Lease is the Go-native view of a CKAP Lease. AttributeSet is
// always populated.
type Lease struct {
	Federation   *cabe.LeaseFederation
	LeaseRef     []byte
	LKAI         LKAI
	Expiry       time.Time
	AttributeSet attrset.Set
	LeaseID      string
}

// LKAI is a discriminated union; exactly one field is set.
type LKAI struct {
	NonCaptive *LKAINonCaptive
	Captive    *LKAICaptive
}

// LKAINonCaptive carries the complete COSE Lease Key, including its algorithm
// and Base IV. Transports must preserve every parameter.
//
// The transport layer is responsible for zeroing the Lease Key
// once the CBOR response bytes have been serialised and written
// to the client.
type LKAINonCaptive struct {
	LeaseKey ckapraw.COSEKey
}

type LKAICaptive struct {
	LKAT []byte
}

// deniedErr logs the Decision's server-side diagnostic fields
// (Reason, DeterminingPolicies, Diagnostics) and returns bare
// ErrDenied. Details about the decision are intentionally not
// included in the returned error in case it gets sent on the wire.
func deniedErr(ctx context.Context, op, principalURI string, d policyengine.Decision) error {
	slog.InfoContext(ctx, "keyserver: policy denied request",
		"op", op,
		"principalURI", principalURI,
		"reason", d.Reason,
		"determiningPolicies", d.DeterminingPolicies,
		"diagnostics", d.Diagnostics,
	)
	return ErrDenied
}
