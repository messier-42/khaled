package keystorage

import (
	"context"
	"errors"
	"iter"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cfar"
)

var (
	// ErrFederationDomainMismatch prevents rebinding a persisted federation identity.
	ErrFederationDomainMismatch = errors.New("federation domain identity mismatch")
	// ErrNoSuchFederationKey indicates an unknown FKID in this storage domain.
	ErrNoSuchFederationKey = errors.New("no such federation key")
	// ErrStaleFederationKey indicates that a rollover already scheduled this key's retirement.
	ErrStaleFederationKey = errors.New("federation key already scheduled for retirement")
)

// FederationKeyOptions selects standard COSE curve and algorithm identifiers.
// Zero values select P-256 and ECDH-ES+A256KW. Backends support the NIST curves
// P-256, P-384 and P-521 with ECDH-ES+A128KW, A192KW or A256KW.
type FederationKeyOptions struct{ Curve, Algorithm int }

// FederationRollover creates a successor and schedules the predecessor in one
// transaction. Zero Activate and Retire mean now; zero Unadvertise means the
// predecessor remains advertised indefinitely. Activate must be no earlier
// than creation; Retire must be no earlier than now or the predecessor's activation;
// Unadvertise, if set, must be no earlier than Retire. Overlapping current keys
// are allowed. A scheduled retirement cannot subsequently be overwritten.
type FederationRollover struct {
	Options                       FederationKeyOptions
	Activate, Retire, Unadvertise time.Time
}

// FederationKeyStatus is derived from the timestamps at the requested instant.
type FederationKeyStatus string

const (
	FederationKeyFuture  FederationKeyStatus = "future"
	FederationKeyCurrent FederationKeyStatus = "current"
	FederationKeyRetired FederationKeyStatus = "retired"
)

// FederationKey is an immutable public snapshot and opaque recovery handle.
// Its globally unique ID is the COSE kid. PublicKey and ID return independent
// copies. Private material is never exported: Recover processes an SFLP inside
// the storage boundary and returns only its complete Non-Captive Lease Key.
// Retirement and advertisement affect discovery only; every retained key can
// recover old packages, including future, retired and unadvertised keys.
type FederationKey interface {
	ID() []byte
	CreationTime() time.Time
	ActivationTime() time.Time
	RetirementTime() time.Time
	UnadvertiseTime() time.Time
	PublicKey() key.Key
	// Recover validates one SFLP against the exact Lease context using this key.
	// It does not authenticate the Origin or authorize release; callers must
	// enforce policy separately. Storage and cancellation errors are returned.
	Recover(ctx context.Context, lease cfar.LeaseContext, raw []byte) (*cabe.LKAINonCaptive, error)
	Status(at time.Time) FederationKeyStatus
	Advertised(at time.Time) bool
}

// FederationDomain is an optional extension to KeyStoreDomain. Federation Key
// history is independent of Root Keys and subepochs: no operation here changes
// local derivations. There is no deletion API; all private FKs are retained.
// All methods support concurrent calls. Iteration releases database resources
// before invoking callers, so callers may use recovery handles during iteration.
type FederationDomain interface {
	// BindFederation atomically binds the configured identity and bootstraps the
	// first FK. The same identity is idempotent; a different identity is rejected.
	BindFederation(ctx context.Context, domainID string, options FederationKeyOptions) error
	// FederationIdentity returns the bound identity, or an empty string if unbound.
	FederationIdentity(ctx context.Context) (string, error)
	ListFederationKeys(ctx context.Context) iter.Seq2[FederationKey, error]
	FederationKeyByID(ctx context.Context, id []byte) (FederationKey, error)
	// RotateFederationKey schedules oldKey exactly once using compare-and-swap.
	RotateFederationKey(ctx context.Context, oldKey FederationKey, schedule FederationRollover) (FederationKey, error)
}
