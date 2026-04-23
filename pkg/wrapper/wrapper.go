// Package wrapper defines the abstract interface implemented by
// byte string authentication primitives used by the Key Server.
//
// An implementation takes an opaque plaintext together with
// optional additional associated data (AAD), and produces an opaque
// output that authenticates both. Unwrap verifies the output against
// the same AAD and returns the plaintext on success.
// Implementations do not interpret either input; higher layers
// (see pkg/refwrapper) define the plaintext structure and the AAD
// convention.
package wrapper

import "context"

// Wrapper authenticates and frames opaque byte strings. Wrap takes
// plaintext and AAD and produces an opaque output; Unwrap verifies
// the output against the same AAD and returns the plaintext on
// success (and only on success). The authentication key is a property
// of the Wrapper.
//
// Implementations must be safe for concurrent use.
type Wrapper interface {
	Wrap(ctx context.Context, plaintext, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, opaque, aad []byte) ([]byte, error)
}
