// Package transport defines the Transport plugin interface. A transport
// is a long-lived listener (e.g. an HTTP server) that exposes the CKAP protocol
// over some carrier.
package transport

import (
	"context"
	"io"
)

// Transport is a listener created from a single `listeners[]`
// entry in the config. A trransport's constructor must bind the listen
// socket before returning. This allows listener errors to be detected
// during startup rather than during the call to Run(), and allows for
// in-process privilege dropping if we ever need to support it.
type Transport interface {
	// Close releases resources, listener sockets, etc. and must be called
	// after Run() is called. Idempotent.
	io.Closer

	// Run blocks and handles traffic until ctx is cancelled or a fatal
	// error occurs. Errors or panics simply handling a request are expected
	// to be contained and are not considered fatal. This function may
	// only be called once on any given transport. A nil return value indicates
	// that graceful shutdown was triggered via context cancellation and
	// successfully completed. Close should still be called in this case.
	Run(ctx context.Context) error
}
