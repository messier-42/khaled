// Package policysource defines the Policy Source plugin interface.
//
// A Policy Source obtains policy data, such as Cedar policy text, from a
// backing store, compiles it into a policyengine.Engine via an injected
// CompileFunc, and keeps it current by watching the backing store for
// changes. It is conceptually a sibling to the Config Source; Current()
// returns the latest good Engine, UpdateChan() reports reload
// outcomes, and failed reloads leave the previous Engine in place.
//
// Parsing/compilation is delegated to a CompileFunc so concrete source
// implementations (e.g. the watched-file source) need not import any
// concrete engine package. A new engine plugs in by passing its own
// CompileFunc closure to the NewPolicySource function, keeping the source
// plugins engine agnostic.
package policysource

import (
	"context"
	"io"

	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// CompileArgs carries the inputs to a CompileFunc.
type CompileArgs struct {
	// Source is the raw policy bytes (e.g. Cedar policy text).
	Source []byte

	// Type is the content type of Source as a MIME type (e.g.
	// "text/cedar"). An empty string means "unknown" and the CompileFunc
	// assumes a default.
	Type string
}

// CompileFunc parses policy source data into a ready-to-use Engine. It
// is invoked by a Source on every successful read of the backing store.
// The returned Engine must be immutable and safe for concurrent use.
type CompileFunc func(ctx context.Context, args CompileArgs) (policyengine.Engine, error)

// Source provides access to the current policy engine and provides
// notifications when it changes. Usage mirrors [configsource.Source].
type Source interface {
	io.Closer

	// Current returns the current Engine. It always returns either a
	// non-nil Engine with a nil error, or a nil Engine with a non-nil
	// error. On first call, Current returns the Engine built from the
	// initial load, or an error if initial load or compile failed.
	//
	// Once an Engine has been successfully loaded, subsequent calls to
	// Current continue to return a non-nil Engine with nil error for
	// the Source's lifetime. A failed reload leaves the previous Engine
	// in place and surfaces its error via UpdateChan() only.
	//
	// The returned Engine is immutable and safe for concurrent use.
	// Callers MAY retain a reference across reloads; it is safe to use a
	// an Engine that has been superseded.
	Current() (policyengine.Engine, error)

	// UpdateChan returns a channel that receives one value per reload
	// outcome: nil on success, or the compile/read error on failure. The
	// initial load does not cause a value to be sent on this channel; detect
	// failures in initial load by calling Current() and checking for a
	// returned error. Implementations MAY coalesce rapid successive reloads
	// into a single send on this channel.
	UpdateChan() <-chan error
}
