package plugin

import (
	"context"
	"fmt"

	"github.com/messier-42/khaled/pkg/config/schema"
)

// Factory is a typed registry of plugin variants for a single plugin
// kind (e.g. "clientAuthn", "keyStorage"). Each variant contributes
// both a constructor (typed against the kind's Args struct) and a
// schema fragment. Building a plugin dispatches on a name looked up
// in the ctor map; the per-kind NewXxx entry point is a one-liner
// over Build.
//
// Centralising dispatch here replaces the N hand-written switch
// statements across pkg/plugin/<kind>.go with one generic path. The
// Args shape stays kind-specific and strongly typed; the Factory
// itself is parameterised on (Args, T) so Go's type system enforces
// that each variant's constructor signature matches.
type Factory[Args any, T any] struct {
	kind    string
	ctors   map[string]func(context.Context, Args) (T, error)
	schemas []func(*schema.Registry) error
}

// NewFactory returns an empty Factory for the given plugin kind name.
// The kind name is used only for error messages; it has no lookup
// effect.
func NewFactory[Args, T any](kind string) *Factory[Args, T] {
	return &Factory[Args, T]{
		kind:  kind,
		ctors: map[string]func(context.Context, Args) (T, error){},
	}
}

// Register adds a variant. ctor is called to build an instance when
// Build is invoked with the given name; sch, if non-nil, contributes
// a JSON Schema fragment when RegisterSchemas runs. Panics on
// duplicate registration — this is a programmer error surfaced at
// init time.
func (f *Factory[Args, T]) Register(name string, ctor func(context.Context, Args) (T, error), sch func(*schema.Registry) error) {
	if _, exists := f.ctors[name]; exists {
		panic(fmt.Sprintf("plugin %q already registered for kind %q", name, f.kind))
	}
	f.ctors[name] = ctor
	if sch != nil {
		f.schemas = append(f.schemas, sch)
	}
}

// Build dispatches to the named variant's constructor. Returns an
// "unsupported" error if the name was not Registered. Constructor
// errors are wrapped only when their own message would not already
// identify the kind — see each NewXxx for the current convention.
func (f *Factory[Args, T]) Build(ctx context.Context, name string, args Args) (T, error) {
	ctor, ok := f.ctors[name]
	if !ok {
		var zero T
		return zero, fmt.Errorf("unsupported %s plugin %q", f.kind, name)
	}
	return ctor(ctx, args)
}

// RegisterSchemas invokes every registered variant's schema fragment
// against r. Returns the first error encountered. Registration order
// is the order of Register calls, which is deterministic across runs.
func (f *Factory[Args, T]) RegisterSchemas(r *schema.Registry) error {
	for _, fn := range f.schemas {
		if err := fn(r); err != nil {
			return err
		}
	}
	return nil
}
