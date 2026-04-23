// Package lifecycle provides a generic lifecycle manager for the subsystem
// reload pattern used for each subsystem.
//
// Every stateful subsystem owns a "current" plugin instance T. On
// each reload snapshot the manager involves an Apply callback provided
// by the subsystem, which decides what should be used going forward
// now: a newly-built T, the previous T unchanged (no-op), or the
// nil (uninstall).
//
// Apply receives both the config snapshot that produced the current T (the
// "old" snapshot) and the new config snapshot that it should
// reconcile against. Subsystem-provided Apply functions are responsible
// for constructing instances of T from the config snapshot.
//
// # Exceptions
//
// Currently, the policy subsystem (policysub) and the transport subsystem
// (transportsub) do not use Manager. policysub is designed to pick up
// changes primarily from external sources, not config source changes;
// transportsub has multiple instances and at some point should be
// refactored to allow listeners to be added or removed dynamically.
package lifecycle

import (
	"context"
	"log/slog"
	"sync"

	"github.com/messier-42/khaled/pkg/config"
)

// Spec is the per-subsystem definition Manager uses to manage a subsystem's
// lifecycle.
type Spec[T any] struct {
	// Name is a short human-readable subsystem label used for logging.
	Name string

	// Apply is the per-subsystem reconciliation step. Manager calls
	// it from Start (with oldT=nil and oldSnap={}) and from every
	// Reconcile (with the previously-committed T and the
	// config snapshot that produced it). Apply decides what should be
	// installed now and returns it:
	//
	//   - Return oldT unchanged to absorb newSnap without rebuilding
	//     (e.g. a subsystem that cannot be changed after startup; warn
	//     and keep the existing source);
	//
	//   - Return a freshly-built T to install a new instance. The
	//     Manager will Close the previous T (outside the lock,
	//     errors logged) once the new instance is committed;
	//
	//   - Return a nil T to uninstall (no plugin configured);
	//
	//   - Return a non-nil error to fail the call. oldT and oldSnap
	//     are retained; the error propagates to the caller.
	Apply func(ctx context.Context, oldT T, oldSnap, newSnap config.Snapshot) (T, error)

	// Close releases a T that the Manager is about to discard. A nil
	// Close means the T has no cleanup requirements. Close is called
	// only when Apply returns a T that differs from oldT (Manager compares
	// with ==, so T must be comparable — pointer or interface is
	// fine; struct values are not).
	Close func(T) error
}

// Manager runs the generic reload lifecycle for a single subsystem.
// Construct a Manager via [New] or [NewEmpty].
type Manager[T any] struct {
	spec Spec[T]

	mu      sync.Mutex
	current T
	hasT    bool
	snap    config.Snapshot // the snapshot that produced current
}

// New calls Apply with zero old-state and the initial snapshot,
// and returns a Manager holding the result. A nil returned T is
// treated as "not installed"; a non-nil T is kept as the current
// instance. Apply errors propagate.
func New[T any](ctx context.Context, snap config.Snapshot, spec Spec[T]) (*Manager[T], error) {
	m := &Manager[T]{spec: spec, snap: snap}
	var zeroT T
	next, err := spec.Apply(ctx, zeroT, config.Snapshot{}, snap)
	if err != nil {
		return nil, err
	}
	if !isZero(next) {
		m.current = next
		m.hasT = true
		slog.Info(spec.Name + " started")
	}
	return m, nil
}

// NewEmpty returns a Manager in the "no active plugin" state. Useful
// for tests.
func NewEmpty[T any](spec Spec[T]) *Manager[T] {
	return &Manager[T]{spec: spec}
}

// Current returns the currently-installed plugin instance, or nil
// if none.
func (m *Manager[T]) Current() T {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

// Stop closes the current plugin instance and clears internal state
// so subsequent Current calls return nil T. Idempotent and safe
// to call multiple times.
func (m *Manager[T]) Stop() error {
	m.mu.Lock()
	prev := m.current
	had := m.hasT
	var zeroT T
	m.current = zeroT
	m.hasT = false
	m.snap = config.Snapshot{}
	m.mu.Unlock()

	if !had || m.spec.Close == nil {
		return nil
	}
	return m.spec.Close(prev)
}

// Reconcile invokes Apply with the previously-committed state and
// the freshly-delivered snapshot, then swaps in the returned T.
// When the returned T differs from oldT, the previous T is Close'd.
// Any error during Close is logged but not returned; the reload loop
// continues regardless.
//
// Note: for a given Manager instance, this method must be called from
// exactly one Goroutine.
func (m *Manager[T]) Reconcile(ctx context.Context, snap config.Snapshot) error {
	m.mu.Lock()
	oldT := m.current
	oldSnap := m.snap
	m.mu.Unlock()

	next, err := m.spec.Apply(ctx, oldT, oldSnap, snap)
	if err != nil {
		return err
	}

	same := sameInstance(oldT, next)

	m.mu.Lock()
	m.current = next
	m.hasT = !isZero(next)
	m.snap = snap
	m.mu.Unlock()

	if !same && !isZero(oldT) && m.spec.Close != nil {
		if err := m.spec.Close(oldT); err != nil {
			slog.Error(m.spec.Name+" shutdown error during reload", "error", err)
		}
	}
	if !same {
		slog.Info(m.spec.Name + " rebuilt due to config change")
	}
	return nil
}

// sameInstance reports whether a and b are the same T. For pointer
// and interface Ts this is identity comparison; for struct Ts it is
// value equality. The Apply contract requires T to be comparable.
func sameInstance[T any](a, b T) bool {
	return any(a) == any(b)
}

// isZero reports whether v is the zero value of T.
func isZero[T any](v T) bool {
	var zero T
	return any(v) == any(zero)
}
