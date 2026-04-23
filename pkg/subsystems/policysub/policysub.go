// Package policysub provides the policy engine subsystem.
//
// A Manager owns a running policy source and publishes the compiled
// Engine into an atomic pointer that is updated in the background as
// the underlying policy file changes. When the snapshot's policy
// configuration changes, the Manager rebuilds its internal runtime
// and atomically swaps it in so downstream consumers observe the new
// Engine automatically via the stable Engine() accessor.
package policysub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/plugin/policysource"
)

// loadEngine reads the current Engine from p, treating an unset
// pointer as "no engine available" (nil, meaning deny-by-default).
func loadEngine(p *atomic.Pointer[policyengine.Engine]) policyengine.Engine {
	if e := p.Load(); e != nil {
		return *e
	}
	return nil
}

// storeEngine writes eng into p. A nil interface clears the pointer
// so future loads return nil, rather than storing a non-nil pointer
// to a nil interface value.
func storeEngine(p *atomic.Pointer[policyengine.Engine], eng policyengine.Engine) {
	if eng == nil {
		p.Store(nil)
		return
	}
	p.Store(&eng)
}

// runtime owns a running policy source and publishes its Engine into
// an atomic pointer. It is constructed from a config snapshot and is
// responsible for keeping the pointer updated as the underlying
// policy file changes.
type runtime struct {
	source policysource.Source

	// args captures the arguments that built source, so that a config
	// reload can detect whether the runtime needs to be rebuilt.
	args plugin.PolicySourceArgs

	// targetMu protects the target pointer itself (as opposed to the
	// atomic pointer it references). The owning Manager may redirect
	// target to a private sink just before stop so any last-in-flight
	// update from the watcher does not clobber the shared pointer.
	targetMu sync.Mutex
	target   *atomic.Pointer[policyengine.Engine]

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

// currentTarget returns the pointer the watcher should publish to.
func (r *runtime) currentTarget() *atomic.Pointer[policyengine.Engine] {
	r.targetMu.Lock()
	defer r.targetMu.Unlock()
	return r.target
}

// redirectTarget replaces the pointer the watcher publishes to. Used
// by the Manager to redirect a soon-to-be-stopped runtime's updates
// into a throwaway sink.
func (r *runtime) redirectTarget(p *atomic.Pointer[policyengine.Engine]) {
	r.targetMu.Lock()
	defer r.targetMu.Unlock()
	r.target = p
}

// startRuntime constructs a policy source from snap, publishes the
// initial Engine into target (or a fresh pointer if target is nil),
// and spawns a goroutine that listens for policy-source UpdateChan
// notifications and refreshes the pointer accordingly.
//
// Returns an error if the snapshot is missing required blocks, if the
// source cannot be constructed, or if the initial policy load fails.
// In the error case no goroutine is spawned and no resources leak.
func startRuntime(ctx context.Context, snap config.Snapshot, target *atomic.Pointer[policyengine.Engine]) (*runtime, error) {
	args, err := argsFromSnapshot(snap)
	if err != nil {
		return nil, err
	}

	src, err := plugin.NewPolicySource(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("construct policy source: %w", err)
	}

	eng, err := src.Current()
	if err != nil {
		_ = src.Close()
		return nil, fmt.Errorf("initial policy load: %w", err)
	}

	if target == nil {
		target = &atomic.Pointer[policyengine.Engine]{}
	}
	storeEngine(target, eng)

	runCtx, cancel := context.WithCancel(ctx)
	rt := &runtime{
		source: src,
		target: target,
		args:   args,
		cancel: cancel,
	}

	rt.wg.Add(1)
	go rt.watch(runCtx)

	slog.Info("policy runtime started",
		"source", args.PluginName,
		"engine", args.EngineName,
		"path", args.File.Path,
	)
	return rt, nil
}

// stop cancels the watcher goroutine and closes the underlying policy
// source (which in turn closes its current Engine). The runtime's
// target pointer is left untouched; the Manager redirects it before
// stop when it needs the pointer preserved for a replacement runtime.
func (r *runtime) stop() error {
	if r == nil {
		return nil
	}
	if r.cancel != nil {
		r.cancel()
	}
	var err error
	if r.source != nil {
		err = r.source.Close()
	}
	r.wg.Wait()
	return err
}

// watch consumes the source's UpdateChan and refreshes the target on
// successful reloads. Failed reloads are logged and leave the
// previous Engine in place (the source's last-known-good semantics
// guarantee Current() continues to return the previous Engine).
func (r *runtime) watch(ctx context.Context) {
	defer r.wg.Done()
	updates := r.source.UpdateChan()
	for {
		select {
		case <-ctx.Done():
			return
		case err, ok := <-updates:
			if !ok {
				return
			}
			if err != nil {
				slog.Error("policy reload failed",
					"path", r.args.File.Path,
					"engine", r.args.EngineName,
					"error", err)
				continue
			}
			eng, cerr := r.source.Current()
			if cerr != nil {
				// Should not happen after a nil update per the
				// policysource contract; log defensively.
				slog.Error("post-reload policy Current() failed", "error", cerr)
				continue
			}
			storeEngine(r.currentTarget(), eng)
			slog.Info("policy reloaded", "path", r.args.File.Path, "engine", r.args.EngineName)
		}
	}
}

// Manager owns the currently running policy runtime and reconciles
// it against config snapshots. The atomic pointer it exposes via
// Engine() is stable across reloads even when the underlying runtime
// is torn down and rebuilt, so downstream consumers (typically the
// keyserver) can retain a reference to the Manager indefinitely.
type Manager struct {
	mu      sync.Mutex
	current *runtime
	engine  atomic.Pointer[policyengine.Engine]
}

// New builds the initial policy runtime from snap and returns a
// Manager that owns it. The manager's engine pointer receives the
// initial Engine and is updated in the background as the policy
// source reloads.
func New(ctx context.Context, snap config.Snapshot) (*Manager, error) {
	m := &Manager{}
	rt, err := startRuntime(ctx, snap, &m.engine)
	if err != nil {
		return nil, err
	}
	m.current = rt
	return m, nil
}

// NewEmpty returns a Manager with no current runtime. Used for
// testing.
func NewEmpty() *Manager {
	return &Manager{}
}

// Engine satisfies the keyserver.PolicySource interface. A nil return
// is treated as deny-by-default by the keyserver.
func (m *Manager) Engine() policyengine.Engine {
	return loadEngine(&m.engine)
}

// Stop tears down the current runtime, if any, and stops the Manager.
func (m *Manager) Stop() error {
	m.mu.Lock()
	prev := m.current
	m.current = nil
	m.mu.Unlock()

	if prev == nil {
		storeEngine(&m.engine, nil)
		return nil
	}
	// Redirect the runtime's publish target so any last-in-flight
	// update does not write to our pointer after we clear it.
	prev.redirectTarget(&atomic.Pointer[policyengine.Engine]{})
	err := prev.stop()
	storeEngine(&m.engine, nil)
	return err
}

// Reconcile rebuilds the underlying runtime if snap's policy
// configuration differs from what the current runtime was built with.
// The manager's engine pointer is shared with the new runtime so
// existing consumers observe the new Engine automatically. If the
// rebuild fails, the old runtime is retained and an error is returned.
func (m *Manager) Reconcile(ctx context.Context, snap config.Snapshot) error {
	newArgs, err := argsFromSnapshot(snap)
	if err != nil {
		return fmt.Errorf("resolve policy source args: %w", err)
	}

	m.mu.Lock()
	if m.current != nil && m.current.args == newArgs {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	// Build the replacement runtime outside the lock (the
	// construction reads the policy file and may block briefly). The
	// new runtime shares this manager's engine pointer; on success,
	// downstream consumers see the fresh Engine automatically.
	next, err := startRuntime(ctx, snap, &m.engine)
	if err != nil {
		return fmt.Errorf("rebuild policy runtime: %w", err)
	}

	m.mu.Lock()
	prev := m.current
	m.current = next
	m.mu.Unlock()

	if prev != nil {
		// Redirect the old runtime's publish target to a throwaway
		// sink so any last-in-flight reload update does not clobber
		// the shared pointer that the new runtime has just populated.
		prev.redirectTarget(&atomic.Pointer[policyengine.Engine]{})
		if stopErr := prev.stop(); stopErr != nil {
			slog.Error("policy runtime shutdown error during reload", "error", stopErr)
		}
	}

	slog.Info("policy runtime rebuilt due to config change",
		"source", newArgs.PluginName,
		"engine", newArgs.EngineName,
		"path", newArgs.File.Path,
	)
	return nil
}

// argsFromSnapshot extracts the policyEngine and policySource blocks
// from snap and assembles a plugin.PolicySourceArgs. Schema
// validation has already enforced the required structural invariants
// (presence of `use`, required subblock fields); this function reads
// them and surfaces a clear error if anything is missing at runtime
// (defensive — not expected once the schema has passed).
func argsFromSnapshot(snap config.Snapshot) (plugin.PolicySourceArgs, error) {
	var args plugin.PolicySourceArgs

	engineBlock, ok := snap.Root.GetMap("policyEngine")
	if !ok {
		return args, errors.New("policyEngine block is required")
	}
	engineName, ok := engineBlock.GetString("use")
	if !ok || engineName == "" {
		return args, errors.New("policyEngine.use is required")
	}

	sourceBlock, ok := snap.Root.GetMap("policySource")
	if !ok {
		return args, errors.New("policySource block is required")
	}
	sourceName, ok := sourceBlock.GetString("use")
	if !ok || sourceName == "" {
		return args, errors.New("policySource.use is required")
	}

	args.EngineName = engineName
	args.PluginName = sourceName

	switch sourceName {
	case "file":
		fileBlock, ok := sourceBlock.GetMap("file")
		if !ok {
			return args, errors.New("policySource.file block is required when use=file")
		}
		path, ok := fileBlock.GetString("path")
		if !ok || path == "" {
			return args, errors.New("policySource.file.path is required")
		}
		args.File.Path = path
	case "inline":
		inlineBlock, ok := sourceBlock.GetMap("inline")
		if !ok {
			return args, errors.New("policySource.inline block is required when use=inline")
		}
		text, ok := inlineBlock.GetString("text")
		if !ok || text == "" {
			return args, errors.New("policySource.inline.text is required")
		}
		args.Inline.Text = text
	}

	return args, nil
}
