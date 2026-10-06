package lifecycle_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/lifecycle"
)

const fakeComponentName = "fake"

type fakeArgs struct {
	Name string
	Knob int
}

type fakePlugin struct {
	name     string
	closed   atomic.Bool
	closeErr error
}

func (p *fakePlugin) Close() error {
	p.closed.Store(true)
	return p.closeErr
}

// parseSnap is the "per-subsystem" parse; lifecycle no longer owns it.
func parseSnap(snap config.Snapshot) fakeArgs {
	m, _ := snap.Root.GetMap(fakeComponentName)
	name, _ := m.GetString("name")
	knob := 0
	if knobV, _ := m.Get("knob"); knobV != nil {
		if n, ok := knobV.(int64); ok {
			knob = int(n)
		}
	}
	return fakeArgs{Name: name, Knob: knob}
}

// buildSpec returns a Spec whose Apply rebuilds on any args change
// (appending each construction to sink) and uninstalls when Name is
// empty. Callers can replace Apply for bespoke scenarios.
func buildSpec(t *testing.T, sink *[]*fakePlugin) lifecycle.Spec[*fakePlugin] {
	t.Helper()
	return lifecycle.Spec[*fakePlugin]{
		Name: fakeComponentName,
		Apply: func(_ context.Context, old *fakePlugin, oldSnap, newSnap config.Snapshot) (*fakePlugin, error) {
			newArgs := parseSnap(newSnap)
			if newArgs.Name == "" {
				return nil, nil
			}
			if old != nil && parseSnap(oldSnap) == newArgs {
				return old, nil
			}
			p := &fakePlugin{name: fmt.Sprintf("%s/%d", newArgs.Name, newArgs.Knob)}
			*sink = append(*sink, p)
			return p, nil
		},
		Close: func(p *fakePlugin) error { return p.Close() },
	}
}

func snap(name string, knob int) config.Snapshot {
	return config.Snapshot{Root: config.Map{
		fakeComponentName: config.Map{
			"name": name,
			"knob": int64(knob),
		},
	}}
}

func TestManager_StartBuildsCurrent(t *testing.T) {
	var built []*fakePlugin
	spec := buildSpec(t, &built)

	mgr, err := lifecycle.New(context.Background(), snap("one", 1), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	if got := mgr.Current(); got == nil || got.name != "one/1" {
		t.Fatalf("Current: got %v, want one/1", got)
	}
	if len(built) != 1 {
		t.Fatalf("built: got %d, want 1", len(built))
	}
}

func TestManager_StartEmptyArgsSkipsBuild(t *testing.T) {
	var built []*fakePlugin
	spec := buildSpec(t, &built)

	mgr, err := lifecycle.New(context.Background(), snap("", 0), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	if len(built) != 0 {
		t.Fatalf("Apply returning nil should not record a build; got %d", len(built))
	}
	if mgr.Current() != nil {
		t.Fatal("empty args should leave Current at zero")
	}
}

func TestManager_ReconcileNoOpWhenApplyReturnsOld(t *testing.T) {
	var built []*fakePlugin
	spec := buildSpec(t, &built)

	mgr, err := lifecycle.New(context.Background(), snap("one", 1), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	before := mgr.Current()
	if err := mgr.Reconcile(context.Background(), snap("one", 1)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if mgr.Current() != before {
		t.Fatal("Apply returning old should keep Current")
	}
	if before.closed.Load() {
		t.Fatal("Apply returning old should not Close prev")
	}
	if len(built) != 1 {
		t.Fatalf("expected 1 build, got %d", len(built))
	}
}

func TestManager_ReconcileRebuildsOnArgsChange(t *testing.T) {
	var built []*fakePlugin
	spec := buildSpec(t, &built)

	mgr, err := lifecycle.New(context.Background(), snap("one", 1), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	before := mgr.Current()
	if err := mgr.Reconcile(context.Background(), snap("two", 2)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	after := mgr.Current()
	if after == before {
		t.Fatal("args change should rebuild")
	}
	if !before.closed.Load() {
		t.Fatal("old plugin was not Closed on rebuild")
	}
	if after == nil || after.name != "two/2" {
		t.Fatalf("after rebuild: got %v, want two/2", after)
	}
}

func TestManager_StartPropagatesApplyError(t *testing.T) {
	boom := errors.New("boom")
	spec := lifecycle.Spec[*fakePlugin]{
		Name: fakeComponentName,
		Apply: func(context.Context, *fakePlugin, config.Snapshot, config.Snapshot) (*fakePlugin, error) {
			return nil, boom
		},
	}
	if _, err := lifecycle.New(context.Background(), snap("x", 1), spec); !errors.Is(err, boom) {
		t.Fatalf("Start err: got %v, want %v", err, boom)
	}
}

// TestManager_ReconcileApplyErrorRetainsOld verifies that when Apply
// returns an error from Reconcile, the previous instance and args
// remain committed.
func TestManager_ReconcileApplyErrorRetainsOld(t *testing.T) {
	var built []*fakePlugin
	boom := errors.New("apply-boom")
	failAfterFirst := false
	spec := lifecycle.Spec[*fakePlugin]{
		Name: fakeComponentName,
		Apply: func(_ context.Context, old *fakePlugin, _, newSnap config.Snapshot) (*fakePlugin, error) {
			if failAfterFirst {
				return nil, boom
			}
			p := &fakePlugin{name: parseSnap(newSnap).Name}
			built = append(built, p)
			return p, nil
		},
		Close: func(p *fakePlugin) error { return p.Close() },
	}

	mgr, err := lifecycle.New(context.Background(), snap("one", 1), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })
	before := mgr.Current()

	failAfterFirst = true
	if err := mgr.Reconcile(context.Background(), snap("two", 2)); !errors.Is(err, boom) {
		t.Fatalf("Reconcile err: got %v, want %v", err, boom)
	}
	if mgr.Current() != before {
		t.Fatal("rejected reconcile must not replace Current")
	}
	if before.closed.Load() {
		t.Fatal("rejected reconcile must not Close prev")
	}
}

func TestManager_ReconcileToEmptyUninstalls(t *testing.T) {
	var built []*fakePlugin
	spec := buildSpec(t, &built)

	mgr, err := lifecycle.New(context.Background(), snap("one", 1), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	prev := mgr.Current()
	if err := mgr.Reconcile(context.Background(), snap("", 0)); err != nil {
		t.Fatalf("Reconcile to empty: %v", err)
	}
	if mgr.Current() != nil {
		t.Fatal("Apply returning nil should clear Current")
	}
	if !prev.closed.Load() {
		t.Fatal("old plugin was not Closed on uninstall")
	}
}

func TestManager_StopClosesAndClears(t *testing.T) {
	var built []*fakePlugin
	spec := buildSpec(t, &built)

	mgr, err := lifecycle.New(context.Background(), snap("one", 1), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	prev := mgr.Current()
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if !prev.closed.Load() {
		t.Fatal("Stop did not Close the current plugin")
	}
	if mgr.Current() != nil {
		t.Fatal("Stop did not clear Current")
	}
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop (second): %v", err)
	}
}

func TestManager_StopPropagatesCloseError(t *testing.T) {
	var built []*fakePlugin
	spec := buildSpec(t, &built)

	mgr, err := lifecycle.New(context.Background(), snap("one", 1), spec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	boom := errors.New("close-boom")
	mgr.Current().closeErr = boom

	err = mgr.Stop()
	if !errors.Is(err, boom) {
		t.Fatalf("Stop err: got %v, want %v", err, boom)
	}
}

func TestManager_NewEmptyIsUsable(t *testing.T) {
	var built []*fakePlugin
	spec := buildSpec(t, &built)

	mgr := lifecycle.NewEmpty(spec)
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop on empty: %v", err)
	}
	if err := mgr.Reconcile(context.Background(), snap("one", 1)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if mgr.Current() == nil {
		t.Fatal("Reconcile on empty manager did not build")
	}
}

// TestManager_ApplyCanAbsorbReturnOld exercises the spiffesub-style
// bootstrap-only policy: Apply returns oldT to acknowledge newSnap
// without rebuilding.
func TestManager_ApplyCanAbsorbReturnOld(t *testing.T) {
	var built []*fakePlugin
	absorbSpec := lifecycle.Spec[*fakePlugin]{
		Name: fakeComponentName,
		Apply: func(_ context.Context, old *fakePlugin, _, newSnap config.Snapshot) (*fakePlugin, error) {
			if old != nil {
				return old, nil // absorb changes silently
			}
			args := parseSnap(newSnap)
			if args.Name == "" {
				return nil, nil
			}
			p := &fakePlugin{name: args.Name}
			built = append(built, p)
			return p, nil
		},
		Close: func(p *fakePlugin) error { return p.Close() },
	}

	mgr, err := lifecycle.New(context.Background(), snap("one", 1), absorbSpec)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	before := mgr.Current()
	if err := mgr.Reconcile(context.Background(), snap("two", 2)); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if mgr.Current() != before {
		t.Fatal("Apply returning old should keep Current")
	}
	if before.closed.Load() {
		t.Fatal("absorb path must not Close old")
	}
	if len(built) != 1 {
		t.Fatalf("absorb path must not Build again: built=%d", len(built))
	}
}
