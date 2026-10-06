package policysub

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

const (
	pluginSelector  = "use"
	policyEngineKey = "policyEngine"
	cedarEngine     = "cedar"
	fileSource      = "file"
	inlineSource    = "inline"
	policySourceKey = "policySource"
)

func snapWithPolicy(t *testing.T, path string) config.Snapshot {
	t.Helper()
	snap, err := config.NewSnapshot(map[string]any{
		policyEngineKey: map[string]any{pluginSelector: cedarEngine},
		policySourceKey: map[string]any{
			pluginSelector: fileSource,
			fileSource:     map[string]any{"path": path},
		},
	})
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap
}

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.cedar")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

func TestArgsFromSnapshot_HappyPath(t *testing.T) {
	snap := snapWithPolicy(t, "/tmp/x")
	args, err := argsFromSnapshot(snap)
	if err != nil {
		t.Fatalf("args: %v", err)
	}
	if args.PluginName != fileSource || args.EngineName != cedarEngine || args.File.Path != "/tmp/x" {
		t.Errorf("unexpected args: %+v", args)
	}
}

func TestArgsFromSnapshot_MissingEngine(t *testing.T) {
	snap, _ := config.NewSnapshot(map[string]any{
		policySourceKey: map[string]any{pluginSelector: fileSource, fileSource: map[string]any{"path": "/x"}},
	})
	if _, err := argsFromSnapshot(snap); err == nil {
		t.Fatalf("expected error for missing policyEngine block")
	}
}

func TestArgsFromSnapshot_MissingSource(t *testing.T) {
	snap, _ := config.NewSnapshot(map[string]any{
		policyEngineKey: map[string]any{pluginSelector: cedarEngine},
	})
	if _, err := argsFromSnapshot(snap); err == nil {
		t.Fatalf("expected error for missing policySource block")
	}
}

func TestArgsFromSnapshot_MissingFilePath(t *testing.T) {
	snap, _ := config.NewSnapshot(map[string]any{
		policyEngineKey: map[string]any{pluginSelector: cedarEngine},
		policySourceKey: map[string]any{pluginSelector: fileSource, fileSource: map[string]any{}},
	})
	if _, err := argsFromSnapshot(snap); err == nil {
		t.Fatalf("expected error for missing file.path")
	}
}

func TestStart_EngineWorks(t *testing.T) {
	path := writePolicyFile(t, `permit(principal, action, resource);`)
	snap := snapWithPolicy(t, path)

	mgr, err := New(context.Background(), snap)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	eng := mgr.Engine()
	if eng == nil {
		t.Fatalf("engine empty after startup")
	}

	set, _ := attrset.New(nil)
	d, err := eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p"},
		AttributeSet: set,
	})
	if err != nil {
		t.Fatalf("DecideEncapsulate: %v", err)
	}
	if !d.Allow {
		t.Errorf("expected allow from permit-all policy")
	}
}

func TestStart_MissingFileSurfacedAsStartupError(t *testing.T) {
	snap := snapWithPolicy(t, filepath.Join(t.TempDir(), "missing.cedar"))
	if _, err := New(context.Background(), snap); err == nil {
		t.Fatalf("expected initial-load error")
	}
}

func TestStart_BadPolicySurfacedAsStartupError(t *testing.T) {
	path := writePolicyFile(t, "not cedar")
	snap := snapWithPolicy(t, path)
	_, err := New(context.Background(), snap)
	if err == nil {
		t.Fatalf("expected initial compile error")
	}
	if !strings.Contains(err.Error(), "initial policy load") {
		t.Errorf("expected initial-load wrap, got %v", err)
	}
}

func TestManager_ReconcileNoOpWhenArgsUnchanged(t *testing.T) {
	path := writePolicyFile(t, `permit(principal, action, resource);`)
	snap := snapWithPolicy(t, path)

	mgr, err := New(context.Background(), snap)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	engBefore := mgr.Engine()
	rtBefore := mgr.current

	if err := mgr.Reconcile(context.Background(), snap); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	engAfter := mgr.Engine()
	if engBefore != engAfter {
		t.Errorf("engine identity changed on no-op reconcile")
	}
	if mgr.current != rtBefore {
		t.Errorf("runtime was rebuilt on no-op reconcile")
	}
}

func TestManager_ReconcileRebuildsOnPathChange(t *testing.T) {
	path1 := writePolicyFile(t, `permit(principal, action, resource);`)
	path2 := writePolicyFile(t, `forbid(principal, action, resource);`)

	snap1 := snapWithPolicy(t, path1)
	snap2 := snapWithPolicy(t, path2)

	mgr, err := New(context.Background(), snap1)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	engBefore := mgr.Engine()
	rtBefore := mgr.current

	if err := mgr.Reconcile(context.Background(), snap2); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	engAfter := mgr.Engine()
	if engAfter == nil {
		t.Fatalf("engine empty after reconcile")
	}
	if engBefore == engAfter {
		t.Errorf("expected engine identity to change after path swap")
	}
	if mgr.current == rtBefore {
		t.Errorf("expected runtime to be rebuilt after path swap")
	}

	// Verify the new engine reflects the new policy (forbid-all).
	set, _ := attrset.New(nil)
	d, err := engAfter.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p"},
		AttributeSet: set,
	})
	if err != nil {
		t.Fatalf("DecideEncapsulate: %v", err)
	}
	if d.Allow {
		t.Errorf("expected deny from new policy, got allow")
	}
}

func TestManager_ReconcileFailureRetainsPrevious(t *testing.T) {
	path1 := writePolicyFile(t, `permit(principal, action, resource);`)
	snap1 := snapWithPolicy(t, path1)

	mgr, err := New(context.Background(), snap1)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	engBefore := mgr.Engine()
	rtBefore := mgr.current

	// Point at a missing file.
	snap2 := snapWithPolicy(t, filepath.Join(t.TempDir(), "nope.cedar"))
	if err := mgr.Reconcile(context.Background(), snap2); err == nil {
		t.Fatalf("expected reconcile error")
	}

	engAfter := mgr.Engine()
	if engAfter != engBefore {
		t.Errorf("failed reconcile changed the engine")
	}
	if mgr.current != rtBefore {
		t.Errorf("failed reconcile replaced the runtime")
	}
}

func TestManager_StopClearsEngine(t *testing.T) {
	path := writePolicyFile(t, `permit(principal, action, resource);`)
	snap := snapWithPolicy(t, path)

	mgr, err := New(context.Background(), snap)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	if mgr.Engine() == nil {
		t.Fatalf("engine empty before Stop")
	}
	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if mgr.Engine() != nil {
		t.Errorf("engine not cleared after Stop")
	}

	// Second Stop is a no-op.
	if err := mgr.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func snapWithInlinePolicy(t *testing.T, text string) config.Snapshot {
	t.Helper()
	snap, err := config.NewSnapshot(map[string]any{
		policyEngineKey: map[string]any{pluginSelector: cedarEngine},
		policySourceKey: map[string]any{
			pluginSelector: inlineSource,
			inlineSource:   map[string]any{"text": text},
		},
	})
	if err != nil {
		t.Fatalf("NewSnapshot: %v", err)
	}
	return snap
}

func TestArgsFromSnapshot_InlineHappyPath(t *testing.T) {
	snap := snapWithInlinePolicy(t, "permit(principal, action, resource);")
	args, err := argsFromSnapshot(snap)
	if err != nil {
		t.Fatalf("args: %v", err)
	}
	if args.PluginName != inlineSource || args.EngineName != cedarEngine {
		t.Errorf("unexpected args: %+v", args)
	}
	if args.Inline.Text != "permit(principal, action, resource);" {
		t.Errorf("unexpected inline text: %q", args.Inline.Text)
	}
}

func TestArgsFromSnapshot_InlineMissingText(t *testing.T) {
	snap, _ := config.NewSnapshot(map[string]any{
		policyEngineKey: map[string]any{pluginSelector: cedarEngine},
		policySourceKey: map[string]any{pluginSelector: inlineSource, inlineSource: map[string]any{}},
	})
	if _, err := argsFromSnapshot(snap); err == nil {
		t.Fatalf("expected error for missing inline.text")
	}
}

func TestManager_ReconcileRebuildsOnInlineTextChange(t *testing.T) {
	snap1 := snapWithInlinePolicy(t, "permit(principal, action, resource);")
	snap2 := snapWithInlinePolicy(t, "forbid(principal, action, resource);")

	mgr, err := New(context.Background(), snap1)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	engBefore := mgr.Engine()

	if err := mgr.Reconcile(context.Background(), snap2); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	engAfter := mgr.Engine()
	if engAfter == nil {
		t.Fatalf("engine empty after reconcile")
	}
	if engBefore == engAfter {
		t.Errorf("expected engine identity to change after inline text swap")
	}

	set, _ := attrset.New(nil)
	d, err := engAfter.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p"},
		AttributeSet: set,
	})
	if err != nil {
		t.Fatalf("DecideEncapsulate: %v", err)
	}
	if d.Allow {
		t.Errorf("expected deny from new inline policy, got allow")
	}
}

func TestManager_ReconcileNoOpWhenInlineTextUnchanged(t *testing.T) {
	snap := snapWithInlinePolicy(t, "permit(principal, action, resource);")

	mgr, err := New(context.Background(), snap)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	engBefore := mgr.Engine()
	rtBefore := mgr.current
	if err := mgr.Reconcile(context.Background(), snap); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if mgr.Engine() != engBefore {
		t.Errorf("engine identity changed on no-op inline reconcile")
	}
	if mgr.current != rtBefore {
		t.Errorf("runtime was rebuilt on no-op inline reconcile")
	}
}

func TestRuntime_PolicyFileChangeUpdatesHolder(t *testing.T) {
	path := writePolicyFile(t, `permit(principal, action, resource);`)
	snap := snapWithPolicy(t, path)

	mgr, err := New(context.Background(), snap)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	first := mgr.Engine()

	// Atomically replace the file with a new policy.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(`forbid(principal, action, resource);`), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// Wait for the manager to publish a different engine.
	deadline := time.Now().Add(3 * time.Second)
	var updated policyengine.Engine
	for time.Now().Before(deadline) {
		cur := mgr.Engine()
		if cur != nil && cur != first {
			updated = cur
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if updated == nil {
		t.Fatalf("manager did not publish the reloaded engine")
	}

	set, _ := attrset.New(nil)
	d, err := updated.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{
		Principal:    policyengine.Principal{URI: "p"},
		AttributeSet: set,
	})
	if err != nil {
		t.Fatalf("DecideEncapsulate: %v", err)
	}
	if d.Allow {
		t.Errorf("expected deny from reloaded policy, got allow")
	}
}
