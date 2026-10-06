package keyserversub

import (
	"context"
	"testing"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/keyserver"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// stubPolicyEngine implements policyengine.Engine and also
// keyserver.PolicySource. Used by Start tests to avoid standing up a
// real Cedar engine.
type stubPolicyEngine struct{}

func (stubPolicyEngine) DecideEncapsulate(_ context.Context, _ policyengine.EncapsulateRequest) (policyengine.Decision, error) {
	return policyengine.Decision{Allow: true}, nil
}
func (stubPolicyEngine) DecideDecapsulate(_ context.Context, _ policyengine.DecapsulateRequest) (policyengine.Decision, error) {
	return policyengine.Decision{Allow: true}, nil
}
func (stubPolicyEngine) Close() error                { return nil }
func (stubPolicyEngine) Engine() policyengine.Engine { return stubPolicyEngine{} }

func snapshotForKeyStorage(dir string) config.Snapshot {
	return config.Snapshot{Root: config.Map{
		"keyStorage": config.Map{
			"use":  "disk",
			"disk": config.Map{"path": dir},
		},
	}}
}

func TestStart_MintsALease(t *testing.T) {
	snap := snapshotForKeyStorage(t.TempDir())

	mgr, err := New(context.Background(), snap, stubPolicyEngine{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	srv := mgr.Current().Server()
	if srv == nil {
		t.Fatal("holder returned nil server")
	}
	as, err := attrset.New(map[string]any{"sensitivity": "secret"})
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}
	resp, err := srv.Prograde(context.Background(), keyserver.ProgradeRequest{
		Principal:    policyengine.Principal{URI: "spiffe://test/alice"},
		AttributeSet: as,
	})
	if err != nil {
		t.Fatalf("Prograde: %v", err)
	}
	if resp.Lease.LKAI.NonCaptive == nil || len(resp.Lease.LKAI.NonCaptive.LeaseKey[-1].([]byte)) != 32 {
		t.Fatal("expected 32-byte non-captive LeaseKey")
	}
}

func TestStart_ReconcileNoOpOnSameConfig(t *testing.T) {
	snap := snapshotForKeyStorage(t.TempDir())

	mgr, err := New(context.Background(), snap, stubPolicyEngine{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	before := mgr.Current().Server()
	if err := mgr.Reconcile(context.Background(), snap); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	after := mgr.Current().Server()
	if before != after {
		t.Fatal("Reconcile with unchanged args rebuilt the server")
	}
}

func TestStart_ReconcileRebuildsOnPathChange(t *testing.T) {
	snap1 := snapshotForKeyStorage(t.TempDir())
	mgr, err := New(context.Background(), snap1, stubPolicyEngine{})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Stop() })

	before := mgr.Current().Server()
	snap2 := snapshotForKeyStorage(t.TempDir())
	if err := mgr.Reconcile(context.Background(), snap2); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	after := mgr.Current().Server()
	if before == after {
		t.Fatal("Reconcile with changed path did not rebuild the server")
	}
}

func TestStart_RequiresKeyStorageBlock(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{}}
	if _, err := New(context.Background(), snap, stubPolicyEngine{}); err == nil {
		t.Fatal("Start accepted empty snapshot")
	}
}

func TestStart_RejectsUnknownPlugin(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"keyStorage": config.Map{"use": "nonesuch"},
	}}
	if _, err := New(context.Background(), snap, stubPolicyEngine{}); err == nil {
		t.Fatal("Start accepted unknown plugin")
	}
}
