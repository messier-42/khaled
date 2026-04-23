package k8s

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"github.com/messier-42/khaled/pkg/backoff"
	"github.com/messier-42/khaled/pkg/config"
)

const cedarEngine = "cedar"

func TestCurrentLoadsFromConfigMapYAMLData(t *testing.T) {
	client, watcher := newFakeClientWithWatch(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data: map[string]string{
			"khaled.yaml": "policyEngine:\n  use: cedar\n",
		},
	})

	source, err := newWithClient(context.Background(), client, "configmap/test-config", "test-ns", nil)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current: %v", err)
	}

	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}

	if got, ok := policyEngine.GetString("use"); !ok || got != cedarEngine {
		t.Fatalf("unexpected policyEngine.use: got %q, ok=%v", got, ok)
	}
}

func TestCurrentLoadsFromConfigMapBinaryCBOR(t *testing.T) {
	payload, err := cbor.Marshal(map[string]any{
		"policyEngine": map[string]any{"use": cedarEngine},
	})
	if err != nil {
		t.Fatalf("marshal cbor: %v", err)
	}

	client, watcher := newFakeClientWithWatch(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		BinaryData: map[string][]byte{
			"khaled.cbor": payload,
		},
	})

	source, err := newWithClient(context.Background(), client, "test-config", "test-ns", nil)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current: %v", err)
	}

	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}

	if got, ok := policyEngine.GetString("use"); !ok || got != cedarEngine {
		t.Fatalf("unexpected policyEngine.use: got %q, ok=%v", got, ok)
	}
}

func TestCurrentRejectsConfigMapWithMultipleConfigEntries(t *testing.T) {
	client, watcher := newFakeClientWithWatch(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data: map[string]string{
			"khaled.yaml": "policyEngine:\n  use: yaml\n",
		},
		BinaryData: map[string][]byte{
			"khaled.cbor": {0xa1},
		},
	})

	source, err := newWithClient(context.Background(), client, "test-config", "test-ns", nil)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	if _, err := source.Current(); err == nil {
		t.Fatalf("expected startup error")
	}
}

func TestCurrentKeepsLastGoodConfigAfterInvalidWatchUpdate(t *testing.T) {
	client, watcher := newFakeClientWithWatch(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data: map[string]string{
			"khaled.yaml": "policyEngine:\n  use: cedar\n",
		},
	})

	source, err := newWithClient(context.Background(), client, "test-config", "test-ns", nil)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	updated := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data: map[string]string{
			"khaled.yaml": "{\n",
		},
	}
	if err := client.Tracker().Update(configMapGVR(), updated, "test-ns"); err != nil {
		t.Fatalf("update tracker: %v", err)
	}
	watcher.Modify(updated)

	waitForUpdateError(t, source.UpdateChan())

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current: %v", err)
	}

	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}

	if got, ok := policyEngine.GetString("use"); !ok || got != cedarEngine {
		t.Fatalf("unexpected policyEngine.use: got %q, ok=%v", got, ok)
	}
}

func TestCurrentAppliesValidWatchUpdate(t *testing.T) {
	client, watcher := newFakeClientWithWatch(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data: map[string]string{
			"khaled.yaml": "policyEngine:\n  use: cedar\n",
		},
	})

	source, err := newWithClient(context.Background(), client, "test-config", "test-ns", nil)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	updated := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data: map[string]string{
			"khaled.yaml": "policyEngine:\n  use: updated\n",
		},
	}
	if err := client.Tracker().Update(configMapGVR(), updated, "test-ns"); err != nil {
		t.Fatalf("update tracker: %v", err)
	}
	watcher.Modify(updated)

	waitForUpdate(t, source.UpdateChan())

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current: %v", err)
	}

	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}

	if got, ok := policyEngine.GetString("use"); !ok || got != "updated" {
		t.Fatalf("unexpected policyEngine.use: got %q, ok=%v", got, ok)
	}
}

func TestValidateFuncRejectingInitialLoadProducesStartupError(t *testing.T) {
	client, watcher := newFakeClientWithWatch(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data: map[string]string{
			"khaled.yaml": "policyEngine:\n  use: cedar\n",
		},
	})

	validate := func(_ context.Context, old *config.Snapshot, _ config.Snapshot) error {
		if old != nil {
			t.Fatalf("expected nil old snapshot on initial load")
		}
		return errors.New("nope")
	}

	source, err := newWithClient(context.Background(), client, "configmap/test-config", "test-ns", validate)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	_, err = source.Current()
	if err == nil {
		t.Fatalf("expected startup error from validation")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestValidateFuncRejectingReloadKeepsLastGoodConfig(t *testing.T) {
	client, watcher := newFakeClientWithWatch(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data: map[string]string{
			"khaled.yaml": "policyEngine:\n  use: cedar\n",
		},
	})

	var rejectReload atomic.Bool
	validate := func(_ context.Context, _ *config.Snapshot, _ config.Snapshot) error {
		if rejectReload.Load() {
			return errors.New("reload rejected")
		}
		return nil
	}

	source, err := newWithClient(context.Background(), client, "configmap/test-config", "test-ns", validate)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	rejectReload.Store(true)
	updated := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data: map[string]string{
			"khaled.yaml": "policyEngine:\n  use: updated\n",
		},
	}
	if err := client.Tracker().Update(configMapGVR(), updated, "test-ns"); err != nil {
		t.Fatalf("update tracker: %v", err)
	}
	watcher.Modify(updated)

	waitForUpdateError(t, source.UpdateChan())

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current: %v", err)
	}
	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}
	if got, ok := policyEngine.GetString("use"); !ok || got != cedarEngine {
		t.Fatalf("unexpected policyEngine.use: got %q, ok=%v", got, ok)
	}
}

// TestWatchReconnectsAfterTransientError simulates a sequence of
// transient Watch API failures followed by a successful re-establish,
// verifying the watch goroutine backs off and retries rather than
// exiting permanently.
func TestWatchReconnectsAfterTransientError(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data:       map[string]string{"khaled.yaml": "policyEngine:\n  use: cedar\n"},
	})

	// First two Watch calls fail; subsequent calls return a working
	// FakeWatcher. Using PrependWatchReactor lets us count calls.
	var calls atomic.Int64
	watcher := watch.NewFake()
	client.PrependWatchReactor("configmaps", func(action kubetesting.Action) (bool, watch.Interface, error) {
		n := calls.Add(1)
		if n <= 2 {
			return true, nil, errors.New("simulated transient watch failure")
		}
		return true, watcher, nil
	})

	// Tight backoff so the test completes quickly. Passed directly to
	// the Source at construction so tests do not mutate shared state.
	source, err := newWithClientOpts(context.Background(), client, "configmap/test-config", "test-ns", nil, backoff.Config{
		Initial: 5 * time.Millisecond,
		Max:     20 * time.Millisecond,
		Jitter:  0,
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	// We expect two update-error signals (from the two failed Watch
	// attempts) on updateCh; drain them.
	for i := range 2 {
		select {
		case err := <-source.UpdateChan():
			if err == nil {
				t.Fatalf("update %d: expected error from failed watch", i)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("update %d: timed out waiting for watch error", i)
		}
	}

	// Now the third Watch call should have succeeded. Fire a modify
	// event and verify reload+update.
	updatedMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data:       map[string]string{"khaled.yaml": "policyEngine:\n  use: cedar-new\n"},
	}
	if _, err := client.CoreV1().ConfigMaps("test-ns").Update(context.Background(), updatedMap, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update configmap: %v", err)
	}
	watcher.Modify(updatedMap)
	waitForUpdate(t, source.UpdateChan())

	if got := calls.Load(); got < 3 {
		t.Fatalf("expected at least 3 Watch attempts, got %d", got)
	}
}

// TestInitialLoadFailsWhenConfigMapMissing pins the startup contract:
// if the configured ConfigMap does not exist at New time, Current()
// surfaces a diagnostic error rather than silently returning an
// empty Snapshot. Operators must see "configmap not found" so a
// typo in the configured name or namespace is caught at boot.
// A later Create of the ConfigMap should be picked up by the
// watch loop and Current() should start succeeding.
func TestInitialLoadFailsWhenConfigMapMissing(t *testing.T) {
	// No ConfigMap objects in the fake client — the Get will 404.
	client := fake.NewSimpleClientset()
	watcher := watch.NewFake()
	client.PrependWatchReactor("configmaps", func(action kubetesting.Action) (bool, watch.Interface, error) {
		return true, watcher, nil
	})

	source, err := newWithClient(context.Background(), client, "configmap/test-config", "test-ns", nil)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	_, err = source.Current()
	if err == nil {
		t.Fatal("expected startup error when ConfigMap is missing")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q; want a 'not found' diagnostic so the operator can tell typos from other failures", err.Error())
	}

	// Now create the ConfigMap; a watch Added event should drive a
	// reload and Current() should start succeeding.
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data:       map[string]string{"khaled.yaml": "policyEngine:\n  use: cedar\n"},
	}
	if _, err := client.CoreV1().ConfigMaps("test-ns").Create(context.Background(), cm, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create configmap: %v", err)
	}
	watcher.Add(cm)
	waitForUpdate(t, source.UpdateChan())

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("Current after create: %v", err)
	}
	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatal("policyEngine object missing from snapshot")
	}
	if got, _ := policyEngine.GetString("use"); got != cedarEngine {
		t.Errorf("policyEngine.use = %q, want %q", got, cedarEngine)
	}
}

// TestWatchBookmarkIgnored verifies that a watch.Bookmark event is
// treated as a heartbeat and does NOT trigger a reload or an update
// notification. Bookmark events carry an updated ResourceVersion but
// no content change; reloading on them would produce spurious
// "Current changed" notifications to downstream consumers and spend
// API-server round-trips for nothing.
func TestWatchBookmarkIgnored(t *testing.T) {
	client, watcher := newFakeClientWithWatch(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data:       map[string]string{"khaled.yaml": "policyEngine:\n  use: cedar\n"},
	})

	source, err := newWithClient(context.Background(), client, "configmap/test-config", "test-ns", nil)
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		watcher.Stop()
	})

	// Baseline: initial load must succeed.
	if _, err := source.Current(); err != nil {
		t.Fatalf("Current: %v", err)
	}

	// Emit a bookmark. An unchanged ConfigMap object (same data as
	// initial) is carried as the payload; the source should ignore
	// the event entirely.
	watcher.Action(watch.Bookmark, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns", ResourceVersion: "99"},
		Data:       map[string]string{"khaled.yaml": "policyEngine:\n  use: cedar\n"},
	})

	// No update notification should fire.
	select {
	case err := <-source.UpdateChan():
		t.Fatalf("bookmark event triggered an update (err=%v); must be ignored", err)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestWatchErrorTriggersReconnect verifies that a watch.Error event
// (e.g. HTTP 410 Gone on a stale ResourceVersion) drops the current
// watcher and causes the outer loop to re-establish a fresh watch.
// The reconnected watcher must pick up subsequent ConfigMap changes.
func TestWatchErrorTriggersReconnect(t *testing.T) {
	client := fake.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data:       map[string]string{"khaled.yaml": "policyEngine:\n  use: cedar\n"},
	})

	firstWatcher := watch.NewFake()
	secondWatcher := watch.NewFake()
	var calls atomic.Int64
	client.PrependWatchReactor("configmaps", func(action kubetesting.Action) (bool, watch.Interface, error) {
		n := calls.Add(1)
		if n == 1 {
			return true, firstWatcher, nil
		}
		return true, secondWatcher, nil
	})

	source, err := newWithClientOpts(context.Background(), client, "configmap/test-config", "test-ns", nil, backoff.Config{
		Initial: 5 * time.Millisecond,
		Max:     20 * time.Millisecond,
		Jitter:  0,
	})
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
		firstWatcher.Stop()
		secondWatcher.Stop()
	})

	// Emit an Error event on the first watcher. The payload for
	// watch.Error is conventionally *metav1.Status, but any runtime
	// object type is accepted by the fake.
	firstWatcher.Error(&metav1.Status{Status: "Failure", Reason: "Expired", Code: 410})

	// The reconnect must establish secondWatcher.
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("expected reconnect (at least 2 Watch calls); got %d", got)
	}

	// Verify the reconnected watcher drives reloads. Push a Modify
	// event through secondWatcher and assert the Source picks it up.
	updated := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "test-config", Namespace: "test-ns"},
		Data:       map[string]string{"khaled.yaml": "policyEngine:\n  use: cedar-new\n"},
	}
	if _, err := client.CoreV1().ConfigMaps("test-ns").Update(context.Background(), updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update configmap: %v", err)
	}
	secondWatcher.Modify(updated)
	waitForUpdate(t, source.UpdateChan())
}

func newFakeClientWithWatch(configMap *corev1.ConfigMap) (*fake.Clientset, *watch.FakeWatcher) {
	client := fake.NewSimpleClientset(configMap)
	watcher := watch.NewFake()
	client.PrependWatchReactor("configmaps", func(action kubetesting.Action) (bool, watch.Interface, error) {
		return true, watcher, nil
	})
	return client, watcher
}

func configMapGVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}
}

func waitForUpdate(t *testing.T, updates <-chan error) {
	t.Helper()
	select {
	case err := <-updates:
		if err != nil {
			t.Fatalf("expected successful update, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for update")
	}
}

func waitForUpdateError(t *testing.T, updates <-chan error) {
	t.Helper()
	select {
	case err := <-updates:
		if err == nil {
			t.Fatalf("expected update error")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for update error")
	}
}
