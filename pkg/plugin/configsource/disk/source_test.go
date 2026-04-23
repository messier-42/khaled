package disk_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin/configsource"
	"github.com/messier-42/khaled/pkg/plugin/configsource/disk"
)

var _ configsource.Source = (*disk.Source)(nil)

const (
	cedarEngine = "cedar"
	updatedUse  = "updated"
)

const cedarPolicyYAML = "policyEngine:\n  use: cedar\n"

func TestCurrentReturnsStartupErrorUntilFirstGoodConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("{\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	source, err := disk.New(path, nil)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
	})

	if _, err := source.Current(); err == nil {
		t.Fatalf("expected startup error before first good config")
	}

	if err := os.WriteFile(path, []byte(cedarPolicyYAML), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}

	waitForUpdate(t, source.UpdateChan(), nil)

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current after fix: %v", err)
	}

	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}

	if got, ok := policyEngine.GetString("use"); !ok || got != cedarEngine {
		t.Fatalf("unexpected policyEngine.use: got %q, ok=%v", got, ok)
	}
}

// TestOversizedConfigFileRejected verifies that a config file larger
// than the configured cap is rejected cleanly rather than read into
// memory. Defends against pointing khaled at /dev/zero or a similar
// unbounded source.
func TestOversizedConfigFileRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	// One byte past the 1 MiB cap.
	big := make([]byte, (1<<20)+1)
	for i := range big {
		big[i] = ' '
	}
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	source, err := disk.New(path, nil)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })

	_, err = source.Current()
	if err == nil {
		t.Fatal("expected oversized config to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds max") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

// TestYAMLWithUTF8HighByteNotMisdetectedAsCBOR pins the disk plugin's
// format-detection heuristic: a YAML document whose first byte is in
// the UTF-8 range 0xC0–0xDF must still be parsed as YAML, not
// misrouted to the CBOR decoder.
//
// Regression fence against an over-eager `looksLikeCBOR` heuristic:
// the stdlib CBOR major type for "tagged value" is 0b110 (0xC0–0xDF),
// which collides exactly with the two-byte UTF-8 lead-byte range.
// Any YAML file whose first meaningful character is a Latin Extended
// letter (ü, é, ñ, etc.) falls into that collision band; if the
// heuristic naively trusts `data[0] >> 5 == 6`, the file is routed
// to CBOR, decoding fails, and the operator gets a misleading
// "cannot decode as CBOR" error on a valid YAML file.
//
// The test uses a realistic case: a YAML map whose first key starts
// with "ü" (U+00FC, UTF-8 0xC3 0xBC). A future heuristic change
// (e.g. "CBOR iff starts with 0xBF or 0xA0–0xBF map indicator") that
// doesn't special-case UTF-8 would fail this test.
func TestYAMLWithUTF8HighByteNotMisdetectedAsCBOR(t *testing.T) {
	// "über-key: foo\nkeyStorage:\n  use: disk\n" — first byte 0xC3.
	doc := []byte("\xC3\xBCber-key: foo\nkeyStorage:\n  use: disk\n")
	if doc[0]>>5 != 0b110 {
		t.Fatalf("test fixture is no longer in the CBOR-tagged-value collision range; "+
			"first byte top-3 bits = %b, want 110", doc[0]>>5)
	}

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	source, err := disk.New(path, nil)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })

	snap, err := source.Current()
	if err != nil {
		t.Fatalf("Current: %v (YAML with UTF-8 high byte was misrouted as CBOR?)", err)
	}
	keyStorage, ok := snap.Root.GetMap("keyStorage")
	if !ok {
		t.Fatalf("keyStorage object missing from parsed snapshot")
	}
	if got, _ := keyStorage.GetString("use"); got != "disk" {
		t.Errorf("keyStorage.use = %q, want %q", got, "disk")
	}
}

func TestCurrentReturnsInitialGoodConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("keyStorage:\n  use: disk\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	source, err := disk.New(path, nil)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
	})

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current: %v", err)
	}

	keyStorage, ok := snapshot.Root.GetMap("keyStorage")
	if !ok {
		t.Fatalf("expected keyStorage object")
	}

	if got, ok := keyStorage.GetString("use"); !ok || got != "disk" {
		t.Fatalf("unexpected keyStorage.use: got %q, ok=%v", got, ok)
	}

	assertNoUpdate(t, source.UpdateChan())
}

func TestCurrentReturnsLastGoodConfigAfterInvalidUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cedarPolicyYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	source, err := disk.New(path, nil)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
	})

	if err := os.WriteFile(path, []byte("{\n"), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}

	waitForUpdateError(t, source.UpdateChan())

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current after invalid update: %v", err)
	}

	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}

	if got, ok := policyEngine.GetString("use"); !ok || got != cedarEngine {
		t.Fatalf("unexpected policyEngine.use: got %q, ok=%v", got, ok)
	}
}

// TestValidUpdateViaAtomicRenameReplacesCurrentConfig exercises the
// editor-save-by-atomic-rename pattern (write a sibling temp file,
// then rename(2) it over the watched path). Kubernetes Secret /
// ConfigMap volume mounts use this shape, as do most text editors.
// The directory-level fsnotify watcher picks up the Create event on
// the new inode.
func TestValidUpdateViaAtomicRenameReplacesCurrentConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(cedarPolicyYAML), 0o600); err != nil {
		t.Fatalf("write initial: %v", err)
	}

	source, err := disk.New(path, nil)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })

	// Write the replacement to a sibling file, then atomic-rename
	// into place. Sibling must be in the same directory (otherwise
	// rename is non-atomic across filesystems).
	tmp := filepath.Join(dir, "config.yaml.tmp")
	if err := os.WriteFile(tmp, []byte("policyEngine:\n  use: updated\n"), 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename: %v", err)
	}

	waitForUpdate(t, source.UpdateChan(), nil)

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	pe, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}
	if got, _ := pe.GetString("use"); got != updatedUse {
		t.Fatalf("policyEngine.use = %q, want updated", got)
	}
}

func TestValidUpdateReplacesCurrentConfigAndSignals(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.cbor")
	initial, err := cbor.Marshal(map[string]any{
		"policyEngine": map[string]any{"use": cedarEngine},
	})
	if err != nil {
		t.Fatalf("marshal initial cbor: %v", err)
	}
	if err := os.WriteFile(path, initial, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	source, err := disk.New(path, nil)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
	})

	updated, err := cbor.Marshal(map[string]any{
		"policyEngine": map[string]any{"use": updatedUse},
	})
	if err != nil {
		t.Fatalf("marshal updated cbor: %v", err)
	}
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}

	waitForUpdate(t, source.UpdateChan(), nil)

	snapshot, err := source.Current()
	if err != nil {
		t.Fatalf("current after update: %v", err)
	}

	policyEngine, ok := snapshot.Root.GetMap("policyEngine")
	if !ok {
		t.Fatalf("expected policyEngine object")
	}

	if got, ok := policyEngine.GetString("use"); !ok || got != updatedUse {
		t.Fatalf("unexpected policyEngine.use: got %q, ok=%v", got, ok)
	}
}

func TestStartupErrorUsesOnlyCBORDecoderForCBORLookingInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.bin")
	if err := os.WriteFile(path, []byte{0xa1}, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	source, err := disk.New(path, nil)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
	})

	_, err = source.Current()
	if err == nil {
		t.Fatalf("expected startup error")
	}

	if !strings.Contains(err.Error(), "as CBOR:") {
		t.Fatalf("expected CBOR error, got %v", err)
	}
	if strings.Contains(err.Error(), "as YAML:") {
		t.Fatalf("expected only CBOR decode path in error, got %v", err)
	}
}

func TestStartupErrorUsesOnlyYAMLDecoderForNonCBORLookingInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.txt")
	if err := os.WriteFile(path, []byte("["), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	source, err := disk.New(path, nil)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
	})

	_, err = source.Current()
	if err == nil {
		t.Fatalf("expected startup error")
	}

	if !strings.Contains(err.Error(), "as YAML:") {
		t.Fatalf("expected YAML error, got %v", err)
	}
	if strings.Contains(err.Error(), "as CBOR:") {
		t.Fatalf("expected only YAML decode path in error, got %v", err)
	}
}

func TestValidateFuncRejectingInitialLoadProducesStartupError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cedarPolicyYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	validate := func(_ context.Context, old *config.Snapshot, _ config.Snapshot) error {
		if old != nil {
			t.Fatalf("expected nil old snapshot on initial load, got %v", old)
		}
		return errors.New("nope")
	}

	source, err := disk.New(path, validate)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
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
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cedarPolicyYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var rejectReload atomic.Bool
	validate := func(_ context.Context, _ *config.Snapshot, _ config.Snapshot) error {
		if rejectReload.Load() {
			return errors.New("reload rejected")
		}
		return nil
	}

	source, err := disk.New(path, validate)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
	})

	rejectReload.Store(true)
	if err := os.WriteFile(path, []byte("policyEngine:\n  use: updated\n"), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}

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

func TestValidateFuncSeesOldSnapshotOnReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cedarPolicyYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	calls := make(chan validateCall, 2)
	validate := func(_ context.Context, old *config.Snapshot, snap config.Snapshot) error {
		newUse, _ := func() (string, bool) {
			pe, ok := snap.Root.GetMap("policyEngine")
			if !ok {
				return "", false
			}
			return pe.GetString("use")
		}()
		calls <- validateCall{oldPresent: old != nil, newUse: newUse}
		return nil
	}

	source, err := disk.New(path, validate)
	if err != nil {
		t.Fatalf("create source: %v", err)
	}
	t.Cleanup(func() {
		_ = source.Close()
	})

	first := mustRecv(t, calls)
	if first.oldPresent {
		t.Fatalf("expected nil old snapshot on initial load")
	}
	if first.newUse != cedarEngine {
		t.Fatalf("unexpected initial new use: %q", first.newUse)
	}

	if err := os.WriteFile(path, []byte("policyEngine:\n  use: updated\n"), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	waitForUpdate(t, source.UpdateChan(), nil)

	second := mustRecv(t, calls)
	if !second.oldPresent {
		t.Fatalf("expected non-nil old snapshot on reload")
	}
	if second.newUse != updatedUse {
		t.Fatalf("unexpected reload new use: %q", second.newUse)
	}
}

type validateCall struct {
	oldPresent bool
	newUse     string
}

func mustRecv(t *testing.T, ch <-chan validateCall) validateCall {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for validate call")
		return validateCall{}
	}
}

func waitForUpdate(t *testing.T, updates <-chan error, want error) {
	t.Helper()

	select {
	case got := <-updates:
		if !errors.Is(got, want) {
			t.Fatalf("unexpected update result: got %v want %v", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for config update")
	}
}

func waitForUpdateError(t *testing.T, updates <-chan error) {
	t.Helper()

	select {
	case got := <-updates:
		if got == nil {
			t.Fatalf("expected config reload error")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for config reload error")
	}
}

func assertNoUpdate(t *testing.T, updates <-chan error) {
	t.Helper()

	select {
	case got := <-updates:
		t.Fatalf("unexpected config update notification: %v", got)
	case <-time.After(500 * time.Millisecond):
	}
}
