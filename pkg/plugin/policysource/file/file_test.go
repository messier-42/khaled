package file_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/plugin/policysource"
	"github.com/messier-42/khaled/pkg/plugin/policysource/file"
)

// stubEngine is a minimal policyengine.Engine used to assert engine
// identity and Close semantics without depending on any concrete engine.
type stubEngine struct {
	content string
	closed  atomic.Bool
}

func (e *stubEngine) DecideEncapsulate(_ context.Context, _ policyengine.EncapsulateRequest) (policyengine.Decision, error) {
	return policyengine.Decision{}, nil
}

func (e *stubEngine) DecideDecapsulate(_ context.Context, _ policyengine.DecapsulateRequest) (policyengine.Decision, error) {
	return policyengine.Decision{}, nil
}

func (e *stubEngine) Close() error {
	e.closed.Store(true)
	return nil
}

// stubCompile builds a stubEngine carrying the compiled bytes verbatim.
// If the bytes start with "BAD" the compile is treated as a syntax error.
func stubCompile(_ context.Context, args policysource.CompileArgs) (policyengine.Engine, error) {
	if len(args.Source) >= 3 && string(args.Source[:3]) == "BAD" {
		return nil, errors.New("stub: bad policy")
	}
	return &stubEngine{content: string(args.Source)}, nil
}

// writeFile writes data to path. For the initial pre-New setup, this
// runs before the watcher is active; for subsequent updates, prefer
// replaceFile so observers never see a mid-write empty file.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// replaceFile writes data to a sibling temp file and atomically renames
// it over path, so any fsnotify observer sees a single Rename event with
// the final content — never an intermediate truncated-empty state from
// O_TRUNC. Use this for updates after the Source is watching.
func replaceFile(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename: %v", err)
	}
}

func waitForUpdate(t *testing.T, ch <-chan error, want error) {
	t.Helper()
	select {
	case got := <-ch:
		if (got == nil) != (want == nil) {
			t.Fatalf("update: got %v, want %v", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for update")
	}
}

func waitForUpdateError(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case got := <-ch:
		if got == nil {
			t.Fatalf("expected reload error, got nil")
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for reload error")
	}
}

func assertNoUpdate(t *testing.T, ch <-chan error) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("unexpected update: %v", got)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestNew_RejectsNilCompile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.cedar")
	writeFile(t, path, []byte("ok"))
	if _, err := file.New(t.Context(), path, nil); err == nil {
		t.Fatalf("expected error for nil compile")
	}
}

func TestInitialLoadSuccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.cedar")
	writeFile(t, path, []byte("v1"))

	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	eng, err := src.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got := eng.(*stubEngine).content; got != "v1" {
		t.Errorf("engine content = %q, want v1", got)
	}
	assertNoUpdate(t, src.UpdateChan())
}

func TestInitialLoadMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.cedar")
	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if _, err := src.Current(); err == nil {
		t.Fatalf("expected initial-load error")
	}
}

func TestInitialCompileFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.cedar")
	writeFile(t, path, []byte("BAD-input"))

	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if _, err := src.Current(); err == nil {
		t.Fatalf("expected compile error on initial load")
	}
}

func TestRecoveryFromInitialError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.cedar")
	writeFile(t, path, []byte("BAD-input"))

	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if _, err := src.Current(); err == nil {
		t.Fatalf("expected startup error")
	}

	replaceFile(t, path, []byte("good"))
	waitForUpdate(t, src.UpdateChan(), nil)

	eng, err := src.Current()
	if err != nil {
		t.Fatalf("Current after recovery: %v", err)
	}
	if got := eng.(*stubEngine).content; got != "good" {
		t.Errorf("engine content = %q, want good", got)
	}
}

func TestReloadSwapsEngineAndClosesOld(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.cedar")
	writeFile(t, path, []byte("v1"))

	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	first, err := src.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	firstStub := first.(*stubEngine)

	replaceFile(t, path, []byte("v2"))
	waitForUpdate(t, src.UpdateChan(), nil)

	// Close of the old engine happens outside the lock, give it a
	// brief window to run.
	deadline := time.Now().Add(time.Second)
	for !firstStub.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !firstStub.closed.Load() {
		t.Errorf("previous engine was not closed on reload")
	}

	second, err := src.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if first == second {
		t.Errorf("engine identity did not change after reload")
	}
	if got := second.(*stubEngine).content; got != "v2" {
		t.Errorf("engine content = %q, want v2", got)
	}
}

func TestReloadFailureRetainsPrevious(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.cedar")
	writeFile(t, path, []byte("v1"))

	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	first, err := src.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}

	replaceFile(t, path, []byte("BAD-junk"))
	waitForUpdateError(t, src.UpdateChan())

	cur, err := src.Current()
	if err != nil {
		t.Fatalf("Current after failed reload: %v", err)
	}
	if cur != first {
		t.Errorf("engine identity changed on failed reload")
	}
	if first.(*stubEngine).closed.Load() {
		t.Errorf("previous engine was closed on failed reload")
	}
}

func TestAtomicReplaceTriggersReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.cedar")
	writeFile(t, path, []byte("v1"))

	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	// rename-into-place.
	tmp := filepath.Join(dir, "p.cedar.new")
	writeFile(t, tmp, []byte("v2"))
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename: %v", err)
	}
	waitForUpdate(t, src.UpdateChan(), nil)

	eng, err := src.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got := eng.(*stubEngine).content; got != "v2" {
		t.Errorf("content after rename = %q, want v2", got)
	}
}

func TestCloseIdempotentAndClosesCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.cedar")
	writeFile(t, path, []byte("v1"))

	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng, err := src.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	stub := eng.(*stubEngine)

	if err := src.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if !stub.closed.Load() {
		t.Errorf("current engine was not closed on Close")
	}
}

func TestConcurrentCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.cedar")
	writeFile(t, path, []byte("v1"))

	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 200 {
				if _, err := src.Current(); err != nil {
					t.Errorf("Current: %v", err)
					return
				}
			}
		})
	}
	wg.Wait()
}

// TestConcurrentReloadAndCurrent stresses the atomic-swap contract:
// many goroutines hammer Current() while a writer repeatedly
// replaces the policy file, and a reloader drains UpdateChan. Any
// torn read (seeing a half-swapped engine, or a Current that races
// with Close of the superseded engine) surfaces as an error or
// panic. Designed to be run under `go test -race`.
func TestConcurrentReloadAndCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.cedar")
	writeFile(t, path, []byte("v0"))

	src, err := file.New(t.Context(), path, stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	stopCh := make(chan struct{})
	var wg sync.WaitGroup

	// Reader goroutines: call Current in a tight loop.
	const readers = 8
	for range readers {
		wg.Go(func() {
			for {
				select {
				case <-stopCh:
					return
				default:
				}
				eng, err := src.Current()
				if err != nil {
					t.Errorf("Current: %v", err)
					return
				}
				// Exercise the engine as a live pointer so the
				// race detector flags use-after-Close if a reload
				// closed the engine we just read.
				_, _ = eng.DecideEncapsulate(context.Background(), policyengine.EncapsulateRequest{})
			}
		})
	}

	// Writer goroutine: replace the file with a new, valid policy
	// repeatedly. Uses atomic rename so fsnotify sees a clean
	// Rename and never an intermediate truncated state.
	wg.Go(func() {
		for i := 1; i <= 30; i++ {
			select {
			case <-stopCh:
				return
			default:
			}
			data := []byte("v" + itoa(i))
			replaceFile(t, path, data)
			time.Sleep(5 * time.Millisecond)
		}
	})

	// Drainer goroutine: consume UpdateChan so the source's
	// buffered channel does not fill (which would be harmless
	// given the coalescing semantic, but doing this keeps the
	// writer honest).
	wg.Go(func() {
		for {
			select {
			case <-stopCh:
				return
			case <-src.UpdateChan():
			}
		}
	})

	// Let the stress run briefly. 500 ms is comfortably long
	// enough for 30 rewrites and hundreds of thousands of reads
	// even on a slow CI box.
	time.Sleep(500 * time.Millisecond)
	close(stopCh)
	wg.Wait()
}

// itoa is a zero-alloc small-int-to-string helper; avoids pulling
// strconv into the _test.go imports.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
