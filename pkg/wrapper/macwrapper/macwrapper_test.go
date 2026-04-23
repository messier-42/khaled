package macwrapper_test

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/plugin/keystorage/disk"
	"github.com/messier-42/khaled/pkg/wrapper/macwrapper"
)

func newWrapper(t *testing.T) (*macwrapper.Wrapper, keystorage.KeyStoreDomain) {
	t.Helper()
	ctx := context.Background()
	store, err := disk.New(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("disk.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d, err := store.DomainByName(ctx, "default")
	if err != nil {
		t.Fatalf("Domain: %v", err)
	}
	w, err := macwrapper.New(d)
	if err != nil {
		t.Fatalf("macwrapper.New: %v", err)
	}
	return w, d
}

func TestWrap_RoundTrip(t *testing.T) {
	ctx := context.Background()
	w, _ := newWrapper(t)

	plaintext := []byte("hello world")
	aad := []byte("attrset-repr")
	wrapped, err := w.Wrap(ctx, plaintext, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	got, err := w.Unwrap(ctx, wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %x, want %x", got, plaintext)
	}
}

func TestUnwrap_RejectsTampered(t *testing.T) {
	ctx := context.Background()
	w, _ := newWrapper(t)
	wrapped, err := w.Wrap(ctx, []byte("x"), []byte("a"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	wrapped[len(wrapped)-1] ^= 0x01
	if _, err := w.Unwrap(ctx, wrapped, []byte("a")); err == nil {
		t.Fatal("tampered ref accepted")
	}
}

func TestUnwrap_RejectsWrongAAD(t *testing.T) {
	ctx := context.Background()
	w, _ := newWrapper(t)
	wrapped, err := w.Wrap(ctx, []byte("x"), []byte("aad-a"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := w.Unwrap(ctx, wrapped, []byte("aad-b")); err == nil {
		t.Fatal("wrong AAD accepted")
	}
}

func TestUnwrap_RejectsShort(t *testing.T) {
	ctx := context.Background()
	w, _ := newWrapper(t)
	if _, err := w.Unwrap(ctx, []byte{0x00}, nil); err == nil {
		t.Fatal("too-short ref accepted")
	}
}

func TestWrap_SurvivesRootRotation(t *testing.T) {
	ctx := context.Background()
	w, d := newWrapper(t)

	plaintext := []byte("pre-rotation")
	aad := []byte("aad")
	wrapped, err := w.Wrap(ctx, plaintext, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	cur, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	if _, err := d.RotateRootKey(ctx, cur); err != nil {
		t.Fatalf("RotateRootKey: %v", err)
	}
	got, err := w.Unwrap(ctx, wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap post-rotation: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %x, want %x", got, plaintext)
	}
}

// TestWrap_SurvivesCacheEviction forces more than cacheSize (16) root
// rotations and verifies that a ref minted under a long-retired root
// still verifies after its MAC key has been evicted from the cache
// (which means it must be re-derived on Unwrap).
func TestWrap_SurvivesCacheEviction(t *testing.T) {
	ctx := context.Background()
	w, d := newWrapper(t)

	plaintext := []byte("ancient")
	aad := []byte("aad")
	wrapped, err := w.Wrap(ctx, plaintext, aad)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Rotate 20 times so the original root's MAC key is evicted from
	// the LRU cache (cap is 16). The filler Wrap below keeps the new
	// root hotter than the original on each iteration, so LRU will
	// evict the original.
	for i := range 20 {
		cur, err := d.CurrentRootKey(ctx)
		if err != nil {
			t.Fatalf("CurrentRootKey(iter %d): %v", i, err)
		}
		if _, err := d.RotateRootKey(ctx, cur); err != nil {
			t.Fatalf("RotateRootKey(iter %d): %v", i, err)
		}
		// Force the new root's MAC key into the cache so it takes a
		// slot. Wrap() uses the current root.
		if _, err := w.Wrap(ctx, []byte("filler"), nil); err != nil {
			t.Fatalf("Wrap filler(iter %d): %v", i, err)
		}
	}

	got, err := w.Unwrap(ctx, wrapped, aad)
	if err != nil {
		t.Fatalf("Unwrap after eviction: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %x, want %x", got, plaintext)
	}
}

// TestConcurrent_WrapUnwrapWithRotations exercises the concurrency
// contract documented on Wrapper: concurrent Wrap/Unwrap while roots
// rotate and MAC keys are evicted from the LRU cache must not race.
// Intended to be run under `go test -race`.
func TestConcurrent_WrapUnwrapWithRotations(t *testing.T) {
	ctx := context.Background()
	w, d := newWrapper(t)

	const workers = 16
	const opsPerWorker = 100

	var wg sync.WaitGroup
	errs := make(chan error, workers+1)

	// Rotator goroutine: rotate many times to force cache eviction.
	wg.Go(func() {
		for range 30 {
			cur, err := d.CurrentRootKey(ctx)
			if err != nil {
				errs <- err
				return
			}
			if _, err := d.RotateRootKey(ctx, cur); err != nil {
				errs <- err
				return
			}
		}
	})

	aad := []byte("aad")
	for range workers {
		wg.Go(func() {
			for range opsPerWorker {
				plaintext := []byte("msg")
				wrapped, err := w.Wrap(ctx, plaintext, aad)
				if err != nil {
					errs <- err
					return
				}
				got, err := w.Unwrap(ctx, wrapped, aad)
				if err != nil {
					errs <- err
					return
				}
				if !bytes.Equal(got, plaintext) {
					errs <- &unexpectedBytesError{got: got, want: plaintext}
					return
				}
			}
		})
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("worker: %v", err)
	}
}

type unexpectedBytesError struct{ got, want []byte }

func (e *unexpectedBytesError) Error() string {
	return "round-trip mismatch"
}

func TestNew_NilDomain(t *testing.T) {
	if _, err := macwrapper.New(nil); err == nil {
		t.Fatal("nil domain accepted")
	}
}
