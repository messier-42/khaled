package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/config"
)

// TestRunReloadLoop_PartialReconcileFailureContinuesChain pins the
// documented behaviour that a handler error does not stop the reload
// loop and does not short-circuit later handlers. A failure in h1 is
// logged (which we can't easily assert here without a capturing
// logger, so we just confirm the call counts) and h2 still runs.
func TestRunReloadLoop_PartialReconcileFailureContinuesChain(t *testing.T) {
	src := &fakeConfigSource{
		currentSnap: config.Snapshot{Root: config.Map{}},
		updates:     make(chan error, 1),
	}

	var h1Calls, h2Calls atomic.Int32
	h1 := func(_ context.Context, _ config.Snapshot) error {
		h1Calls.Add(1)
		return errors.New("simulated reconcile failure")
	}
	h2 := func(_ context.Context, _ config.Snapshot) error {
		h2Calls.Add(1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = runReloadLoop(ctx, src, defaultOptions(), h1, h2)
		close(done)
	}()

	// Drive a reload: h1 errors, h2 still runs.
	src.updates <- nil
	// Spin-wait briefly for both handlers to observe the snapshot.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h1Calls.Load() == 1 && h2Calls.Load() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if got := h1Calls.Load(); got != 1 {
		t.Errorf("h1 called %d times, want 1", got)
	}
	if got := h2Calls.Load(); got != 1 {
		t.Errorf("h2 called %d times, want 1 (handler error must not short-circuit subsequent handlers)", got)
	}
}

// TestRunReloadLoop_ShutdownInterleavedWithUpdate verifies that a
// reload arriving concurrently with context cancellation is handled
// cleanly: the loop exits, the handler may or may not run for the
// late update, and no goroutine is stranded. Designed to be run
// under `go test -race`.
func TestRunReloadLoop_ShutdownInterleavedWithUpdate(t *testing.T) {
	for i := range 20 {
		src := &fakeConfigSource{
			currentSnap: config.Snapshot{Root: config.Map{}},
			updates:     make(chan error, 1),
		}
		noop := func(_ context.Context, _ config.Snapshot) error { return nil }

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- runReloadLoop(ctx, src, defaultOptions(), noop) }()

		// Race: fire an update and cancel in parallel.
		go func() { src.updates <- nil }()
		cancel()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("iteration %d: runReloadLoop returned %v, want nil", i, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("iteration %d: runReloadLoop did not return after cancel", i)
		}
	}
}

// TestRunReloadLoop_InterHandlerCancelStopsChain complements the
// partial-failure test: when ctx is cancelled between handlers,
// subsequent handlers in the chain are NOT called (the ctx.Done
// check between handlers short-circuits the loop).
func TestRunReloadLoop_InterHandlerCancelStopsChain(t *testing.T) {
	src := &fakeConfigSource{
		currentSnap: config.Snapshot{Root: config.Map{}},
		updates:     make(chan error, 1),
	}

	var h1Calls, h2Calls atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())

	h1 := func(_ context.Context, _ config.Snapshot) error {
		h1Calls.Add(1)
		cancel() // simulate shutdown landing mid-chain
		return nil
	}
	h2 := func(_ context.Context, _ config.Snapshot) error {
		h2Calls.Add(1)
		return nil
	}

	done := make(chan struct{})
	go func() {
		_ = runReloadLoop(ctx, src, defaultOptions(), h1, h2)
		close(done)
	}()

	src.updates <- nil
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runReloadLoop did not return after mid-chain cancel")
	}

	if got := h1Calls.Load(); got != 1 {
		t.Errorf("h1 called %d times, want 1", got)
	}
	if got := h2Calls.Load(); got != 0 {
		t.Errorf("h2 called %d times, want 0 (ctx cancel between handlers must short-circuit)", got)
	}
}
