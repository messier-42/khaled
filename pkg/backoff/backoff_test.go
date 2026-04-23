package backoff

import (
	"context"
	"testing"
	"time"
)

func TestWaitAdvancesAndCapsAtMax(t *testing.T) {
	b := Config{
		Initial: 1 * time.Millisecond,
		Max:     8 * time.Millisecond,
		Jitter:  0,
	}.New()

	want := []int{2, 4, 8, 8, 8}
	for i, w := range want {
		if !b.Wait(context.Background()) {
			t.Fatalf("iter %d: Wait returned false unexpectedly", i)
		}
		wantDur := time.Duration(w) * time.Millisecond
		if got := b.Current(); got != wantDur {
			t.Errorf("iter %d: Current = %v, want %v", i, got, wantDur)
		}
	}
}

func TestResetRestoresInitial(t *testing.T) {
	b := Config{
		Initial: 1 * time.Millisecond,
		Max:     8 * time.Millisecond,
		Jitter:  0,
	}.New()

	// Climb a few steps.
	for range 3 {
		if !b.Wait(context.Background()) {
			t.Fatal("Wait returned false")
		}
	}
	if b.Current() == 1*time.Millisecond {
		t.Fatal("precondition failed: Current is still Initial after 3 Waits")
	}

	b.Reset()
	if got, want := b.Current(), 1*time.Millisecond; got != want {
		t.Errorf("after Reset: Current = %v, want %v", got, want)
	}
}

func TestWaitReturnsFalseOnContextCancel(t *testing.T) {
	b := Config{
		Initial: 10 * time.Second,
		Max:     time.Minute,
		Jitter:  0,
	}.New()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if b.Wait(ctx) {
		t.Fatal("Wait returned true on cancelled context")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("Wait blocked for %v after cancel; should return promptly", elapsed)
	}

	// The schedule must NOT advance when Wait aborts early; otherwise
	// a shutdown that happens mid-retry would permanently shift the
	// next run's schedule forward.
	if got, want := b.Current(), 10*time.Second; got != want {
		t.Errorf("Current = %v after cancelled Wait, want %v (schedule should not advance)", got, want)
	}
}

func TestWaitInitialDoesNotAdvance(t *testing.T) {
	b := Config{
		Initial: 1 * time.Millisecond,
		Max:     8 * time.Millisecond,
		Jitter:  0,
	}.New()

	// Climb first.
	for range 2 {
		if !b.Wait(context.Background()) {
			t.Fatal("Wait returned false")
		}
	}
	before := b.Current()

	if !b.WaitInitial(context.Background()) {
		t.Fatal("WaitInitial returned false")
	}
	if got := b.Current(); got != before {
		t.Errorf("WaitInitial advanced schedule: Current = %v, want %v", got, before)
	}
}

func TestJitterStaysWithinBounds(t *testing.T) {
	// A non-zero jitter must land in [d*(1-j), d*(1+j)]. Sample enough
	// draws to catch a mis-scaled formula (e.g. ±2*j or ±j/2).
	const d = 100 * time.Millisecond
	const j = 0.25
	lo := time.Duration(float64(d) * (1 - j))
	hi := time.Duration(float64(d) * (1 + j))

	for range 1000 {
		got := jittered(d, j)
		if got < lo || got > hi {
			t.Fatalf("jittered(%v, %v) = %v; outside [%v, %v]", d, j, got, lo, hi)
		}
	}
}

func TestJitterZeroIsIdentity(t *testing.T) {
	const d = 100 * time.Millisecond
	for range 100 {
		if got := jittered(d, 0); got != d {
			t.Fatalf("jittered(%v, 0) = %v; want %v", d, got, d)
		}
	}
}
