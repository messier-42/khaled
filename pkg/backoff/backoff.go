// Package backoff provides a reusable exponential-backoff helper with
// bounded growth and optional jitter. It is intended for retry loops.
//
// Usage sketch:
//
//	b := backoff.Config{Initial: 500 * time.Millisecond, Max: 30 * time.Second, Jitter: 0.25}.New()
//	for {
//	    err := connect(ctx)
//	    if err != nil {
//	        if !b.Wait(ctx) { return }  // sleep current delay, then advance
//	        continue
//	    }
//	    b.Reset()                       // success; next failure starts from Initial
//	    // ... consume connection until it drops ...
//	    if !b.WaitInitial(ctx) { return } // polite pause before reconnect
//	}
//
// A Backoff is not safe for concurrent use; construct one per retry loop.
package backoff

import (
	"context"
	"math/rand/v2"
	"time"
)

// Config holds the parameters that describe a Backoff's schedule.
//
// Initial is the delay used after the first failure and after Reset.
// Max caps the delay so repeated failures do not stretch into minutes
// or hours. Jitter is a non-negative fraction (e.g. 0.25 for ±25%)
// applied to every sleep; zero disables jitter and produces exact
// doubling.
type Config struct {
	Initial time.Duration
	Max     time.Duration
	Jitter  float64
}

// New returns a Backoff with its current delay set to c.Initial.
func (c Config) New() *Backoff {
	return &Backoff{cfg: c, current: c.Initial}
}

// Backoff tracks the current delay of an exponential-backoff schedule.
type Backoff struct {
	cfg     Config
	current time.Duration
}

// Reset restores the current delay to the configured Initial, e.g.
// after a successful operation so the next failure starts from the
// short delay rather than wherever the schedule had climbed to.
func (b *Backoff) Reset() {
	b.current = b.cfg.Initial
}

// Current returns the current delay *without* jitter. Primarily useful
// for logging ("next retry in ~X") so operators can see the schedule
// climbing; do not use this for sleeping since jitter is then skipped.
func (b *Backoff) Current() time.Duration {
	return b.current
}

// Wait sleeps for the current delay (with jitter applied) and then
// advances the schedule by doubling the current delay, clipped at Max.
// Returns false if ctx was cancelled before the sleep completed, in
// which case the caller should abort its retry loop.
func (b *Backoff) Wait(ctx context.Context) bool {
	if !sleepWithContext(ctx, jittered(b.current, b.cfg.Jitter)) {
		return false
	}
	b.advance()
	return true
}

// WaitInitial sleeps for the Initial delay (with jitter applied) and
// does NOT advance the schedule. Use this for the short "polite pause"
// between a successful long-lived connection dropping and the next
// attempt, where you don't want to count the drop as a failure.
func (b *Backoff) WaitInitial(ctx context.Context) bool {
	return sleepWithContext(ctx, jittered(b.cfg.Initial, b.cfg.Jitter))
}

func (b *Backoff) advance() {
	b.current *= 2
	if b.current > b.cfg.Max {
		b.current = b.cfg.Max
	}
}

// jittered adds a uniform-random ± jitter fraction to d. A jitter of
// 0 returns d unchanged.
func jittered(d time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return d
	}
	delta := float64(d) * jitter
	// rand.Float64 is in [0,1); map to (-delta, +delta).
	adj := (rand.Float64()*2 - 1) * delta
	return d + time.Duration(adj)
}

// sleepWithContext sleeps for d or until ctx is cancelled, whichever
// comes first. Returns true if the full d elapsed, false if ctx was
// cancelled first.
func sleepWithContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
