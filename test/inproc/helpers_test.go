//go:build integration

package inproc

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/ckap"
)

// describeError unwraps err to a *ckap.Error if possible and returns
// a verbose, single-line description suitable for t.Fatalf. Falls
// back to err.Error() when err is not a *ckap.Error.
func describeError(err error) string {
	if err == nil {
		return "<nil>"
	}
	var cerr *ckap.Error
	if errors.As(err, &cerr) {
		return fmt.Sprintf("code=%d op=%q summary=%q details=%v underlying=%v",
			cerr.Code, cerr.Op, cerr.Summary, cerr.Details, cerr.Err)
	}
	return err.Error()
}

// waitFor polls cond every interval up to timeout. Returns true the
// moment cond returns true; returns false on timeout. Used by
// reload tests where the post-reload state becomes observable
// asynchronously: the in-process reload loop reconciles in the
// background, and a poll-and-retry pattern is more honest than a
// fixed sleep.
func waitFor(t *testing.T, timeout time.Duration, interval time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(interval)
	}
	return cond()
}
