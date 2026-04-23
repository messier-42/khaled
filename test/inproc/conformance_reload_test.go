//go:build integration

package inproc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapclient"

	"github.com/messier-42/khaled/test/ktutil"
)

// progradeOnce performs a single Prograde call against client and
// returns the resulting *ckap.Error code (or zero on success).
// Helper for reload tests that need to repeatedly check whether the
// server's policy has switched in or out of permit.
func progradeOnce(t *testing.T, client *ckapclient.Client) (cabe.Code, error) {
	t.Helper()
	as, err := attrset.New(map[string]any{"env": "test"})
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = client.Prograde(ctx, ckap.ProgradeRequest{AttributeSet: as})
	if err == nil {
		return 0, nil
	}
	var cerr *ckap.Error
	if errors.As(err, &cerr) {
		return cerr.Code, err
	}
	return 0, err
}

// TestPolicyReload_SnapshotDriven exercises the harness's
// Reload(WithPolicy(...)) path: the test pushes a new snapshot
// through the in-memory config source, the reload loop reconciles
// the policy manager, and a subsequent Prograde sees the new policy
// take effect. This is the wire-level proof that the
// configsource.Source → RunReloadLoop → policyManager.Reconcile
// chain actually applies new policy without a server restart.
func TestPolicyReload_SnapshotDriven(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t) // permit-all
	client := srv.Client(t)

	// Baseline: Prograde succeeds under permit-all.
	if code, err := progradeOnce(t, client); err != nil {
		t.Fatalf("baseline Prograde: %s", describeError(err))
	} else if code != 0 {
		t.Fatalf("baseline Prograde: code=%d, want success", code)
	}

	// Reload with a deny-all policy. Reload returns once the
	// snapshot is queued; the Reconcile happens asynchronously.
	srv.Reload(t, khaledtest.WithPolicy("forbid(principal, action, resource);\n"))

	// Poll until the new policy takes effect or we time out. 2s is
	// generous for an in-process reload (the disk policy file write
	// + fsnotify event + Reconcile typically completes in single-
	// digit milliseconds), but tolerant of CI scheduling jitter.
	if !waitFor(t, 2*time.Second, 10*time.Millisecond, func() bool {
		code, _ := progradeOnce(t, client)
		return code == cabe.CodePolicyDenied
	}) {
		code, err := progradeOnce(t, client)
		t.Fatalf("policy reload did not take effect: code=%d err=%s",
			code, describeError(err))
	}
}

// TestPolicyReload_FileWatcher exercises the alternate reload path:
// the operator (or a CI/CD pipeline) overwrites the policy file on
// disk, the policysource.file plugin's fsnotify watcher fires, and
// the policyRuntime swaps the holder's Engine — all without going
// through the top-level config snapshot reload. This is the
// in-production reload path for Cedar policy edits.
func TestPolicyReload_FileWatcher(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	client := srv.Client(t)

	if code, err := progradeOnce(t, client); err != nil {
		t.Fatalf("baseline Prograde: %s", describeError(err))
	} else if code != 0 {
		t.Fatalf("baseline Prograde: code=%d, want success", code)
	}

	srv.WritePolicy(t, "forbid(principal, action, resource);\n")

	if !waitFor(t, 2*time.Second, 10*time.Millisecond, func() bool {
		code, _ := progradeOnce(t, client)
		return code == cabe.CodePolicyDenied
	}) {
		code, err := progradeOnce(t, client)
		t.Fatalf("policy file-watcher reload did not take effect: code=%d err=%s",
			code, describeError(err))
	}
}

// TestPolicyReload_InvalidPolicyKeepsOldConfig pins the
// reconciler's last-known-good guarantee: a reload that fails (here,
// because the new Cedar text is syntactically invalid) must NOT
// disrupt the running configuration. A subsequent Prograde must
// continue to succeed under the previous permit-all policy.
//
// This protects against a regression where a parse error during
// reload silently zeroes the policy holder, causing every request
// to be denied by the keyserver's deny-on-nil-engine fallback.
func TestPolicyReload_InvalidPolicyKeepsOldConfig(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	client := srv.Client(t)

	if code, err := progradeOnce(t, client); err != nil {
		t.Fatalf("baseline Prograde: %s", describeError(err))
	} else if code != 0 {
		t.Fatalf("baseline Prograde: code=%d, want success", code)
	}

	// Invalid Cedar — the parser rejects this; the file watcher
	// reports the error on the policysource.UpdateChan and the
	// runtime leaves the previous Engine in place.
	srv.WritePolicy(t, "this is not cedar policy syntax\n")

	// Wait long enough that any (mistaken) Reconcile would have
	// fired, then assert Prograde still succeeds. 200ms is well
	// above the typical fsnotify-to-Reconcile latency observed in
	// the snapshot-driven test above.
	time.Sleep(200 * time.Millisecond)

	if code, err := progradeOnce(t, client); err != nil {
		t.Fatalf("post-failed-reload Prograde: %s", describeError(err))
	} else if code != 0 {
		t.Fatalf("post-failed-reload Prograde: code=%d, want success (old config must be retained)", code)
	}
}
