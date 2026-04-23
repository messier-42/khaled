package kutest

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/types"
)

// bailAndKeepState wires the KUTEST_BAIL_AND_KEEP=1 escape hatch:
// when set, the first failing integration test marks the run as
// failed; subsequent tests are skipped and helper Finish funcs are
// no-ops, so the cluster stays up for kubectl-based debugging.
//
// Ported from qhx-core's kutest.
type bailAndKeepState struct {
	enabled bool

	integrationFailed atomic.Bool

	mu             sync.Mutex
	kubeconfigPath string
}

var integrationBailAndKeep = newBailAndKeepStateFromEnv(os.Getenv)

func newBailAndKeepStateFromEnv(getenv func(string) string) *bailAndKeepState {
	return &bailAndKeepState{enabled: getenv("KUTEST_BAIL_AND_KEEP") == "1"}
}

func (s *bailAndKeepState) setKubeconfigPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.kubeconfigPath = path
}

func (s *bailAndKeepState) shouldRunIntegrationTest() bool {
	if !s.enabled {
		return true
	}
	return !s.integrationFailed.Load()
}

func (s *bailAndKeepState) shouldSkipCleanup() bool {
	if !s.enabled {
		return false
	}
	// In bail-and-keep mode, always skip cleanup. Originally this
	// gated on integrationFailed (only skip on test failure), but
	// setup-time failures (helm install, kind cluster bringup) are
	// the most common case where you actually need the cluster
	// kept alive for kubectl debugging — and those happen before
	// any test runs, so integrationFailed is always false.
	return true
}

func (s *bailAndKeepState) markIntegrationFailure() {
	if !s.enabled {
		return
	}
	if s.integrationFailed.CompareAndSwap(false, true) {
		fmt.Fprintln(os.Stderr, formatBailAndKeepDebugMessage(s.currentKubeconfigPath()))
	}
}

func (s *bailAndKeepState) currentKubeconfigPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kubeconfigPath
}

func formatBailAndKeepDebugMessage(kubeconfigPath string) string {
	return fmt.Sprintf("Use KUBECONFIG=%s kubectl to debug against the live cluster.", kubeconfigPath)
}

// kutestEnvironment wraps env.Environment to plumb bail-and-keep
// through the Test method: a failing test in bail mode marks the
// run failed and short-circuits subsequent tests with t.Skip.
type kutestEnvironment struct {
	env.Environment

	bail *bailAndKeepState
}

func newKutestEnvironment(base env.Environment, bail *bailAndKeepState) *kutestEnvironment {
	if bail == nil {
		bail = &bailAndKeepState{}
	}
	return &kutestEnvironment{Environment: base, bail: bail}
}

func (e *kutestEnvironment) Test(t *testing.T, features ...types.Feature) context.Context {
	t.Helper()
	if !e.bail.shouldRunIntegrationTest() {
		t.Skip("skipping due to an earlier failed integration test in KUTEST_BAIL_AND_KEEP mode")
		return context.Background()
	}
	ctx := e.Environment.Test(t, features...)
	if t.Failed() {
		e.bail.markIntegrationFailure()
	}
	return ctx
}
