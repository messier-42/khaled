package server

import (
	"testing"

	"github.com/messier-42/khaled/pkg/health"
	"github.com/messier-42/khaled/pkg/subsystems/keyserversub"
	"github.com/messier-42/khaled/pkg/subsystems/spiffesub"
	"github.com/messier-42/khaled/pkg/subsystems/transportsub"
)

// findCheck returns the result with the given name, or a zero
// CheckResult if absent.
func findCheck(results []health.CheckResult, name string) health.CheckResult {
	for _, r := range results {
		if r.Name == name {
			return r
		}
	}
	return health.CheckResult{}
}

func TestReadyFuncBeforeStartupNotReady(t *testing.T) {
	// A Server with no handles published — the state during early
	// startup — must report every subsystem as "not started" rather
	// than panic.
	s := &Server{}
	results := s.readyFunc()
	if health.AllOK(results) {
		t.Fatalf("readyFunc should not be ready before startup; got %+v", results)
	}
	for _, name := range []string{"spiffe-source", "keyserver", "transports"} {
		c := findCheck(results, name)
		if c.OK {
			t.Errorf("check %q should be failing before startup", name)
		}
		if c.Detail != "not started" {
			t.Errorf("check %q detail = %q, want \"not started\"", name, c.Detail)
		}
	}
}

func TestReadyFuncShuttingDownShortCircuits(t *testing.T) {
	// Even with healthy subsystems, once shuttingDown is set /readyz
	// must report 503 so Kubernetes drains the pod.
	s := &Server{}
	s.spiffeSrc.Store(spiffesub.NewEmpty())
	s.transports.Store(transportsub.NewEmpty())
	s.keyserverMgr.Store(keyserversub.NewEmpty())

	s.shuttingDown.Store(true)
	results := s.readyFunc()
	if health.AllOK(results) {
		t.Fatalf("readyFunc should report not-ready while shutting down")
	}
	if c := findCheck(results, "shutdown"); c.OK || c.Detail != "shutdown in progress" {
		t.Errorf("expected a failing \"shutdown\" check, got %+v", results)
	}
}

func TestReadyFuncExcludesAuthnAndClaims(t *testing.T) {
	// authn and claims keep last-known-good across reloads and are
	// deliberately not part of readiness.
	s := &Server{}
	results := s.readyFunc()
	for _, name := range []string{"authn", "claims", "claims-mapper", "authenticator"} {
		if c := findCheck(results, name); c.Name != "" {
			t.Errorf("readiness should not include a %q check", name)
		}
	}
}

func TestCheckSPIFFENilSourceIsReady(t *testing.T) {
	// An empty SPIFFE manager (no SPIFFE configured) has a nil
	// Current and is trivially ready — there is nothing to be
	// un-ready.
	s := &Server{}
	s.spiffeSrc.Store(spiffesub.NewEmpty())
	if c := s.checkSPIFFE(); !c.OK {
		t.Errorf("SPIFFE check with no source configured should be ready, got %+v", c)
	}
}

func TestCheckKeyserverEmptyManagerNotReady(t *testing.T) {
	// An empty keyserver manager has no Stack; the stack is not
	// healthy, so the check fails.
	s := &Server{}
	s.keyserverMgr.Store(keyserversub.NewEmpty())
	if c := s.checkKeyserver(); c.OK {
		t.Errorf("keyserver check with no stack should fail, got %+v", c)
	}
}

func TestCheckTransportsEmptyIsReady(t *testing.T) {
	// An empty transport set has no un-bound listeners.
	s := &Server{}
	s.transports.Store(transportsub.NewEmpty())
	if c := s.checkTransports(); !c.OK {
		t.Errorf("transports check with no listeners should be ready, got %+v", c)
	}
}
