package server

import (
	"github.com/messier-42/khaled/pkg/health"
)

const notStartedDetail = "not started"

// readyFunc builds the readiness check set for the /readyz endpoint.
//
// The returned closure captures the Server pointer, so it can be built
// once — before any subsystem has started — and passed to the
// monitoring listener, which is brought up first. Every manager handle
// it reads is nil until the corresponding subsystem starts; the closure
// is null-safe on each, reporting an un-started subsystem as a failing
// "not started" check. This is what makes /readyz informative during a
// slow startup.
//
// Readiness reflects whether the data plane can serve CKAP requests, not
// whether every config block is pristine. Subsystems that keep
// last-known-good across a failed reload — the authenticator and the
// claims mapper — are deliberately excluded: a bad authn config must not
// drain a pod that is still serving.
//
// Once Stop begins, the shuttingDown flag short-circuits every check so
// /readyz reports 503 throughout the drain regardless of subsystem
// state, letting Kubernetes deregister the pod.
func (s *Server) readyFunc() []health.CheckResult {
	if s.shuttingDown.Load() {
		return []health.CheckResult{
			{Name: "shutdown", OK: false, Detail: "shutdown in progress"},
		}
	}

	return []health.CheckResult{
		s.checkSPIFFE(),
		s.checkKeyserver(),
		s.checkTransports(),
	}
}

// checkSPIFFE reports the readiness of the shared SPIFFE source. When
// no SPIFFE source is configured the manager's Current is nil and the
// check passes trivially — there is nothing to be un-ready. When one is
// configured, it is ready once it has produced a usable certificate;
// GetCertificate is a cheap, non-blocking read of the current SVID.
func (s *Server) checkSPIFFE() health.CheckResult {
	const name = "spiffe-source"

	mgr := s.spiffeSrc.Load()
	if mgr == nil {
		return health.CheckResult{Name: name, OK: false, Detail: notStartedDetail}
	}
	src := mgr.Current()
	if src == nil {
		// No SPIFFE source required by this configuration.
		return health.CheckResult{Name: name, OK: true}
	}
	if _, err := src.GetCertificate(nil); err != nil {
		return health.CheckResult{Name: name, OK: false, Detail: "no certificate yet: " + err.Error()}
	}
	return health.CheckResult{Name: name, OK: true}
}

// checkKeyserver reports whether the keyserver stack — keystorage,
// schedule and server — is fully constructed. Stack.Healthy is a cheap,
// non-blocking read; see its doc comment for why it does no I/O.
func (s *Server) checkKeyserver() health.CheckResult {
	const name = "keyserver"

	mgr := s.keyserverMgr.Load()
	if mgr == nil {
		return health.CheckResult{Name: name, OK: false, Detail: notStartedDetail}
	}
	stack := mgr.Current()
	if !stack.Healthy() {
		return health.CheckResult{Name: name, OK: false, Detail: "keyserver stack not ready"}
	}
	return health.CheckResult{Name: name, OK: true}
}

// checkTransports reports whether every CKAP listener is bound.
func (s *Server) checkTransports() health.CheckResult {
	const name = "transports"

	tr := s.transports.Load()
	if tr == nil {
		return health.CheckResult{Name: name, OK: false, Detail: notStartedDetail}
	}
	if !tr.Ready() {
		return health.CheckResult{Name: name, OK: false, Detail: "a listener is not bound"}
	}
	return health.CheckResult{Name: name, OK: true}
}
