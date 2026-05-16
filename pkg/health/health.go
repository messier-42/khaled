// Package health defines the shared vocabulary for khaled's readiness
// reporting: the [CheckResult] type produced by individual readiness
// checks and aggregated by the monitoring listener's /readyz endpoint.
//
// The package deliberately holds types only — no logic. The set of
// checks and the decision of what each one means is owned by
// pkg/server, which closes over its subsystem manager handles to
// derive the results. The monitoring listener (pkg/subsystems/
// monitoringsub) consumes a func() []CheckResult and renders it.
//
// This split keeps readiness semantics next to the subsystem state
// they depend on, while letting the listener stay a dumb renderer.
package health

// CheckResult is the outcome of one named readiness check.
type CheckResult struct {
	// Name is a stable identifier for the check, e.g. "keyserver".
	// It appears verbatim in /readyz?verbose output, so it should be
	// short, lowercase and free of spaces.
	Name string

	// OK reports whether the check passed.
	OK bool

	// Detail is an optional human-readable explanation. It is shown
	// in /readyz?verbose output for failing checks; for passing
	// checks it may be empty.
	Detail string
}

// AllOK reports whether every check in results passed. An empty
// slice is vacuously OK.
func AllOK(results []CheckResult) bool {
	for _, r := range results {
		if !r.OK {
			return false
		}
	}
	return true
}
