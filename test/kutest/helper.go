// Package kutest is khaled's kind-based multi-process integration test
// harness. The Helper interface and several of the generic helpers in
// this package are ported with attribution from qhx-core's kutest;
// khaled-specific helpers (SpireHelper, KhaledHelper, CabetoolHelper)
// are written fresh.
package kutest

import "sigs.k8s.io/e2e-framework/pkg/env"

// Helper is the lifecycle hook each step of the harness implements.
// Setup runs at TestMain bringup; Finish runs at teardown in reverse
// order. String is for human-readable progress logging.
type Helper interface {
	Setup() env.Func
	Finish() env.Func
	String() string
}
