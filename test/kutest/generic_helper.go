package kutest

import (
	"context"

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// GenericHelper wraps two env.Func closures so a one-off lifecycle
// hook (e.g. apply a manifest, wait for a CRD) can be added inline to
// the helper chain without writing a dedicated type.
//
// Ported from qhx-core's kutest.
type GenericHelper struct {
	description string
	setupFunc   env.Func
	finishFunc  env.Func
}

var _ Helper = &GenericHelper{}

func NewGenericHelper(description string, setup, finish env.Func) *GenericHelper {
	return &GenericHelper{description: description, setupFunc: setup, finishFunc: finish}
}

func (ch *GenericHelper) String() string  { return ch.description }
func (ch *GenericHelper) Setup() env.Func { return ch.setupFunc }
func (ch *GenericHelper) Finish() env.Func {
	if ch.finishFunc != nil {
		return ch.finishFunc
	}
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) { return ctx, nil }
}
