package kutest

import (
	"context"
	"os"

	log "k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// ScratchDirHelper provisions a per-run temp directory other helpers
// can scribble files into (kind config YAML, rendered manifests, etc.).
// Reachable from inside any helper or test via GetScratchDir(ctx).
//
// Ported from qhx-core's kutest.
type ScratchDirHelper struct {
	path string
}

var _ Helper = &ScratchDirHelper{}

type scratchDirKey struct{}

func NewScratchDirHelper() *ScratchDirHelper { return &ScratchDirHelper{} }

func (ch *ScratchDirHelper) String() string { return "Create scratch directory" }

func (ch *ScratchDirHelper) Setup() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		dir, err := os.MkdirTemp("", "khaled-kutest-*")
		if err != nil {
			return nil, err
		}
		ch.path = dir
		log.V(2).InfoS("Created scratch directory", "path", dir)
		return context.WithValue(ctx, scratchDirKey{}, dir), nil
	}
}

func GetScratchDir(ctx context.Context) string {
	v, _ := ctx.Value(scratchDirKey{}).(string)
	return v
}

func (ch *ScratchDirHelper) Finish() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		// Intentionally leave the scratch directory on disk: when a
		// test fails, the rendered configs and kind manifest in here
		// are the first thing a developer wants to inspect. The OS
		// reaps /tmp on its own schedule.
		log.V(2).InfoS("Scratch directory left in place for inspection", "path", ch.path)
		return ctx, nil
	}
}
