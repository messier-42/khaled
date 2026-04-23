package kutest

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	log "k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"
)

// KindHelper boots a fresh kind cluster for the duration of the test
// run. Single control-plane node — the workload is small and SPIRE's
// agent DaemonSet runs on the control-plane too via standard
// tolerations.
//
// Ported from qhx-core's kutest with minor edits (single node, no CNI
// override; kindnet suffices for in-cluster pod-to-pod and the SPIFFE
// CSI driver only requires kubelet socket access).
type KindHelper struct {
	clusterName string
}

var _ Helper = &KindHelper{}

func NewKindHelper() *KindHelper { return &KindHelper{} }

func (ch *KindHelper) String() string { return "Setup cluster using kind" }

// kindNodeImage is pinned so CI rebuilds reproduce against the same
// Kubernetes version. Bump deliberately when validating against newer
// kubelet/control-plane behaviour.
const kindNodeImage = "kindest/node:v1.34.0"

func (ch *KindHelper) Setup() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		scratchDir := GetScratchDir(ctx)
		if scratchDir == "" {
			return nil, errors.New("kind helper: no scratch dir in context (did ScratchDirHelper run first?)")
		}

		ch.clusterName = envconf.RandomName("khaled-kutest", 4)

		kindConfigPath := filepath.Join(scratchDir, "kind-config.yaml")
		kindConfigText := `apiVersion: kind.x-k8s.io/v1alpha4
kind: Cluster
nodes:
  - role: control-plane
`
		log.V(2).InfoS("Writing kind config", "clusterName", ch.clusterName, "path", kindConfigPath)
		if err := os.WriteFile(kindConfigPath, []byte(kindConfigText), 0o644); err != nil {
			return nil, fmt.Errorf("write kind-config.yaml: %w", err)
		}

		setup := envfuncs.CreateClusterWithConfig(
			kind.NewProvider(),
			ch.clusterName,
			kindConfigPath,
			kind.WithImage(kindNodeImage),
		)
		return setup(ctx, cfg)
	}
}

func (ch *KindHelper) Finish() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		log.V(2).InfoS("Tearing down kind cluster", "clusterName", ch.clusterName)
		exportLogs := envfuncs.ExportClusterLogs(ch.clusterName, "./logs")
		teardown := envfuncs.DestroyCluster(ch.clusterName)

		ctx2, err := exportLogs(ctx, cfg)
		if err != nil {
			return ctx, err
		}
		return teardown(ctx2, cfg)
	}
}
