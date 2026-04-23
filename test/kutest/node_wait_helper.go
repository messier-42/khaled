package kutest

import (
	"context"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	log "k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// NodeWaitHelper blocks until every node in the cluster reports
// Ready=True. Required after KindHelper because subsequent helpers
// (preloader, helm install) need a scheduler that will actually
// place pods.
//
// Ported from qhx-core's kutest.
type NodeWaitHelper struct{}

var _ Helper = &NodeWaitHelper{}

func NewNodeWaitHelper() *NodeWaitHelper { return &NodeWaitHelper{} }

func (ch *NodeWaitHelper) String() string { return "Wait for nodes to be ready" }

func (ch *NodeWaitHelper) Setup() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return nil, err
		}

		var nodeList corev1.NodeList
		if err := client.Resources().List(ctx, &nodeList); err != nil {
			return nil, err
		}

		names := make([]string, 0, len(nodeList.Items))
		for _, n := range nodeList.Items {
			names = append(names, n.Name)
		}
		log.V(2).InfoS("Waiting for all nodes to be ready", "nodeNames", strings.Join(names, ","))

		ready := map[string]bool{}
		for _, node := range nodeList.Items {
			err := wait.For(conditions.New(client.Resources()).ResourceMatch(&node, func(obj k8s.Object) bool {
				n := obj.(*corev1.Node)
				for _, c := range n.Status.Conditions {
					if c.Type == "Ready" && c.Status == "True" {
						if !ready[n.Name] {
							ready[n.Name] = true
							log.V(2).InfoS("Node is now ready", "nodeName", n.Name)
						}
						return true
					}
				}
				return false
			}), wait.WithTimeout(2*time.Minute))
			if err != nil {
				return nil, err
			}
		}
		return ctx, nil
	}
}

func (ch *NodeWaitHelper) Finish() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) { return ctx, nil }
}
