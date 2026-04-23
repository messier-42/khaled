package kutest

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	log "k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

// KhaledHelper installs the in-tree khaled Helm chart against the
// running kind cluster, registers a ClusterSPIFFEID so the SPIRE
// controller-manager issues an SVID to the khaled pod, and waits for
// the StatefulSet to come up. The chart's values are overridden so
// the image reference matches the preloaded OCI archive's recorded
// ref (the chart's defaults point at a registry the test cluster
// cannot reach).
type KhaledHelperConfig struct {
	// ChartPath points at the packaged chart .tgz produced by
	// `make chart` (or, if empty, falls back to the in-tree source
	// directory chart/khaled).
	ChartPath string
	// ImageRef is the OCI ref recorded in the preloaded khaled.oci
	// archive; the chart's image.repository and image.tag are set
	// from this so the StatefulSet pulls the in-cluster image
	// rather than an external registry.
	ImageRef string
	// SPIFFEID is the URI the controller-manager will issue to khaled
	// pods via ClusterSPIFFEID. Defaults to spiffe://<trust>/khaled
	// when empty.
	SPIFFEID string
	// ClaimsMappingMode selects between the two ClaimsMapping plugins
	// the chart can render: "static" (the chart default — wildcard
	// principal echoing back whatever URI the authn plugin produced)
	// or "k8s-attestation" (resolves the cabetool pod's identity
	// against the k8s API and derives namespace/SA/labels claims).
	// Empty means "static".
	//
	// k8s-attestation mode also flips rbac.podRead.enabled=true so
	// the khaled SA gets the cluster-wide pod-read RBAC the plugin
	// requires.
	ClaimsMappingMode string
	// PolicyText, if non-empty, overrides the chart's default
	// permit-all Cedar policy. Tests use this to install a policy
	// that distinguishes principal claims (for k8s-attestation
	// Features) or that flips between permit/deny for ConfigSource
	// reload Features.
	PolicyText string
}

type KhaledHelper struct {
	cfg        KhaledHelperConfig
	didInstall bool
}

var _ Helper = &KhaledHelper{}

func NewKhaledHelper(cfg KhaledHelperConfig) *KhaledHelper {
	if cfg.SPIFFEID == "" {
		cfg.SPIFFEID = "spiffe://" + SpireTrustDomain + "/khaled"
	}
	return &KhaledHelper{cfg: cfg}
}

func (ch *KhaledHelper) String() string { return "Install khaled via helm chart" }

const (
	khaledReleaseName = "khaled"
	KhaledNamespace   = "default"
	khaledReadyTimeout = 3 * time.Minute
)

func (ch *KhaledHelper) Setup() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if ch.cfg.ChartPath == "" {
			return ctx, fmt.Errorf("khaled helper: ChartPath is required")
		}
		if ch.cfg.ImageRef == "" {
			return ctx, fmt.Errorf("khaled helper: ImageRef is required")
		}

		// The preloaded image's recorded ref looks like
		// `oci.messier42.com/cabe/khaled:dev` — split into repo/tag
		// to satisfy the chart's image.repository / image.tag values.
		repo, tag, err := splitImageRef(ch.cfg.ImageRef)
		if err != nil {
			return ctx, err
		}

		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}

		// Register the ClusterSPIFFEID before the StatefulSet starts:
		// the controller-manager reconciles policies on a short
		// interval, but if khaled's first SPIFFE bootstrap attempt
		// races the entry creation, the pod's spiffeBootstrapTimeout
		// (30s) trips. Better to pay the registration latency now.
		if err := applyClusterSPIFFEID(ctx, client, "khaled", ch.cfg.SPIFFEID, KhaledNamespace, "khaled"); err != nil {
			return ctx, fmt.Errorf("apply ClusterSPIFFEID for khaled: %w", err)
		}

		hm := helm.New(cfg.KubeconfigFile())
		args := []string{
			"--set", "image.registry=",
			"--set", "image.repository=" + repo,
			"--set", "image.tag=" + tag,
			"--set", "image.pullPolicy=Never",
		}
		// Cedar policy text contains characters helm's --set parser
		// mangles (`,`, `=`, `[`, etc), so anything that needs custom
		// nested values goes through a scratch values.yaml passed via
		// --values. Build that lazily; if neither knob is set the
		// install runs entirely from chart defaults plus the four
		// --set image flags.
		valuesOverlay := map[string]any{}
		if ch.cfg.ClaimsMappingMode == "k8s-attestation" {
			// The k8s-attestation plugin requires the SA to be able
			// to GET pods cluster-wide. The chart guards that RBAC
			// behind rbac.podRead.enabled to avoid handing out
			// cluster-scoped privileges by default — flip it here
			// when the Feature asks for the attestation mapper.
			valuesOverlay["rbac"] = map[string]any{"podRead": map[string]any{"enabled": true}}
			valuesOverlay["config"] = map[string]any{
				"claimsMapping": map[string]any{"use": "k8s-attestation"},
			}
		}
		if ch.cfg.PolicyText != "" {
			valuesOverlay["policyText"] = ch.cfg.PolicyText
		}
		var overlayPath string
		if len(valuesOverlay) > 0 {
			data, err := yaml.Marshal(valuesOverlay)
			if err != nil {
				return ctx, fmt.Errorf("marshal helm values overlay: %w", err)
			}
			f, err := os.CreateTemp("", "khaled-values-*.yaml")
			if err != nil {
				return ctx, fmt.Errorf("create helm values overlay tempfile: %w", err)
			}
			if _, werr := f.Write(data); werr != nil {
				_ = f.Close()
				return ctx, fmt.Errorf("write helm values overlay: %w", werr)
			}
			if cerr := f.Close(); cerr != nil {
				return ctx, fmt.Errorf("close helm values overlay: %w", cerr)
			}
			overlayPath = f.Name()
			// Tempfile is cleaned up after the install completes; helm
			// only reads it during RunInstall. Remove on the way out
			// regardless of install success/failure.
			defer func() { _ = os.Remove(overlayPath) }()
			args = append(args, "--values", overlayPath)
		}
		log.V(0).InfoS("Installing khaled via helm",
			"chart", ch.cfg.ChartPath,
			"image", ch.cfg.ImageRef,
			"spiffeID", ch.cfg.SPIFFEID,
			"claimsMappingMode", ch.cfg.ClaimsMappingMode,
			"valuesOverlay", overlayPath,
		)
		if err := hm.RunInstall(
			helm.WithName(khaledReleaseName),
			helm.WithNamespace(KhaledNamespace),
			helm.WithChart(ch.cfg.ChartPath),
			helm.WithArgs(args...),
			helm.WithWait(),
			helm.WithTimeout(khaledReadyTimeout.String()),
		); err != nil {
			return ctx, fmt.Errorf("helm install khaled: %w", err)
		}
		ch.didInstall = true

		log.V(0).InfoS("Waiting for khaled StatefulSet to be Ready", "timeout", khaledReadyTimeout)
		if err := waitStatefulSetReady(ctx, client, KhaledNamespace, "khaled", khaledReadyTimeout); err != nil {
			return ctx, fmt.Errorf("khaled StatefulSet not ready: %w", err)
		}
		log.V(0).InfoS("khaled installation complete")
		return ctx, nil
	}
}

func (ch *KhaledHelper) Finish() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if !ch.didInstall {
			return ctx, nil
		}
		hm := helm.New(cfg.KubeconfigFile())
		log.V(0).InfoS("Uninstalling khaled")
		if err := hm.RunUninstall(
			helm.WithName(khaledReleaseName),
			helm.WithNamespace(KhaledNamespace),
		); err != nil {
			log.V(0).ErrorS(err, "helm uninstall khaled failed (continuing)")
		}
		return ctx, nil
	}
}

// splitImageRef separates a repo:tag string into its parts. Treats
// the substring after the final colon (if not part of a port number
// in the registry hostname) as the tag.
func splitImageRef(ref string) (string, string, error) {
	i := strings.LastIndex(ref, ":")
	if i < 0 {
		return "", "", fmt.Errorf("image ref %q has no tag", ref)
	}
	// Handle "registry:port/repo" with no tag — last colon would be
	// part of the port. Detect by checking for a slash after the colon.
	if strings.Contains(ref[i+1:], "/") {
		return "", "", fmt.Errorf("image ref %q has no tag", ref)
	}
	return ref[:i], ref[i+1:], nil
}

// applyClusterSPIFFEID creates a ClusterSPIFFEID CRD that the SPIRE
// controller-manager reconciles into a SPIRE entry. Selects pods by
// (namespace, app.kubernetes.io/name) so it matches both the chart's
// labelling and the cabetool helper's. Idempotent: the already-exists
// case is treated as success.
//
// className must match the controller-manager instance reconciling
// the resource — the SPIRE chart names its instance "spire-system-spire"
// and only ClusterSPIFFEIDs carrying that className are picked up.
// Without it the resource is silently orphaned and SPIRE falls back
// to the bundled default (`spiffe://<trust>/ns/<ns>/sa/<sa>`).
func applyClusterSPIFFEID(ctx context.Context, client klient.Client, name, spiffeIDTemplate, namespace, appName string) error {
	gvr := schema.GroupVersionResource{
		Group:    "spire.spiffe.io",
		Version:  "v1alpha1",
		Resource: "clusterspiffeids",
	}
	obj := &unstructured.Unstructured{}
	obj.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   gvr.Group,
		Version: gvr.Version,
		Kind:    "ClusterSPIFFEID",
	})
	obj.SetName(name)
	if err := unstructured.SetNestedField(obj.Object, spireControllerClassName, "spec", "className"); err != nil {
		return err
	}
	if err := unstructured.SetNestedField(obj.Object, spiffeIDTemplate, "spec", "spiffeIDTemplate"); err != nil {
		return err
	}
	if err := unstructured.SetNestedMap(obj.Object,
		map[string]interface{}{
			"matchLabels": map[string]interface{}{
				"kubernetes.io/metadata.name": namespace,
			},
		}, "spec", "namespaceSelector",
	); err != nil {
		return err
	}
	if err := unstructured.SetNestedMap(obj.Object,
		map[string]interface{}{
			"matchLabels": map[string]interface{}{
				"app.kubernetes.io/name": appName,
			},
		}, "spec", "podSelector",
	); err != nil {
		return err
	}
	if err := client.Resources().Create(ctx, obj); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

// waitStatefulSetReady polls a StatefulSet until ReadyReplicas
// matches Spec.Replicas (and ObservedGeneration is current).
func waitStatefulSetReady(ctx context.Context, client klient.Client, namespace, name string, timeout time.Duration) error {
	ss := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}
	return wait.For(conditions.New(client.Resources(namespace)).ResourceMatch(ss, func(obj k8s.Object) bool {
		got := obj.(*appsv1.StatefulSet)
		if got.Status.ObservedGeneration < got.Generation {
			return false
		}
		desired := int32(1)
		if got.Spec.Replicas != nil {
			desired = *got.Spec.Replicas
		}
		return got.Status.ReadyReplicas == desired
	}), wait.WithTimeout(timeout))
}
