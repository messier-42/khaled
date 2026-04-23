package kutest

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	log "k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/third_party/helm"
)

// SpireHelper installs SPIRE (server + agent + CSI driver +
// controller-manager) into the kind cluster via the upstream
// spiffe/spire Helm chart from the hardened-charts repo. The chart
// is the production-recommended deployment shape, so the test
// realistically exercises the SPIRE control plane khaled would see
// in a production cluster.
//
// Trust domain is fixed at "example.test"; SQLite datastore avoids
// needing an external database for tests.
type SpireHelper struct {
	didInstall     bool
	didInstallCRDs bool
}

var _ Helper = &SpireHelper{}

func NewSpireHelper() *SpireHelper { return &SpireHelper{} }

func (ch *SpireHelper) String() string { return "Install SPIRE via helm chart" }

const (
	spireRepoName    = "spiffe"
	spireRepoURL     = "https://spiffe.github.io/helm-charts-hardened/"
	spireChartName   = "spire"
	spireCRDsChart   = "spire-crds"
	spireCRDsRelease = "spire-crds"
	spireReleaseName = "spire"
	spireNamespace   = "spire-system"
	SpireTrustDomain = "example.test"

	// spireControllerClassName is the className the spire-controller-
	// manager instance shipped by the spire helm chart reconciles.
	// Custom ClusterSPIFFEIDs MUST carry this className or they are
	// silently orphaned and SPIRE falls back to the chart's bundled
	// default template (spiffe://<trust>/ns/<ns>/sa/<sa>).
	//
	// Naming follows the chart convention: <namespace>-<release-name>.
	spireControllerClassName = spireNamespace + "-" + spireReleaseName
	// spireBootstrapTimeout caps how long we wait for the SPIRE
	// agent DaemonSet to become Ready before declaring the helper
	// failed. Cold pull of the SPIRE images on a fresh cluster is
	// the long pole; observed at 60-120s in CI.
	spireBootstrapTimeout = 5 * time.Minute
)

// spireValues are the minimum --set knobs needed to install SPIRE
// for an integration test. Pulled into a constant so the inverse
// (uninstall) and any future per-test overrides can reference the
// same trust domain / namespace strings.
var spireValues = map[string]string{
	"global.spire.trustDomain": SpireTrustDomain,
	// We pre-create the spire-system namespace so that helm doesn't
	// try to claim/import it. Setting namespaces.create=false also
	// avoids the chart inserting Namespace resources into its own
	// manifest, which would conflict with our pre-creation.
	"global.spire.namespaces.create": "false",
	"spire-server.dataStore.type":    "sqlite",
	"spire-server.replicaCount":      "1",
}

func (ch *SpireHelper) Setup() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		hm := helm.New(cfg.KubeconfigFile())

		log.V(0).InfoS("Adding SPIRE helm repo", "repo", spireRepoURL)
		if err := hm.RunRepo(
			helm.WithArgs("add", spireRepoName, spireRepoURL),
		); err != nil {
			// `helm repo add` returns non-zero if the repo already
			// exists; that's harmless for our purposes.
			log.V(2).InfoS("helm repo add returned (may be already-exists)", "err", err)
		}
		if err := hm.RunRepo(helm.WithArgs("update")); err != nil {
			return ctx, fmt.Errorf("helm repo update: %w", err)
		}

		// Pre-create the namespace ourselves rather than letting
		// either helm release own it: spire-crds and spire share
		// the same namespace, and helm refuses to import a
		// namespace it didn't create.
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		if err := ensureNamespace(ctx, client, spireNamespace); err != nil {
			return ctx, fmt.Errorf("ensure namespace %q: %w", spireNamespace, err)
		}

		// SPIRE chart bootstrap requires CRDs (ClusterSPIFFEID etc.)
		// to be installed first. Upstream ships them as a separate
		// `spire-crds` chart; without this step the main chart's
		// install fails with "no matches for kind ClusterSPIFFEID".
		log.V(0).InfoS("Installing SPIRE CRDs via helm", "namespace", spireNamespace)
		if err := hm.RunInstall(
			helm.WithName(spireCRDsRelease),
			helm.WithNamespace(spireNamespace),
			helm.WithChart(spireRepoName+"/"+spireCRDsChart),
			helm.WithWait(),
			helm.WithTimeout(spireBootstrapTimeout.String()),
		); err != nil {
			return ctx, fmt.Errorf("helm install spire-crds: %w", err)
		}
		ch.didInstallCRDs = true

		args := []string{}
		for k, v := range spireValues {
			args = append(args, "--set", fmt.Sprintf("%s=%s", k, v))
		}

		log.V(0).InfoS("Installing SPIRE via helm", "namespace", spireNamespace, "trustDomain", SpireTrustDomain)
		if err := hm.RunInstall(
			helm.WithName(spireReleaseName),
			helm.WithNamespace(spireNamespace),
			helm.WithChart(spireRepoName+"/"+spireChartName),
			helm.WithArgs(args...),
			helm.WithWait(),
			helm.WithTimeout(spireBootstrapTimeout.String()),
		); err != nil {
			return ctx, fmt.Errorf("helm install spire: %w", err)
		}
		ch.didInstall = true

		log.V(0).InfoS("Waiting for spire-agent DaemonSet to be Ready", "timeout", spireBootstrapTimeout)
		if err := waitDaemonSetReady(ctx, client, spireNamespace, "spire-agent", spireBootstrapTimeout); err != nil {
			return ctx, fmt.Errorf("spire-agent not ready: %w", err)
		}
		log.V(0).InfoS("SPIRE installation complete")
		return ctx, nil
	}
}

func (ch *SpireHelper) Finish() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		hm := helm.New(cfg.KubeconfigFile())
		if ch.didInstall {
			log.V(0).InfoS("Uninstalling SPIRE")
			if err := hm.RunUninstall(
				helm.WithName(spireReleaseName),
				helm.WithNamespace(spireNamespace),
			); err != nil {
				log.V(0).ErrorS(err, "helm uninstall spire failed (continuing)")
			}
		}
		if ch.didInstallCRDs {
			log.V(0).InfoS("Uninstalling SPIRE CRDs")
			if err := hm.RunUninstall(
				helm.WithName(spireCRDsRelease),
				helm.WithNamespace(spireNamespace),
			); err != nil {
				log.V(0).ErrorS(err, "helm uninstall spire-crds failed (continuing)")
			}
		}
		return ctx, nil
	}
}

// ensureNamespace creates the named namespace if it doesn't already
// exist. Used to pre-create namespaces that two helm releases share
// — by owning the namespace ourselves, neither release tries (and
// fails) to import or reconcile it.
func ensureNamespace(ctx context.Context, client klient.Client, name string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	if err := client.Resources().Create(ctx, ns); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

// waitDaemonSetReady polls a DaemonSet until its observedGeneration
// has caught up with its generation and every desired pod is
// Ready. Used by SpireHelper for spire-agent and by KhaledHelper
// indirectly through this package.
func waitDaemonSetReady(ctx context.Context, client klient.Client, namespace, name string, timeout time.Duration) error {
	ds := &appsv1.DaemonSet{}
	ds.Name = name
	ds.Namespace = namespace
	return wait.For(conditions.New(client.Resources(namespace)).ResourceMatch(ds, func(obj k8s.Object) bool {
		got := obj.(*appsv1.DaemonSet)
		if got.Status.ObservedGeneration < got.Generation {
			return false
		}
		return got.Status.NumberReady > 0 &&
			got.Status.NumberReady == got.Status.DesiredNumberScheduled
	}), wait.WithTimeout(timeout))
}
