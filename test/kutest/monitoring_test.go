//go:build integration_k8s

package kutest

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// khaledPodIP returns the pod IP of the (single-replica) khaled
// StatefulSet pod. The monitoring listener is plaintext and not
// exposed via the khaled Service, so Features reach it directly on
// the pod IP, which is routable within the kind cluster.
func khaledPodIP(ctx context.Context, t *testing.T, r *resources.Resources) string {
	t.Helper()
	var pods corev1.PodList
	if err := r.List(ctx, &pods,
		resources.WithLabelSelector("app.kubernetes.io/name=khaled")); err != nil {
		t.Fatalf("list khaled pods: %v", err)
	}
	if len(pods.Items) == 0 {
		t.Fatal("no khaled pod found")
	}
	ip := pods.Items[0].Status.PodIP
	if ip == "" {
		t.Fatalf("khaled pod %s has no PodIP", pods.Items[0].Name)
	}
	return ip
}

// probeFromCabetool performs an HTTP GET of the given monitoring path
// against the khaled pod's plaintext monitoring port, using busybox
// wget inside the cabetool pod. It returns the response body.
//
// `wget -S -O -` prints response headers to stderr and the body to
// stdout; a non-2xx status makes wget exit non-zero, which surfaces
// here as an error along with the captured stderr.
func probeFromCabetool(ctx context.Context, t *testing.T, cfg *envconf.Config, podIP, path string) (string, string, error) {
	t.Helper()
	client, err := cfg.NewClient()
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	url := fmt.Sprintf("http://%s:8081%s", podIP, path)
	return ExecInPodFirst(ctx, client,
		CabetoolNamespace, "app.kubernetes.io/name=cabetool",
		"wget", "-q", "-S", "-O", "-", url)
}

// TestMonitoring_PodBecomesReady proves the readiness probe is wired
// end to end: the khaled StatefulSet pod reaches the Ready condition,
// which the kubelet only reports once the chart's readinessProbe
// against /readyz has succeeded.
func TestMonitoring_PodBecomesReady(t *testing.T) {
	feature := features.New("khaled pod reports Ready via /readyz probe").
		Assess("khaled pod has the Ready condition true", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			var pods corev1.PodList
			if err := client.Resources(KhaledNamespace).List(ctx, &pods,
				resources.WithLabelSelector("app.kubernetes.io/name=khaled")); err != nil {
				t.Fatalf("list khaled pods: %v", err)
			}
			if len(pods.Items) == 0 {
				t.Fatal("no khaled pod found")
			}
			pod := pods.Items[0]
			ready := false
			for _, c := range pod.Status.Conditions {
				if c.Type == corev1.PodReady {
					ready = c.Status == corev1.ConditionTrue
				}
			}
			if !ready {
				t.Errorf("khaled pod %s is not Ready; conditions: %+v",
					pod.Name, pod.Status.Conditions)
			}
			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}

// TestMonitoring_LivezReadyz probes /livez and /readyz directly on the
// khaled pod's plaintext monitoring listener. /livez must always be
// 200; /readyz must be 200 because the pod is fully up by this point.
func TestMonitoring_LivezReadyz(t *testing.T) {
	feature := features.New("/livez and /readyz answer on the monitoring listener").
		Assess("/livez returns ok", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			ip := khaledPodIP(ctx, t, r.Resources(KhaledNamespace))

			stdout, stderr, err := probeFromCabetool(ctx, t, cfg, ip, "/livez")
			if err != nil {
				t.Fatalf("probe /livez: %v\nstderr: %s", err, stderr)
			}
			if !strings.Contains(stdout, "ok") {
				t.Errorf("/livez body = %q, want it to contain \"ok\"", stdout)
			}
			return ctx
		}).
		Assess("/readyz returns ready", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			ip := khaledPodIP(ctx, t, r.Resources(KhaledNamespace))

			stdout, stderr, err := probeFromCabetool(ctx, t, cfg, ip, "/readyz")
			if err != nil {
				t.Fatalf("probe /readyz: %v\nstderr: %s", err, stderr)
			}
			if !strings.Contains(stdout, "ok") {
				t.Errorf("/readyz body = %q, want it to contain \"ok\"", stdout)
			}
			return ctx
		}).
		Assess("/readyz?verbose lists per-check status", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			r, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			ip := khaledPodIP(ctx, t, r.Resources(KhaledNamespace))

			stdout, stderr, err := probeFromCabetool(ctx, t, cfg, ip, "/readyz?verbose")
			if err != nil {
				t.Fatalf("probe /readyz?verbose: %v\nstderr: %s", err, stderr)
			}
			for _, want := range []string{
				"[+] keyserver ok",
				"[+] transports ok",
				"readyz check passed",
			} {
				if !strings.Contains(stdout, want) {
					t.Errorf("/readyz?verbose body missing %q\ngot:\n%s", want, stdout)
				}
			}
			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}
