//go:build integration_k8s

package kutest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/yaml"
)

// k8s ConfigSource live-reload Features.
//
// The chart deploys khaled with KHALED_CONFIG_SOURCE=k8s, so every
// run of the suite already exercises the configsource plugin's
// initial-load path. What these Features exercise is the *watch*
// path — patching the live ConfigMap and confirming khaled re-reads
// it without restarting.
//
// Shared assumptions:
//
//   - Khaled is installed with the chart's default permit-all Cedar
//     policy. cabetool encap therefore succeeds in the baseline.
//   - The chart's StatefulSet has no checksum/config annotation, so
//     ConfigMap mutations do NOT trigger a pod rollout. If a future
//     edit to the chart re-introduces that annotation, these Features
//     start passing for the wrong reason (cold restart, not watch
//     reload). Watch the wallclock — > 10s past the mutation is
//     suspicious.
//   - Watch propagation latency is bounded by the configsource
//     plugin's initial backoff (500ms) plus apiserver watch event
//     fanout. We allow up to 30s to be generous; in practice reload
//     fires within 1-2s.
//
// Cross-Feature ordering matters: each sub-Feature must restore the
// ConfigMap to a known-good state on Cleanup so the next one starts
// from baseline. Otherwise a failure in test #1 leaves the ConfigMap
// broken for test #2 and the diagnosis is harder than it needs to be.

const configReloadTimeout = 30 * time.Second

// denyAllPolicy is a Cedar policy that explicitly forbids every
// request.
const denyAllPolicy = `forbid(principal, action, resource);
`

// permitAllPolicy is the chart's default-equivalent baseline. We
// spell it out so the test code controls the baseline rather than
// depending on whatever the chart's values.yaml currently says.
const permitAllPolicy = `// Permit-all baseline.
permit(principal, action, resource);
`

// invalidYAML is a payload DecodeYAML rejects. Bare unquoted `:::` is
// a syntactic error, not a valid mapping; the configsource validate
// path catches both that and structurally-bad-but-syntactically-valid
// YAML, but the syntactic case is the simplest signal.
const invalidYAML = ":::not valid yaml:::\n"

// TestK8sConfigSource_LiveReload exercises the watch loop in the k8s
// configsource plugin. Three sub-Features cover the reload happy path
// and two failure modes; all three share the single khaled deployment
// installed by the harness and mutate the chart-rendered ConfigMap in
// place.
func TestK8sConfigSource_LiveReload(t *testing.T) {
	t.Run("PolicyChange", testConfigSourcePolicyChange)
	t.Run("InvalidYAML", testConfigSourceInvalidYAML)
	t.Run("DeleteRecreate", testConfigSourceDeleteRecreate)
}

// testConfigSourcePolicyChange flips the Cedar policy under khaled's
// feet and asserts cabetool encap transitions from success to a
// policy-denied error within configReloadTimeout, then back to
// success when the original policy is restored.
//
// Note: this exercises the *file* policysource's reload (the chart
// projects policy.cedar onto the filesystem) rather than the k8s
// configsource's watch directly. We use it as the most observable
// proof-of-life that ConfigMap edits propagate into khaled's running
// state without a pod restart. The next two Features exercise the
// configsource plugin itself by mutating the khaled.yaml key.
func testConfigSourcePolicyChange(t *testing.T) {
	feature := features.New("policy change reload").
		Assess("ConfigMap policy edit changes encap behavior without pod restart", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			if encapErr := runCabetoolEncap(ctx, client); encapErr != nil {
				t.Fatalf("baseline encap failed (chart default policy is permit-all): %v", encapErr)
			}

			if err := patchPolicy(ctx, client, denyAllPolicy); err != nil {
				t.Fatalf("patch policy to deny-all: %v", err)
			}
			t.Cleanup(func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := patchPolicy(cleanupCtx, client, permitAllPolicy); err != nil {
					t.Logf("cleanup: restore permit-all policy failed: %v", err)
				}
			})

			if err := AwaitConfigReload(ctx, configReloadTimeout, func(ctx context.Context) error {
				err := runCabetoolEncap(ctx, client)
				if err == nil {
					return fmt.Errorf("encap still succeeding under deny-all policy")
				}
				if !strings.Contains(err.Error(), "access denied") {
					return fmt.Errorf("encap failed but not with access-denied: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatalf("policy change did not take effect: %v", err)
			}

			if err := patchPolicy(ctx, client, permitAllPolicy); err != nil {
				t.Fatalf("patch policy back to permit-all: %v", err)
			}
			if err := AwaitConfigReload(ctx, configReloadTimeout, func(ctx context.Context) error {
				if encapErr := runCabetoolEncap(ctx, client); encapErr != nil {
					return fmt.Errorf("encap still denied under permit-all: %v", encapErr)
				}
				return nil
			}); err != nil {
				t.Fatalf("permit-all restore did not take effect: %v", err)
			}

			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}

// testConfigSourceInvalidYAML proves the last-good-config invariant
// in the k8s configsource: when the watch surfaces a malformed
// ConfigMap, khaled rejects the new snapshot and keeps serving from
// the previously loaded config. We can't observe the rejection
// directly from outside the pod — but we can observe its consequence:
// encap continues to succeed against the previously loaded permit-all
// policy even after the ConfigMap has been clobbered with garbage
// YAML.
func testConfigSourceInvalidYAML(t *testing.T) {
	feature := features.New("invalid YAML preserves last-good config").
		Assess("malformed ConfigMap does not break running khaled", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			if encapErr := runCabetoolEncap(ctx, client); encapErr != nil {
				t.Fatalf("baseline encap failed: %v", encapErr)
			}

			origConfig, err := getKhaledConfigYAML(ctx, client)
			if err != nil {
				t.Fatalf("snapshot original khaled.yaml: %v", err)
			}
			if err := PatchKhaledConfigMap(ctx, client, func(cm *corev1.ConfigMap) {
				cm.Data["khaled.yaml"] = invalidYAML
			}); err != nil {
				t.Fatalf("patch ConfigMap to invalid YAML: %v", err)
			}
			t.Cleanup(func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := PatchKhaledConfigMap(cleanupCtx, client, func(cm *corev1.ConfigMap) {
					cm.Data["khaled.yaml"] = origConfig
				}); err != nil {
					t.Logf("cleanup: restore valid khaled.yaml failed: %v", err)
				}
			})

			// Three checks across the window catch a delayed
			// adopt-bad-config bug. 15s is enough for any reasonable
			// watch propagation; if the bad config is going to
			// poison khaled's serving state it would do so well
			// inside that window.
			deadline := time.Now().Add(15 * time.Second)
			for time.Now().Before(deadline) {
				if encapErr := runCabetoolEncap(ctx, client); encapErr != nil {
					t.Fatalf("encap broke under invalid-YAML watch event (last-good not preserved): %v", encapErr)
				}
				time.Sleep(2 * time.Second)
			}

			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}

// testConfigSourceDeleteRecreate exercises the gap-then-restore path:
// the ConfigMap is deleted entirely (a Delete watch event), khaled
// continues serving from last-good, and once the ConfigMap is
// recreated khaled re-syncs.
func testConfigSourceDeleteRecreate(t *testing.T) {
	feature := features.New("delete + recreate ConfigMap").
		Assess("khaled survives the gap and re-syncs when ConfigMap returns", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			origData, err := getConfigMapData(ctx, client)
			if err != nil {
				t.Fatalf("snapshot ConfigMap data: %v", err)
			}
			if encapErr := runCabetoolEncap(ctx, client); encapErr != nil {
				t.Fatalf("baseline encap failed: %v", encapErr)
			}

			if err := DeleteKhaledConfigMap(ctx, client); err != nil {
				t.Fatalf("delete ConfigMap: %v", err)
			}
			restored := false
			t.Cleanup(func() {
				if restored {
					return
				}
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := CreateKhaledConfigMap(cleanupCtx, client, origData); err != nil {
					t.Logf("cleanup: recreate ConfigMap failed: %v", err)
				}
			})

			// During the gap, encap should still work from last-good.
			// Wait briefly so the watch event has had time to fire.
			time.Sleep(2 * time.Second)
			if encapErr := runCabetoolEncap(ctx, client); encapErr != nil {
				t.Fatalf("encap broke during ConfigMap-deleted gap (last-good not preserved): %v", encapErr)
			}

			if err := CreateKhaledConfigMap(ctx, client, origData); err != nil {
				t.Fatalf("recreate ConfigMap: %v", err)
			}
			restored = true
			if err := AwaitConfigReload(ctx, configReloadTimeout, func(ctx context.Context) error {
				if encapErr := runCabetoolEncap(ctx, client); encapErr != nil {
					return fmt.Errorf("encap failed after ConfigMap recreate: %v", encapErr)
				}
				return nil
			}); err != nil {
				t.Fatalf("encap did not resume after ConfigMap recreate: %v", err)
			}

			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}

// runCabetoolEncap drives a one-shot cabetool encap inside the
// cabetool pod. Returns nil on success, error wrapping cabetool's
// stderr on either exec failure or a CKAP error response from khaled.
// The Features inspect the error string for substrings like
// "access denied" to distinguish policy-denied from other failures.
func runCabetoolEncap(ctx context.Context, client klient.Client) error {
	cmd := fmt.Sprintf(
		"printf %%s reload-probe | cabetool encap --attr env=str:test --base-url %s --spiffe-socket /spiffe-workload-api/socket --server-spiffe-id-regex '%s' >/dev/null",
		khaledBaseURL, serverSPIFFEIDRegex,
	)
	_, stderr, err := ExecInPodFirst(ctx, client,
		CabetoolNamespace, "app.kubernetes.io/name=cabetool",
		"sh", "-c", cmd,
	)
	if err != nil {
		return fmt.Errorf("cabetool encap exited non-zero: stderr=%q: %w", strings.TrimSpace(stderr), err)
	}
	return nil
}

// patchPolicy edits the inline Cedar policy embedded in the chart's
// khaled.yaml ConfigMap key (config.policySource.inline.text). The
// k8s configsource plugin observes the ConfigMap update via its API
// watch (~1 second), feeds the new snapshot to the policyManager,
// which detects the changed Inline.Text and rebuilds the policy
// runtime — the new Cedar engine is in effect within a couple of
// seconds at most.
//
// Compare: the previous file-based policy reload was bottlenecked by
// the kubelet's projected-ConfigMap refresh delay (~60s) which made
// these Features either painfully slow or flaky.
func patchPolicy(ctx context.Context, client klient.Client, policyText string) error {
	return PatchKhaledConfigMap(ctx, client, func(cm *corev1.ConfigMap) {
		updated, err := setInlinePolicyInKhaledYAML(cm.Data["khaled.yaml"], policyText)
		if err != nil {
			// PatchKhaledConfigMap callbacks can't return errors;
			// stash a clearly-broken value so the API server's CM
			// update reflects the failure mode in a kubectl-visible
			// way and the next encap probe surfaces it too.
			cm.Data["khaled.yaml"] = "PATCH_POLICY_FAILED:\n" + err.Error()
			return
		}
		cm.Data["khaled.yaml"] = updated
	})
}

// setInlinePolicyInKhaledYAML rewrites a khaled.yaml document's
// config.policySource.inline.text field to the supplied policy text.
// All other fields are preserved verbatim. Returns the re-marshalled
// YAML.
func setInlinePolicyInKhaledYAML(input, policyText string) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(input), &doc); err != nil {
		return "", fmt.Errorf("parse khaled.yaml: %w", err)
	}
	ps, ok := doc["policySource"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("khaled.yaml has no policySource block")
	}
	inline, ok := ps["inline"].(map[string]any)
	if !ok {
		// Could be that the chart was overridden to use the file
		// source. Force the inline structure since the whole point
		// of this helper is to swap to inline.
		inline = map[string]any{}
		ps["inline"] = inline
		ps["use"] = "inline"
		delete(ps, "file")
	}
	inline["text"] = policyText
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal khaled.yaml: %w", err)
	}
	return string(out), nil
}

// getKhaledConfigYAML returns the current khaled.yaml string from the
// live ConfigMap so tests can restore on cleanup.
func getKhaledConfigYAML(ctx context.Context, client klient.Client) (string, error) {
	cm := &corev1.ConfigMap{}
	if err := client.Resources().Get(ctx, "khaled-config", KhaledNamespace, cm); err != nil {
		return "", err
	}
	return cm.Data["khaled.yaml"], nil
}

// getConfigMapData snapshots the entire data map for restoration in
// the DeleteRecreate Feature.
func getConfigMapData(ctx context.Context, client klient.Client) (map[string]string, error) {
	cm := &corev1.ConfigMap{}
	if err := client.Resources().Get(ctx, "khaled-config", KhaledNamespace, cm); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(cm.Data))
	for k, v := range cm.Data {
		out[k] = v
	}
	return out, nil
}
