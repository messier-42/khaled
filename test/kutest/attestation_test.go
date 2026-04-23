//go:build integration_k8s

package kutest

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
)

// k8s-attestation Features.
//
// The harness installs khaled with claimsMapping.use=k8s-attestation
// (see main_test.go). Cabetool is issued the standard k8s-pod-shaped
// SVID by SPIRE (see CabetoolPodSPIFFEIDTemplate). When cabetool
// dials khaled, khaled's k8s-attestation plugin:
//
//   1. Parses the SVID URI into (namespace, sa, pod-name, uid).
//   2. GETs the live pod from the apiserver via its bound SA token.
//   3. Cross-checks pod.UID and pod.spec.serviceAccountName against
//      the SPIFFE ID values, and on success derives a Principal whose
//      claims describe the originating workload (namespace, SA,
//      pod-name, node-name, container images, labels, annotations).
//
// These Features prove the plugin's claims actually flow into Cedar's
// principal context — i.e. khaled is making a live API call and using
// the result, not just rubber-stamping the SVID.

// permitNamespaceDefaultPolicy permits encap only when the principal
// belongs to the "default" namespace. Cabetool runs in default, so
// encap should succeed.
const permitNamespaceDefaultPolicy = `permit(principal, action, resource) when { principal.namespace == "default" };
`

// permitNamespaceKubeSystemPolicy permits encap only when the
// principal belongs to "kube-system". Cabetool runs in default, so
// encap should be denied.
const permitNamespaceKubeSystemPolicy = `permit(principal, action, resource) when { principal.namespace == "kube-system" };
`

// TestK8sAttestation_Claims drives encap against a Cedar policy that
// requires a specific principal.namespace claim. Two sub-Features
// flip the policy: default → permits cabetool (which lives in
// default), kube-system → denies it. This proves the namespace claim
// is actually being attested from the live pod, not statically
// configured.
func TestK8sAttestation_Claims(t *testing.T) {
	t.Run("PermitMatchingNamespace", testAttestationPermitMatchingNamespace)
	t.Run("DenyNonMatchingNamespace", testAttestationDenyNonMatchingNamespace)
}

func testAttestationPermitMatchingNamespace(t *testing.T) {
	feature := features.New("policy permits matching namespace claim").
		Assess("encap transitions from denied to permitted when policy matches principal.namespace", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			// Start from a denying policy so the predicate below
			// actually has to observe a transition. Otherwise the
			// chart's default permit-all would satisfy
			// "encap succeeds" before any reload happened, masking
			// a non-functional reload path.
			if err := patchPolicy(ctx, client, permitNamespaceKubeSystemPolicy); err != nil {
				t.Fatalf("seed deny baseline: %v", err)
			}
			if err := AwaitConfigReload(ctx, configReloadTimeout, func(ctx context.Context) error {
				err := runCabetoolEncap(ctx, client)
				if err == nil {
					return fmt.Errorf("encap still succeeding under deny baseline")
				}
				return nil
			}); err != nil {
				t.Fatalf("deny baseline did not take effect: %v", err)
			}

			if err := patchPolicy(ctx, client, permitNamespaceDefaultPolicy); err != nil {
				t.Fatalf("install permit-default policy: %v", err)
			}
			t.Cleanup(func() { restorePermitAll(client, t) })

			if err := AwaitConfigReload(ctx, configReloadTimeout, func(ctx context.Context) error {
				if encapErr := runCabetoolEncap(ctx, client); encapErr != nil {
					return fmt.Errorf("encap denied under permit-namespace=default policy: %v", encapErr)
				}
				return nil
			}); err != nil {
				t.Fatalf("permit-namespace=default did not authorize cabetool: %v", err)
			}

			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}

func testAttestationDenyNonMatchingNamespace(t *testing.T) {
	feature := features.New("policy denies non-matching namespace claim").
		Assess("encap fails when policy requires a namespace cabetool is not in", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			if err := patchPolicy(ctx, client, permitNamespaceKubeSystemPolicy); err != nil {
				t.Fatalf("install permit-kube-system policy: %v", err)
			}
			t.Cleanup(func() { restorePermitAll(client, t) })

			if err := AwaitConfigReload(ctx, configReloadTimeout, func(ctx context.Context) error {
				err := runCabetoolEncap(ctx, client)
				if err == nil {
					return fmt.Errorf("encap still succeeding under permit-namespace=kube-system policy (cabetool is in default)")
				}
				if !strings.Contains(err.Error(), "access denied") {
					return fmt.Errorf("encap failed but not with access-denied: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatalf("permit-namespace=kube-system did not deny cabetool: %v", err)
			}

			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}

// TestK8sAttestation_NotAttestableID proves the k8s-attestation
// plugin rejects SVIDs that don't match the k8s-pod URI shape. We
// temporarily override the cabetool ClusterSPIFFEID to issue a
// non-k8s-shaped SVID (`spiffe://example.test/anonymous`) and assert
// cabetool encap fails. After the assertion we restore the standard
// k8s-pod template and confirm encap recovers.
//
// Why this matters: the plugin's parseSPIFFEID regex is the gate
// between "attested workload identity" and "any SPIRE-issued URI in
// the trust domain". A regression that loosens the parse would let
// any SPIRE-registered workload through. This Feature is the only
// end-to-end test of that gate.
func TestK8sAttestation_NotAttestableID(t *testing.T) {
	feature := features.New("non-k8s SVID is rejected by attestation").
		Assess("cabetool with a custom (non-k8s) SVID URI is denied", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			origTemplate := CabetoolPodSPIFFEIDTemplate
			const customTemplate = `spiffe://{{ .TrustDomain }}/anonymous`
			if err := patchClusterSPIFFEIDTemplate(ctx, client, "cabetool", customTemplate); err != nil {
				t.Fatalf("patch cabetool ClusterSPIFFEID to custom template: %v", err)
			}
			t.Cleanup(func() {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				if err := patchClusterSPIFFEIDTemplate(cleanupCtx, client, "cabetool", origTemplate); err != nil {
					t.Logf("cleanup: restore cabetool ClusterSPIFFEID failed: %v", err)
					return
				}
				// Block until SPIRE re-rotates cabetool's SVID back
				// to the k8s-pod shape, otherwise the next test runs
				// against a still-unattestable SVID and fails for
				// reasons unrelated to its own contract.
				if err := AwaitConfigReload(cleanupCtx, 90*time.Second, func(ctx context.Context) error {
					if encapErr := runCabetoolEncap(ctx, client); encapErr != nil {
						return fmt.Errorf("cabetool SVID still not attestable: %v", encapErr)
					}
					return nil
				}); err != nil {
					t.Logf("cleanup: cabetool SVID did not return to k8s-pod shape in time: %v", err)
				}
			})

			// SPIRE controller-manager reconcile + SVID rotation +
			// CSI mount refresh all happen back-to-back; in practice
			// a custom-template change settles in 10-30s. Be generous.
			const svidRotationTimeout = 90 * time.Second
			if err := AwaitConfigReload(ctx, svidRotationTimeout, func(ctx context.Context) error {
				err := runCabetoolEncap(ctx, client)
				if err == nil {
					return fmt.Errorf("encap still succeeding with custom (non-k8s) SVID")
				}
				return nil
			}); err != nil {
				t.Fatalf("custom SVID still authorized: %v", err)
			}

			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}

// patchClusterSPIFFEIDTemplate replaces the spec.spiffeIDTemplate of
// the named ClusterSPIFFEID. Used by the NotAttestableID Feature to
// swap cabetool's URI shape mid-test; reads/writes via unstructured
// to avoid pulling spire-controller-manager's CRD types into this
// module.
func patchClusterSPIFFEIDTemplate(ctx context.Context, client klient.Client, name, template string) error {
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
	if err := client.Resources().Get(ctx, name, "", obj); err != nil {
		return fmt.Errorf("get ClusterSPIFFEID %s: %w", name, err)
	}
	if err := unstructured.SetNestedField(obj.Object, template, "spec", "spiffeIDTemplate"); err != nil {
		return fmt.Errorf("set spiffeIDTemplate: %w", err)
	}
	if err := client.Resources().Update(ctx, obj); err != nil {
		return fmt.Errorf("update ClusterSPIFFEID %s: %w", name, err)
	}
	return nil
}

// restorePermitAll is a t.Cleanup convenience that restores the
// permit-all baseline policy. Errors are logged (not failed) because
// cleanup runs in a defer and a failure here would mask the actual
// test failure.
func restorePermitAll(client klient.Client, t *testing.T) {
	t.Helper()
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := patchPolicy(cleanupCtx, client, permitAllPolicy); err != nil {
		t.Logf("cleanup: restore permit-all policy failed: %v", err)
	}
}
