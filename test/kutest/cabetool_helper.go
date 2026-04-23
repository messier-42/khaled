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
)

// CabetoolHelper deploys a long-running cabetool pod (busybox base
// with the cabetool binary baked in; entrypoint is `sleep infinity`)
// so Features can drive cabetool via `kubectl exec`. Also registers
// a ClusterSPIFFEID so the SPIRE controller-manager issues an SVID
// to the cabetool pod via the SPIFFE CSI mount.
type CabetoolHelperConfig struct {
	// ImageRef is the OCI ref recorded in the preloaded cabetool.oci
	// archive.
	ImageRef string
	// SPIFFEID is the URI template the controller-manager issues to
	// cabetool pods. Defaults to the k8s-pod shape
	// (spiffe://<td>/ns/<ns>/sa/<sa>/pod/<pod>/<uid>) when empty —
	// that shape is what the k8s-attestation claimsmapping plugin
	// expects, and the chart's default static-with-wildcard mapper
	// accepts any URI shape, so this works for both Stage 2 Feature
	// groups without per-test SVID juggling.
	SPIFFEID string
}

type CabetoolHelper struct {
	cfg       CabetoolHelperConfig
	didDeploy bool
}

var _ Helper = &CabetoolHelper{}

// CabetoolPodSPIFFEIDTemplate is the SPIRE controller-manager Go
// template that emits the standard k8s-pod SPIFFE ID shape. Both the
// chart's default static-with-wildcard claimsmapping (which matches
// any URI) and the k8s-attestation claimsmapping (which requires this
// exact shape) accept SVIDs issued from this template.
const CabetoolPodSPIFFEIDTemplate = `spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}/pod/{{ .PodMeta.Name }}/{{ .PodMeta.UID }}`

func NewCabetoolHelper(cfg CabetoolHelperConfig) *CabetoolHelper {
	if cfg.SPIFFEID == "" {
		cfg.SPIFFEID = CabetoolPodSPIFFEIDTemplate
	}
	return &CabetoolHelper{cfg: cfg}
}

func (ch *CabetoolHelper) String() string { return "Deploy cabetool test client" }

const (
	cabetoolDeploymentName = "cabetool"
	cabetoolReadyTimeout   = 2 * time.Minute
	// CabetoolNamespace is exported so Features can target the pod
	// for `kubectl exec`.
	CabetoolNamespace = "default"
)

func (ch *CabetoolHelper) Setup() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if ch.cfg.ImageRef == "" {
			return ctx, fmt.Errorf("cabetool helper: ImageRef is required")
		}
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}

		if err := applyClusterSPIFFEID(ctx, client, "cabetool", ch.cfg.SPIFFEID, CabetoolNamespace, "cabetool"); err != nil {
			return ctx, fmt.Errorf("apply ClusterSPIFFEID for cabetool: %w", err)
		}

		dep := buildCabetoolDeployment(CabetoolNamespace, ch.cfg.ImageRef)
		if err := client.Resources().Create(ctx, dep); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return ctx, fmt.Errorf("create cabetool deployment: %w", err)
			}
		}
		ch.didDeploy = true

		log.V(0).InfoS("Waiting for cabetool deployment to be Ready", "timeout", cabetoolReadyTimeout)
		if err := waitDeploymentReady(ctx, client, CabetoolNamespace, cabetoolDeploymentName, cabetoolReadyTimeout); err != nil {
			return ctx, fmt.Errorf("cabetool not ready: %w", err)
		}
		log.V(0).InfoS("cabetool deployment ready")
		return ctx, nil
	}
}

func (ch *CabetoolHelper) Finish() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if !ch.didDeploy {
			return ctx, nil
		}
		client, err := cfg.NewClient()
		if err != nil {
			log.V(0).ErrorS(err, "could not build client for cabetool teardown")
			return ctx, nil
		}
		dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: cabetoolDeploymentName, Namespace: CabetoolNamespace}}
		if err := client.Resources().Delete(ctx, dep); err != nil {
			log.V(0).ErrorS(err, "delete cabetool deployment failed (continuing)")
		}
		return ctx, nil
	}
}

func buildCabetoolDeployment(namespace, imageRef string) *appsv1.Deployment {
	replicas := int32(1)
	runAsUser := int64(65532)
	runAsGroup := int64(65532)
	runAsNonRoot := true
	allowPrivilegeEscalation := false
	readOnlyRootFilesystem := false // sleep + exec needs writable /tmp etc.
	labels := map[string]string{
		"app.kubernetes.io/name": "cabetool",
	}
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: cabetoolDeploymentName, Namespace: namespace, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					SecurityContext: &corev1.PodSecurityContext{
						RunAsUser:    &runAsUser,
						RunAsGroup:   &runAsGroup,
						RunAsNonRoot: &runAsNonRoot,
					},
					Containers: []corev1.Container{{
						Name:  "cabetool",
						Image: imageRef,
						// Containerfile.cabetool sets ENTRYPOINT to
						// `sleep infinity` already, but spell it out
						// here so a swap to a different base image
						// doesn't silently break the harness.
						Command: []string{"sleep", "infinity"},
						SecurityContext: &corev1.SecurityContext{
							AllowPrivilegeEscalation: &allowPrivilegeEscalation,
							ReadOnlyRootFilesystem:   &readOnlyRootFilesystem,
							Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
						},
						Env: []corev1.EnvVar{
							{Name: "SPIFFE_ENDPOINT_SOCKET", Value: "unix:///spiffe-workload-api/socket"},
						},
						VolumeMounts: []corev1.VolumeMount{{
							Name:      "spiffe-workload-api",
							MountPath: "/spiffe-workload-api",
							ReadOnly:  true,
						}},
					}},
					Volumes: []corev1.Volume{{
						Name: "spiffe-workload-api",
						VolumeSource: corev1.VolumeSource{
							CSI: &corev1.CSIVolumeSource{
								Driver:   "csi.spiffe.io",
								ReadOnly: ptrTo(true),
							},
						},
					}},
					ImagePullSecrets: nil,
				},
			},
		},
	}
}

func ptrTo[T any](v T) *T { return &v }

// waitDeploymentReady polls a Deployment until ReadyReplicas matches
// Spec.Replicas.
func waitDeploymentReady(ctx context.Context, client klient.Client, namespace, name string, timeout time.Duration) error {
	dep := &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace}}
	return wait.For(conditions.New(client.Resources(namespace)).ResourceMatch(dep, func(obj k8s.Object) bool {
		got := obj.(*appsv1.Deployment)
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
