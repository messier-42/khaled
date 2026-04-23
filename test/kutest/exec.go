package kutest

import (
	"bytes"
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
)

// ExecInPodFirst runs cmd in the first pod matching label selector
// in namespace. Returns stdout, stderr, and any exec error.
//
// Used by Features to drive cabetool inside the cluster:
//
//	stdout, _, err := ExecInPodFirst(ctx, client,
//	    CabetoolNamespace, "app.kubernetes.io/name=cabetool",
//	    "cabetool", "whoami", "--base-url", baseURL, ...)
func ExecInPodFirst(ctx context.Context, client klient.Client, namespace, labelSelector string, cmd ...string) (string, string, error) {
	var pods corev1.PodList
	if err := client.Resources(namespace).List(ctx, &pods, resources.WithLabelSelector(labelSelector)); err != nil {
		return "", "", fmt.Errorf("list pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return "", "", fmt.Errorf("no pods matched %q in namespace %q", labelSelector, namespace)
	}
	pod := pods.Items[0]
	if pod.Status.Phase != corev1.PodRunning {
		return "", "", fmt.Errorf("pod %s/%s is not Running (phase=%s)", namespace, pod.Name, pod.Status.Phase)
	}
	containerName := pod.Spec.Containers[0].Name
	return execInPod(ctx, client.RESTConfig(), namespace, pod.Name, containerName, cmd)
}

func execInPod(ctx context.Context, cfg *rest.Config, namespace, podName, container string, cmd []string) (string, string, error) {
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "", "", fmt.Errorf("kubernetes clientset: %w", err)
	}
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)
	exec, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("new exec: %w", err)
	}
	var stdout, stderr bytes.Buffer
	streamErr := exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	return stdout.String(), stderr.String(), streamErr
}
