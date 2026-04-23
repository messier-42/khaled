// Package preloader provides Go utilities for preloading OCI image archives to
// Kubernetes clusters without reliance on OCI registry infrastructure.
package preloader

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	log "k8s.io/klog/v2"

	"sigs.k8s.io/e2e-framework/klient"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
)

type ReaderFactory func() (io.ReadCloser, error)

type PreloadArgs struct {
	// Kubernetes API client
	Client klient.Client

	// OCI archive suppliers. Each factory is expected to return a fresh reader
	// positioned at the start of an OCI tarball that will be streamed to every
	// cluster node.
	Images []ReaderFactory

	// The namespace to use for the loader.
	LoaderNamespace string
	// The daemon set name to use for the loader.
	LoaderName string
	// The OCI image ref to use for the nerdctl loader. A sensible default is used if this is not specified.
	LoaderImageRef string
}

const (
	containerdSocketPath   = "/run/containerd/containerd.sock"
	defaultLoaderName      = "image-loader"
	defaultLoaderNamespace = defaultLoaderName
	defaultLoaderImageRef  = "ghcr.io/containerd/nerdctl:latest"
	containerName          = defaultLoaderName
	cleanupTimeout         = 30 * time.Second
	statusPollInterval     = 1 * time.Second

	namespaceDeleteTimeout = 2 * time.Minute
	namespaceCreateTimeout = 30 * time.Second
	daemonSetCreateTimeout = 30 * time.Second
	daemonSetReadyTimeout  = 5 * time.Minute
	podListTimeout         = 30 * time.Second
	podReadyTimeout        = 2 * time.Minute
	streamIdleTimeout      = 1 * time.Minute
)

// Preload loads the provided OCI images into containerd on every node by
// deploying a privileged nerdctl daemonset and streaming each archive into
// nerdctl load via pod exec.
func Preload(ctx context.Context, args PreloadArgs) (err error) {
	// Set defaults.
	if args.LoaderNamespace == "" {
		args.LoaderNamespace = defaultLoaderNamespace
	}
	if args.LoaderName == "" {
		args.LoaderName = defaultLoaderName
	}
	if args.LoaderImageRef == "" {
		args.LoaderImageRef = defaultLoaderImageRef
	}

	// Validate arguments.
	if args.Client == nil {
		return errors.New("preloader: Kubernetes client is required")
	}

	restCfg := args.Client.RESTConfig()
	if restCfg == nil {
		return errors.New("preloader: client REST config is nil")
	}

	for i, factory := range args.Images {
		if factory == nil {
			return fmt.Errorf("preloader: image factory at index %d is nil", i)
		}
	}

	log.V(0).InfoS("Starting OCI image preload", "loaderNamespace", args.LoaderNamespace, "loaderName", args.LoaderName, "loaderImageRef", args.LoaderImageRef, "imageCount", len(args.Images))

	// Ensure the namespace does not already exist, deleting it if needed.
	log.V(1).InfoS("Ensuring loader namespace is clean", "namespace", args.LoaderNamespace)
	if err := runWithTimeout(ctx, namespaceDeleteTimeout, func(stageCtx context.Context) error {
		return deleteNamespaceAndWait(stageCtx, args.Client, args.LoaderNamespace)
	}); err != nil {
		log.V(0).ErrorS(err, "Failed clearing loader namespace", "namespace", args.LoaderNamespace)
		return fmt.Errorf("preloader: clearing namespace %q failed: %w", args.LoaderNamespace, err)
	}
	log.V(2).InfoS("Loader namespace cleared", "namespace", args.LoaderNamespace)

	// Create a fresh namespace.
	log.V(1).InfoS("Creating loader namespace", "namespace", args.LoaderNamespace, "loaderName", args.LoaderName)
	if err := runWithTimeout(ctx, namespaceCreateTimeout, func(stageCtx context.Context) error {
		return createNamespace(stageCtx, args.Client, args.LoaderNamespace, args.LoaderName)
	}); err != nil {
		log.V(0).ErrorS(err, "Failed creating loader namespace", "namespace", args.LoaderNamespace)
		return fmt.Errorf("preloader: creating namespace %q failed: %w", args.LoaderNamespace, err)
	}
	log.V(2).InfoS("Loader namespace ready", "namespace", args.LoaderNamespace)

	// When this function returns, regardless of whether it returned successfully
	// or with an error, we make a best-effort, time-limited attempt to delete
	// our temporary namespace.
	//nolint:contextcheck // Deliberately non-inherited context.
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		log.V(2).InfoS("Cleaning up loader namespace", "namespace", args.LoaderNamespace)
		if cleanupErr := deleteNamespaceFast(cleanupCtx, args.Client, args.LoaderNamespace); cleanupErr != nil {
			log.V(0).ErrorS(cleanupErr, "Cleanup failed", "namespace", args.LoaderNamespace)
			if err == nil {
				err = fmt.Errorf("preloader: cleanup failed: %w", cleanupErr)
			} else {
				err = fmt.Errorf("preloader: both preload and cleanup failed; preload failed with %w, cleanup failed with %w", err, cleanupErr)
			}
		} else {
			log.V(3).InfoS("Cleanup completed", "namespace", args.LoaderNamespace)
		}
	}()

	// Create the daemon set.
	log.V(1).InfoS("Creating loader daemonset", "namespace", args.LoaderNamespace, "loaderName", args.LoaderName, "imageRef", args.LoaderImageRef)
	if err := runWithTimeout(ctx, daemonSetCreateTimeout, func(stageCtx context.Context) error {
		return createDaemonSet(stageCtx, args.Client, args.LoaderNamespace, args.LoaderName, args.LoaderImageRef)
	}); err != nil {
		log.V(0).ErrorS(err, "Failed creating loader daemonset", "namespace", args.LoaderNamespace, "loaderName", args.LoaderName)
		return fmt.Errorf("preloader: creating daemonset failed: %w", err)
	}
	log.V(2).InfoS("Loader daemonset created", "namespace", args.LoaderNamespace, "loaderName", args.LoaderName)

	// Wait for the daemon set to come up.
	log.V(1).InfoS("Waiting for loader daemonset to be ready", "namespace", args.LoaderNamespace, "loaderName", args.LoaderName)
	if err := runWithTimeout(ctx, daemonSetReadyTimeout, func(stageCtx context.Context) error {
		return waitForDaemonSetReady(stageCtx, args.Client, args.LoaderNamespace, args.LoaderName)
	}); err != nil {
		log.V(0).ErrorS(err, "Loader daemonset failed to become ready", "namespace", args.LoaderNamespace, "loaderName", args.LoaderName)
		return fmt.Errorf("preloader: daemonset readiness check failed: %w", err)
	}
	log.V(2).InfoS("Loader daemonset ready", "namespace", args.LoaderNamespace, "loaderName", args.LoaderName)

	kubeClient, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("preloader: building clientset failed: %w", err)
	}

	labelSelector := "app=" + args.LoaderName

	for imageIdx, factory := range args.Images {
		var pods []corev1.Pod
		log.V(2).InfoS("Listing loader pods", "namespace", args.LoaderNamespace, "selector", labelSelector, "imageIndex", imageIdx)
		if err := runWithTimeout(ctx, podListTimeout, func(stageCtx context.Context) error {
			var listErr error
			pods, listErr = listPods(stageCtx, args.Client, args.LoaderNamespace, labelSelector)
			return listErr
		}); err != nil {
			log.V(0).ErrorS(err, "Failed listing loader pods", "namespace", args.LoaderNamespace)
			return fmt.Errorf("preloader: listing loader pods failed: %w", err)
		}
		log.V(3).InfoS("Loader pods listed", "namespace", args.LoaderNamespace, "podCount", len(pods), "imageIndex", imageIdx)
		if len(pods) == 0 {
			log.V(1).InfoS("No loader pods found; skipping image", "imageIndex", imageIdx)
			continue
		}
		for _, pod := range pods {
			log.V(2).InfoS("Waiting for loader pod to be ready", "podName", pod.Name, "namespace", pod.Namespace)
			if err := runWithTimeout(ctx, podReadyTimeout, func(stageCtx context.Context) error {
				return waitForPodReady(stageCtx, args.Client, args.LoaderNamespace, pod.Name)
			}); err != nil {
				log.V(0).ErrorS(err, "Loader pod failed to become ready", "podName", pod.Name, "namespace", pod.Namespace)
				return fmt.Errorf("preloader: pod %s readiness wait failed: %w", pod.Name, err)
			}
			log.V(3).InfoS("Loader pod is ready", "podName", pod.Name, "namespace", pod.Namespace)
			reader, err := factory()
			if err != nil {
				log.V(0).ErrorS(err, "Failed creating OCI reader", "imageIndex", imageIdx)
				return fmt.Errorf("preloader: preparing reader for image %d failed: %w", imageIdx, err)
			}
			if reader == nil {
				return fmt.Errorf("preloader: factory for image %d returned a nil reader", imageIdx)
			}
			log.V(2).InfoS("Streaming OCI archive to pod", "podName", pod.Name, "namespace", pod.Namespace, "imageIndex", imageIdx)
			loadErr := execNerdctlLoad(ctx, kubeClient, restCfg, pod.Namespace, pod.Name, reader, streamIdleTimeout)
			if loadErr != nil {
				closeErr := reader.Close()
				if closeErr != nil {
					loadErr = errors.Join(loadErr, closeErr)
				}
				log.V(0).ErrorS(loadErr, "nerdctl load failed", "podName", pod.Name, "namespace", pod.Namespace, "imageIndex", imageIdx)
				return loadErr
			}
			log.V(2).InfoS("OCI archive loaded", "podName", pod.Name, "namespace", pod.Namespace, "imageIndex", imageIdx)
			if closeErr := reader.Close(); closeErr != nil {
				log.V(0).ErrorS(closeErr, "Failed closing OCI reader", "imageIndex", imageIdx)
				return fmt.Errorf("preloader: closing reader for image %d failed: %w", imageIdx, closeErr)
			}
		}
	}

	return nil
}

// Create the temporary namespace used to contain the preloader.
func createNamespace(ctx context.Context, client klient.Client, name, loaderName string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
		Name: name,
		Labels: map[string]string{
			"app":      loaderName,
			"appClass": defaultLoaderName,
		},
	}}
	log.V(3).InfoS("Submitting namespace create request", "namespace", name, "loaderName", loaderName)
	err := client.Resources().Create(ctx, ns)
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return err
	}
	if apierrors.IsAlreadyExists(err) {
		log.V(3).InfoS("Namespace already exists", "namespace", name)
	} else {
		log.V(4).InfoS("Namespace create request accepted", "namespace", name)
	}
	return nil
}

// Create the daemon set.
func createDaemonSet(ctx context.Context, client klient.Client, namespace, loaderName, nerdctlImageRef string) error {
	ds := buildDaemonSet(namespace, loaderName, nerdctlImageRef)
	return client.Resources().Create(ctx, ds)
}

// Idempotently tears down any existing namespace with the given name, waiting
// for termination to be completed as needed. This returns successfully if a
// namespace with the given name does not exist.
func deleteNamespaceAndWait(ctx context.Context, client klient.Client, name string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	log.V(3).InfoS("Deleting namespace and waiting for termination", "namespace", name)
	err := client.Resources().Delete(ctx, ns)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if apierrors.IsNotFound(err) {
		log.V(4).InfoS("Namespace does not exist", "namespace", name)
		return nil
	}
	return waitNamespaceDeletion(ctx, client, name)
}

// Idempotently begins deletion of any existing namespace with the given name.
// This does not wait for termination to complete. Returns successfully if a
// namespace with the given name does not exist.
func deleteNamespaceFast(ctx context.Context, client klient.Client, name string) error {
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
	log.V(3).InfoS("Initiating fast namespace deletion", "namespace", name)
	err := client.Resources().Delete(ctx, ns, resources.WithGracePeriod(0))
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if apierrors.IsNotFound(err) {
		log.V(4).InfoS("Namespace already removed", "namespace", name)
	}
	return nil
}

// Waits for a namespace for which deletion has been initiated to cease to
// exist.
func waitNamespaceDeletion(ctx context.Context, client klient.Client, name string) error {
	ticker := time.NewTicker(statusPollInterval)
	defer ticker.Stop()

	log.V(4).InfoS("Waiting for namespace deletion", "namespace", name)
	for {
		var ns corev1.Namespace
		err := client.Resources().Get(ctx, name, "", &ns)
		if apierrors.IsNotFound(err) {
			log.V(4).InfoS("Namespace deletion complete", "namespace", name)
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for namespace %s deletion: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func waitForDaemonSetReady(ctx context.Context, client klient.Client, namespace, name string) error {
	ticker := time.NewTicker(statusPollInterval)
	defer ticker.Stop()

	for {
		var ds appsv1.DaemonSet
		err := client.Resources().Get(ctx, name, namespace, &ds)
		if err != nil {
			if apierrors.IsNotFound(err) {
				// DaemonSet not created yet, keep waiting.
			} else {
				return err
			}
		} else {
			desired := ds.Status.DesiredNumberScheduled
			ready := ds.Status.NumberReady
			if ds.Status.ObservedGeneration >= ds.Generation && desired == ready {
				log.V(3).InfoS("Daemonset reports all pods ready", "namespace", namespace, "daemonSet", name, "desired", desired, "ready", ready)
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for daemonset %s ready: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func buildDaemonSet(namespace, loaderName, nerdctlImageRef string) *appsv1.DaemonSet {
	privileged := true
	runAsUser := int64(0)
	terminationGracePeriod := int64(0)
	hostPathType := corev1.HostPathSocket
	x100Percent := intstr.FromString("100%")

	labels := map[string]string{
		"app":      loaderName,
		"appClass": defaultLoaderName,
	}

	return &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      loaderName,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &metav1.LabelSelector{
				MatchLabels: labels,
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
				RollingUpdate: &appsv1.RollingUpdateDaemonSet{
					MaxUnavailable: &x100Percent,
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					Tolerations: []corev1.Toleration{
						{Operator: corev1.TolerationOpExists},
					},
					TerminationGracePeriodSeconds: &terminationGracePeriod,
					Containers: []corev1.Container{
						{
							Name:            containerName,
							Image:           nerdctlImageRef,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"/bin/sh", "-c", "sleep infinity"},
							SecurityContext: &corev1.SecurityContext{
								RunAsUser:  &runAsUser,
								Privileged: &privileged,
							},
							Env: []corev1.EnvVar{
								{Name: "CONTAINERD_SOCK", Value: containerdSocketPath},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "containerd-socket",
									MountPath: containerdSocketPath,
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "containerd-socket",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: containerdSocketPath,
									Type: &hostPathType,
								},
							},
						},
					},
				},
			},
		},
	}
}

func listPods(ctx context.Context, client klient.Client, namespace, labelSelector string) ([]corev1.Pod, error) {
	var pods corev1.PodList
	log.V(4).InfoS("Listing pods", "namespace", namespace, "selector", labelSelector)
	if err := client.Resources(namespace).List(ctx, &pods, resources.WithLabelSelector(labelSelector)); err != nil {
		return nil, err
	}
	return pods.Items, nil
}

func waitForPodReady(ctx context.Context, client klient.Client, namespace, name string) error {
	ticker := time.NewTicker(statusPollInterval)
	defer ticker.Stop()

	log.V(4).InfoS("Polling pod readiness", "namespace", namespace, "podName", name)
	for {
		var pod corev1.Pod
		err := client.Resources().Get(ctx, name, namespace, &pod)
		if err != nil {
			if apierrors.IsNotFound(err) {
				// Pod not yet observed.
			} else {
				return err
			}
		} else if isPodReady(&pod) {
			log.V(4).InfoS("Pod is ready", "namespace", namespace, "podName", name)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for pod %s ready: %w", name, ctx.Err())
		case <-ticker.C:
		}
	}
}

func isPodReady(pod *corev1.Pod) bool {
	if pod.Status.Phase != corev1.PodRunning {
		return false
	}
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func execNerdctlLoad(ctx context.Context, clientset kubernetes.Interface, cfg *rest.Config, namespace, podName string, reader io.Reader, idleTimeout time.Duration) error {
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var idleTriggered atomic.Bool
	var monitor *idleTimeoutReader
	if idleTimeout > 0 {
		monitor = newIdleTimeoutReader(reader, idleTimeout, func() {
			idleTriggered.Store(true)
			cancel()
		})
		reader = monitor
		defer monitor.Stop()
	}

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   []string{"nerdctl", "-n", "k8s.io", "load"},
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(cfg, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("preloader: creating exec for pod %s failed: %w", podName, err)
	}

	var stdout, stderr bytes.Buffer
	log.V(3).InfoS("Starting nerdctl load exec", "namespace", namespace, "podName", podName)
	streamErr := exec.StreamWithContext(execCtx, remotecommand.StreamOptions{
		Stdin:  reader,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if idleTriggered.Load() {
		log.V(0).ErrorS(errImageStreamIdle, "nerdctl load stalled", "namespace", namespace, "podName", podName, "idleTimeout", idleTimeout)
		return errImageStreamIdle
	}
	if streamErr != nil {
		log.V(0).ErrorS(streamErr, "nerdctl load failed", "namespace", namespace, "podName", podName)
		return fmt.Errorf("preloader: nerdctl load failed on pod %s: %w (stdout: %s, stderr: %s)", podName, streamErr, stdout.String(), stderr.String())
	}
	log.V(3).InfoS("nerdctl load completed", "namespace", namespace, "podName", podName)
	return nil
}

var errImageStreamIdle = errors.New("preloader: nerdctl load stalled due to inactivity")

func runWithTimeout(parent context.Context, timeout time.Duration, fn func(context.Context) error) error {
	var (
		stageCtx context.Context
		cancel   context.CancelFunc
	)
	if timeout > 0 {
		stageCtx, cancel = context.WithTimeout(parent, timeout)
	} else {
		stageCtx, cancel = context.WithCancel(parent)
	}
	defer cancel()
	return fn(stageCtx)
}

type idleTimeoutReader struct {
	src      io.Reader
	idle     time.Duration
	notify   func()
	touchCh  chan struct{}
	stopCh   chan struct{}
	stopOnce sync.Once
}

func newIdleTimeoutReader(src io.Reader, idle time.Duration, notify func()) *idleTimeoutReader {
	if idle <= 0 {
		return &idleTimeoutReader{src: src}
	}
	if notify == nil {
		notify = func() {}
	}
	r := &idleTimeoutReader{
		src:     src,
		idle:    idle,
		notify:  notify,
		touchCh: make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
	}
	r.touch()
	go r.watch()
	return r
}

func (r *idleTimeoutReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if r.idle > 0 && n > 0 {
		r.touch()
	}
	if err != nil {
		r.Stop()
	}
	return n, err
}

func (r *idleTimeoutReader) touch() {
	if r.idle <= 0 {
		return
	}
	select {
	case r.touchCh <- struct{}{}:
	default:
	}
}

func (r *idleTimeoutReader) watch() {
	timer := time.NewTimer(r.idle)
	defer timer.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-r.touchCh:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(r.idle)
		case <-timer.C:
			r.notify()
			r.Stop()
			return
		}
	}
}

func (r *idleTimeoutReader) Stop() {
	if r.idle <= 0 {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stopCh)
	})
}
