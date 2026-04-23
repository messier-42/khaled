package kutest

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/e2e-framework/klient"
)

// PatchKhaledConfigMap mutates the live khaled ConfigMap in place by
// reading the current state, applying mutate, and writing it back via
// Update. Used by Stage 2 ConfigSource live-reload Features to flip
// chart-rendered config out from under the running khaled pod and
// observe whether the k8s configsource plugin's watch loop picks up
// the change.
//
// The chart's StatefulSet pod template is intentionally NOT annotated
// with a ConfigMap checksum (see chart/khaled/values.yaml comment), so
// this update will *not* trigger a pod rollout. That's the whole
// point: we want to prove khaled re-reads the ConfigMap via its watch
// without restarting.
//
// The mutate callback receives a deep copy of the live ConfigMap and
// may modify any field; namespace/name are preserved on write.
func PatchKhaledConfigMap(ctx context.Context, client klient.Client, mutate func(*corev1.ConfigMap)) error {
	const cmName = "khaled-config"
	cm := &corev1.ConfigMap{}
	if err := client.Resources().Get(ctx, cmName, KhaledNamespace, cm); err != nil {
		return fmt.Errorf("get configmap %s/%s: %w", KhaledNamespace, cmName, err)
	}
	updated := cm.DeepCopy()
	mutate(updated)
	if err := client.Resources().Update(ctx, updated); err != nil {
		return fmt.Errorf("update configmap %s/%s: %w", KhaledNamespace, cmName, err)
	}
	return nil
}

// DeleteKhaledConfigMap removes the live khaled ConfigMap entirely.
// Khaled's k8s configsource plugin observes the delete, surfaces an
// error to its updateCh, and continues serving from last-good. Used
// by the DeleteRecreate sub-Feature.
func DeleteKhaledConfigMap(ctx context.Context, client klient.Client) error {
	const cmName = "khaled-config"
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: KhaledNamespace}}
	if err := client.Resources().Delete(ctx, cm); err != nil {
		return fmt.Errorf("delete configmap %s/%s: %w", KhaledNamespace, cmName, err)
	}
	return nil
}

// CreateKhaledConfigMap creates a fresh khaled ConfigMap. mutate
// supplies the data fields; the metadata (name/namespace/labels) is
// populated to match what the chart would render so Khaled's watch
// (filtered by metadata.name) picks it back up.
func CreateKhaledConfigMap(ctx context.Context, client klient.Client, data map[string]string) error {
	const cmName = "khaled-config"
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cmName,
			Namespace: KhaledNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":     "khaled",
				"app.kubernetes.io/instance": "khaled",
			},
		},
		Data: data,
	}
	if err := client.Resources().Create(ctx, cm); err != nil {
		return fmt.Errorf("create configmap %s/%s: %w", KhaledNamespace, cmName, err)
	}
	return nil
}

// AwaitConfigReload polls predicate at a tight interval until it
// returns nil or the timeout elapses. Predicate is expected to do
// something observable (e.g. run cabetool encap and check for a
// policy-denied error vs. success) and return nil once the post-
// reload behavior matches.
//
// The poll interval intentionally undershoots khaled's watch latency
// so we observe the reload as soon as it happens, not on a fixed
// 5-second cadence.
func AwaitConfigReload(ctx context.Context, timeout time.Duration, predicate func(context.Context) error) error {
	deadline := time.Now().Add(timeout)
	const interval = 250 * time.Millisecond
	var lastErr error
	for {
		if err := predicate(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("config reload not observed within %v: %w", timeout, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}
