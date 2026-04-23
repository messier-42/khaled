// Package k8s implements the configsource.Source interface by
// reading a Kubernetes ConfigMap and tracking it via the Kubernetes
// watch API. The ConfigMap is identified by namespace and name.
package k8s

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/messier-42/khaled/pkg/backoff"
	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin/configsource"
)

var defaultWatchBackoff = backoff.Config{
	Initial: 500 * time.Millisecond,
	Max:     30 * time.Second,
	Jitter:  0.25,
}

type Source struct {
	client     kubernetes.Interface
	name       string
	namespace  string
	validate   configsource.ValidateFunc
	updateCh   chan error
	cancel     context.CancelFunc
	backoffCfg backoff.Config

	mu      sync.RWMutex
	current *config.Snapshot
	loadErr error
}

var _ configsource.Source = &Source{}

// New creates a Kubernetes-backed config source.
func New(configSpec string, namespace string, validate configsource.ValidateFunc) (*Source, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("create in-cluster kubernetes config: %w", err)
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create kubernetes client: %w", err)
	}

	return newWithClient(context.Background(), client, configSpec, namespace, validate)
}

func newWithClient(parent context.Context, client kubernetes.Interface, configSpec, namespace string, validate configsource.ValidateFunc) (*Source, error) {
	return newWithClientOpts(parent, client, configSpec, namespace, validate, defaultWatchBackoff)
}

func newWithClientOpts(parent context.Context, client kubernetes.Interface, configSpec, namespace string, validate configsource.ValidateFunc, backoffCfg backoff.Config) (*Source, error) {
	name, err := parseConfigMapSpec(configSpec)
	if err != nil {
		return nil, err
	}
	if namespace == "" {
		return nil, errors.New("k8s config namespace is required")
	}

	ctx, cancel := context.WithCancel(parent)
	source := &Source{
		client:     client,
		name:       name,
		namespace:  namespace,
		validate:   validate,
		updateCh:   make(chan error, 1),
		cancel:     cancel,
		backoffCfg: backoffCfg,
	}

	source.reload(ctx, false)
	go source.watch(ctx)
	return source, nil
}

func (s *Source) Current() (config.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.loadErr != nil {
		return config.Snapshot{}, s.loadErr
	}

	if s.current == nil {
		panic("k8s.Source invariant violated: current and loadErr are both nil")
	}

	return *s.current, nil
}

func (s *Source) UpdateChan() <-chan error {
	return s.updateCh
}

func (s *Source) Close() error {
	s.cancel()
	return nil
}

func (s *Source) watch(ctx context.Context) {
	b := s.backoffCfg.New()
	for {
		watcher, err := s.client.CoreV1().ConfigMaps(s.namespace).Watch(ctx, metav1.ListOptions{
			FieldSelector: fields.OneTermEqualSelector("metadata.name", s.name).String(),
		})
		if err != nil {
			if ctx.Err() != nil {
				return
			}

			wrappedErr := fmt.Errorf("watch configmap %s/%s: %w", s.namespace, s.name, err)
			s.sendUpdate(wrappedErr)

			slog.Warn("k8s configsource: watch establish failed, retrying",
				"namespace", s.namespace,
				"name", s.name,
				"backoff", b.Current(),
				"error", err,
			)
			if !b.Wait(ctx) {
				return
			}

			continue
		}

		// Successful watch; reset the backoff.
		b.Reset()

		if !s.consumeWatch(ctx, watcher) {
			return
		}

		// consumeWatch returned true, meaning the watcher terminated
		// without context cancellation (channel closed, bookmark
		// expired, etc.). Loop around and re-establish after a pause.
		if !b.WaitInitial(ctx) {
			return
		}
	}
}

func (s *Source) consumeWatch(ctx context.Context, watcher watch.Interface) bool {
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return false
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return ctx.Err() == nil
			}

			switch event.Type {
			case watch.Added, watch.Modified, watch.Deleted:
				s.reload(ctx, true)
			case watch.Bookmark:
				// Bookmark events are heartbeats carrying an
				// updated ResourceVersion; no ConfigMap content
				// change. Safe to ignore.
			case watch.Error:
				// A typed error event (e.g. HTTP 410 Gone for a
				// stale ResourceVersion) means the watcher is no
				// longer tracking changes. Drop it and let the
				// outer loop re-establish a fresh watch.
				slog.Warn("k8s configsource: watch error event, reconnecting",
					"namespace", s.namespace,
					"name", s.name,
					"object", event.Object,
				)
				return ctx.Err() == nil
			}
		}
	}
}

// reload holds s.mu write-locked across the validate-and-swap so the
// ValidateFunc always sees the snapshot that is currently being
// served as oldConfig.
func (s *Source) reload(ctx context.Context, notify bool) {
	snapshot, err := s.loadCurrentConfigMap(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err == nil && s.validate != nil {
		if verr := s.validate(ctx, s.current, snapshot); verr != nil {
			err = fmt.Errorf("validate configmap %s/%s: %w", s.namespace, s.name, verr)
		}
	}

	if err != nil {
		if s.current == nil {
			s.loadErr = err
		}
		if notify {
			s.sendUpdate(err)
		}
		return
	}

	s.loadErr = nil
	s.current = &snapshot
	if notify {
		s.sendUpdate(nil)
	}
}

func (s *Source) sendUpdate(err error) {
	select {
	case s.updateCh <- err:
	default:
	}
}

func (s *Source) loadCurrentConfigMap(ctx context.Context) (config.Snapshot, error) {
	configMap, err := s.client.CoreV1().ConfigMaps(s.namespace).Get(ctx, s.name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return config.Snapshot{}, fmt.Errorf("configmap %s/%s not found", s.namespace, s.name)
		}
		return config.Snapshot{}, fmt.Errorf("get configmap %s/%s: %w", s.namespace, s.name, err)
	}

	data, format, err := selectConfigData(configMap)
	if err != nil {
		return config.Snapshot{}, err
	}

	switch format {
	case "cbor":
		snap, err := configsource.DecodeCBOR(data)
		if err != nil {
			return config.Snapshot{}, fmt.Errorf("cannot decode config data as CBOR: %w", err)
		}
		return snap, nil
	case "yaml":
		snap, err := configsource.DecodeYAML(data)
		if err != nil {
			return config.Snapshot{}, fmt.Errorf("cannot decode config data as YAML: %w", err)
		}
		return snap, nil
	default:
		return config.Snapshot{}, fmt.Errorf("unsupported config format %q", format)
	}
}

func selectConfigData(configMap *corev1.ConfigMap) ([]byte, string, error) {
	type candidate struct {
		name   string
		format string
		data   []byte
	}

	var candidates []candidate
	if value, ok := configMap.Data["khaled.yaml"]; ok {
		candidates = append(candidates, candidate{name: `data["khaled.yaml"]`, format: "yaml", data: []byte(value)})
	}
	if value, ok := configMap.BinaryData["khaled.yaml"]; ok {
		candidates = append(candidates, candidate{name: `binaryData["khaled.yaml"]`, format: "yaml", data: value})
	}
	if value, ok := configMap.BinaryData["khaled.cbor"]; ok {
		candidates = append(candidates, candidate{name: `binaryData["khaled.cbor"]`, format: "cbor", data: value})
	}

	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("configmap %s/%s does not contain khaled.yaml or khaled.cbor", configMap.Namespace, configMap.Name)
	}
	if len(candidates) > 1 {
		names := make([]string, 0, len(candidates))
		for _, candidate := range candidates {
			names = append(names, candidate.name)
		}
		return nil, "", fmt.Errorf("configmap %s/%s has multiple config entries set: %s", configMap.Namespace, configMap.Name, strings.Join(names, ", "))
	}

	return candidates[0].data, candidates[0].format, nil
}

func parseConfigMapSpec(spec string) (string, error) {
	if spec == "" {
		return "", errors.New("k8s config spec is required")
	}

	parts := strings.Split(spec, "/")
	switch len(parts) {
	case 1:
		return parts[0], nil
	case 2:
		if parts[0] != "configmap" || parts[1] == "" {
			return "", fmt.Errorf("invalid k8s config spec %q", spec)
		}
		return parts[1], nil
	default:
		return "", fmt.Errorf("invalid k8s config spec %q", spec)
	}
}
