// Package k8sattestation implements the "k8s-attestation" Claims
// Mapping plugin, which is able to attest a SPIFFE identity against the
// Kubernetes API server and derive a fixed-schema set of claims about the
// originating workload (namespace, service account, pod, node, container images,
// labels, annotations).
//
// The plugin accepts only clientauthn.SPIFFEIdentity client identity objects
// (as produced by tls-spiffe) and works only with SVIDs issued using SPIFFE-IDs
// of the following form:
//
//	spiffe://<trust-domain>/ns/<ns>/sa/<sa>/pod/<pod-name>/<pod-uid>
//
// It works by parsing the SPIFFE-ID and querying the Kubernetes API for details
// regarding the Pod in question. Lookups are cached.
package k8sattestation

import (
	"context"
	"fmt"
	"regexp"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"golang.org/x/sync/singleflight"

	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// Default cache parameters. Short TTLs trade off attestation freshness
// against API-server load; values tuned conservatively for MVP.
const (
	defaultTTL         = 30 * time.Second
	defaultNegativeTTL = 5 * time.Second
	defaultMaxEntries  = 4096
)

// spiffeIDRegex matches the Kubernetes-pod SPIFFE ID layout. The
// format is:
//
//	spiffe://<td>/ns/<ns>/sa/<sa>/pod/<pod-name>/<pod-uid>
//
// Path components are non-empty and contain no slashes. Namespace,
// service account, and pod-name follow Kubernetes naming rules; the
// regex does not re-validate those, only the basic shape.
var spiffeIDRegex = regexp.MustCompile(`^spiffe://([^/]+)/ns/([^/]+)/sa/([^/]+)/pod/([^/]+)/([^/]+)$`)

// workloadRef is the parsed view of a SPIFFE ID in the form this plugin expects.
type workloadRef struct {
	TrustDomain    string
	Namespace      string
	ServiceAccount string
	PodName        string
	PodUID         string
}

func parseSPIFFEID(id string) (workloadRef, bool) {
	m := spiffeIDRegex.FindStringSubmatch(id)
	if m == nil {
		return workloadRef{}, false
	}
	return workloadRef{
		TrustDomain:    m[1],
		Namespace:      m[2],
		ServiceAccount: m[3],
		PodName:        m[4],
		PodUID:         m[5],
	}, true
}

// Config provides plugin configuration. Any zero-valued field takes the built-in
// default.
type Config struct {
	// TTL is how long a successful attestation is reused.
	TTL time.Duration

	// NegativeTTL is how long a failed attestation is cached.
	// Prevents an attacker holding a bad SVID from hammering the
	// Kubernetes API.
	NegativeTTL time.Duration

	// MaxEntries bounds the cache size.
	MaxEntries int
}

func (c Config) withDefaults() Config {
	if c.TTL <= 0 {
		c.TTL = defaultTTL
	}
	if c.NegativeTTL <= 0 {
		c.NegativeTTL = defaultNegativeTTL
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = defaultMaxEntries
	}
	return c
}

// Mapper is the k8s-attestation ClaimsMapper.
type Mapper struct {
	client kubernetes.Interface
	cfg    Config
	cache  *ttlLRU
	group  singleflight.Group
	// now is the clock used for cache expiry decisions; overridable
	// by tests.
	now func() time.Time
}

var _ claimsmapping.ClaimsMapper = &Mapper{}

// New builds a Mapper using an in-cluster Kubernetes client. Returns
// an error if the in-cluster configuration is unavailable (e.g.
// running outside a pod).
func New(cfg Config) (*Mapper, error) {
	rcfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("k8s-attestation: in-cluster config: %w", err)
	}

	client, err := kubernetes.NewForConfig(rcfg)
	if err != nil {
		return nil, fmt.Errorf("k8s-attestation: build kubernetes client: %w", err)
	}

	return NewWithClient(client, cfg), nil
}

// NewWithClient constructs a mapper using a specific Kubernetes client.
// It is intended for testing.
func NewWithClient(client kubernetes.Interface, cfg Config) *Mapper {
	cfg = cfg.withDefaults()
	return newWithClock(client, cfg, time.Now)
}

func newWithClock(client kubernetes.Interface, cfg Config, clock func() time.Time) *Mapper {
	return &Mapper{
		client: client,
		cfg:    cfg,
		cache:  newTTLLRU(cfg.MaxEntries, clock),
		now:    clock,
	}
}

func (m *Mapper) Close() error {
	return nil
}

// Map attests the identity against the Kubernetes API and returns a
// Principal.
func (m *Mapper) Map(ctx context.Context, id clientauthn.ClientIdentity) (policyengine.Principal, error) {
	spi, ok := id.(clientauthn.SPIFFEIdentity)
	if !ok {
		return policyengine.Principal{}, fmt.Errorf("%w: got %T", claimsmapping.ErrIdentityUnsupported, id)
	}

	ref, ok := parseSPIFFEID(spi.URI())
	if !ok {
		return policyengine.Principal{}, fmt.Errorf("%w: spiffe id %q does not match kubernetes pod format", claimsmapping.ErrPrincipalUnknown, spi.URI())
	}

	pod, err := m.attest(ctx, ref)
	if err != nil {
		return policyengine.Principal{}, err
	}

	return policyengine.Principal{
		URI:    spi.URI(),
		Claims: claimsFromPod(ref, pod),
	}, nil
}

// attest returns an attested pod for ref. Cached results are returned
// without an API call. Both successful and failed attestations are cached.
func (m *Mapper) attest(ctx context.Context, ref workloadRef) (*corev1.Pod, error) {
	key := cacheKey{Namespace: ref.Namespace, PodName: ref.PodName, PodUID: ref.PodUID}

	if entry, ok := m.cache.get(key); ok {
		if entry.pod != nil {
			return entry.pod, nil
		}
		return nil, fmt.Errorf("%w: %s", claimsmapping.ErrPrincipalUnknown, entry.errReason)
	}

	singleKey := ref.Namespace + "/" + ref.PodName + "/" + ref.PodUID
	type fetchResult struct {
		pod *corev1.Pod
		err error
	}
	resCh := m.group.DoChan(singleKey, func() (any, error) {
		pod, err := m.fetchAndAttest(context.WithoutCancel(ctx), ref)
		return fetchResult{pod: pod, err: err}, nil
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resCh:
		r := res.Val.(fetchResult)
		return r.pod, r.err
	}
}

// fetchAndAttest does the actual GET and verification, populates the
// cache, and returns the pod or a wrapped ErrPrincipalUnknown.
func (m *Mapper) fetchAndAttest(ctx context.Context, ref workloadRef) (*corev1.Pod, error) {
	pod, err := m.client.CoreV1().Pods(ref.Namespace).Get(ctx, ref.PodName, metav1.GetOptions{})
	if err != nil {
		// Only genuine attestation failures get negative-cached.
		// Transient errors must not poison the cache: doing so would lock valid
		// workloads out for NegativeTTL after network errors.
		//
		// Transients surface as an error to the caller without
		// being cached; the next request re-tries.
		if apierrors.IsNotFound(err) {
			m.cache.put(cacheKey{ref.Namespace, ref.PodName, ref.PodUID}, cacheEntry{
				errReason: "not-found",
				expiresAt: m.now().Add(m.cfg.NegativeTTL),
			})

			return nil, fmt.Errorf("%w: pod %s/%s not found", claimsmapping.ErrPrincipalUnknown, ref.Namespace, ref.PodName)
		}

		return nil, fmt.Errorf("k8s-attestation: get pod %s/%s: %w", ref.Namespace, ref.PodName, err)
	}

	// Verify pod UID matches the SPIFFE ID's UID. Without this, an attacker with
	// a stale SVID could authenticate against a recreated pod of the same name.
	if string(pod.UID) != ref.PodUID {
		m.cache.put(cacheKey{ref.Namespace, ref.PodName, ref.PodUID}, cacheEntry{
			errReason: "uid-mismatch",
			expiresAt: m.now().Add(m.cfg.NegativeTTL),
		})

		return nil, fmt.Errorf("%w: pod %s/%s UID mismatch", claimsmapping.ErrPrincipalUnknown, ref.Namespace, ref.PodName)
	}

	if pod.Spec.ServiceAccountName != ref.ServiceAccount {
		m.cache.put(cacheKey{ref.Namespace, ref.PodName, ref.PodUID}, cacheEntry{
			errReason: "sa-mismatch",
			expiresAt: m.now().Add(m.cfg.NegativeTTL),
		})

		return nil, fmt.Errorf("%w: pod %s/%s service-account mismatch", claimsmapping.ErrPrincipalUnknown, ref.Namespace, ref.PodName)
	}

	m.cache.put(cacheKey{ref.Namespace, ref.PodName, ref.PodUID}, cacheEntry{
		pod:       pod,
		expiresAt: m.now().Add(m.cfg.TTL),
	})

	return pod, nil
}

// claimsFromPod renders the fixed claim schema from an attested pod.
//
// The `images` claim includes every container in the pod — main
// (Spec.Containers), init (Spec.InitContainers), and ephemeral
// (Spec.EphemeralContainers) — keyed by container name. Init and
// ephemeral entries are prefixed "init:" and "ephemeral:"
// respectively; main containers keep their bare name.
func claimsFromPod(ref workloadRef, pod *corev1.Pod) map[string]any {
	imageCount := len(pod.Spec.Containers) + len(pod.Spec.InitContainers) + len(pod.Spec.EphemeralContainers)
	images := make(map[string]any, imageCount)
	for _, c := range pod.Spec.Containers {
		images[c.Name] = c.Image
	}
	for _, c := range pod.Spec.InitContainers {
		images["init:"+c.Name] = c.Image
	}
	for _, c := range pod.Spec.EphemeralContainers {
		images["ephemeral:"+c.Name] = c.Image
	}

	labels := make(map[string]any, len(pod.Labels))
	for k, v := range pod.Labels {
		labels[k] = v
	}

	annotations := make(map[string]any, len(pod.Annotations))
	for k, v := range pod.Annotations {
		annotations[k] = v
	}

	return map[string]any{
		"trust-domain":    ref.TrustDomain,
		"namespace":       ref.Namespace,
		"service-account": pod.Spec.ServiceAccountName,
		"pod-name":        pod.Name,
		"pod-uid":         string(pod.UID),
		"node-name":       pod.Spec.NodeName,
		"images":          images,
		"labels":          labels,
		"annotations":     annotations,
	}
}
