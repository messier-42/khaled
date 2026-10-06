package k8sattestation_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	kubetesting "k8s.io/client-go/testing"

	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping/k8sattestation"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
)

const testAppName = "app"

func checkClaim(t *testing.T, claims map[string]any, key, want string) {
	t.Helper()
	got, ok := claims[key]
	if !ok {
		t.Errorf("claims[%q] missing", key)
		return
	}
	if got != want {
		t.Errorf("claims[%q] = %v, want %q", key, got, want)
	}
}

// identity builds a SPIFFEIdentity carrying the given SPIFFE ID string.
func identity(t *testing.T, uri string) clientauthn.SPIFFEIdentity {
	t.Helper()
	id := spiffeid.RequireFromString(uri)
	return clientauthn.NewSPIFFEIdentity(id, nil)
}

// testPod builds a corev1.Pod with the fields the mapper reads.
func testPod(ns, name, uid, sa, node string, image string, labels, annotations map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			UID:         types.UID(uid),
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: sa,
			NodeName:           node,
			Containers: []corev1.Container{
				{Name: testAppName, Image: image},
			},
		},
	}
}

func TestMapSuccess(t *testing.T) {
	pod := testPod("prod", "pod-a", "uid-1", testAppName, "node-7",
		"ghcr.io/org/app@sha256:deadbeef",
		map[string]string{"tier": "critical"},
		map[string]string{"cabe/classification": "secret"},
	)
	client := fake.NewSimpleClientset(pod)
	m := k8sattestation.NewWithClient(client, k8sattestation.Config{})
	defer m.Close() // best effort

	p, err := m.Map(context.Background(),
		identity(t, "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1"))
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	checkClaim(t, p.Claims, "trust-domain", "example.org")
	checkClaim(t, p.Claims, "namespace", "prod")
	checkClaim(t, p.Claims, "service-account", testAppName)
	checkClaim(t, p.Claims, "pod-name", "pod-a")
	checkClaim(t, p.Claims, "pod-uid", "uid-1")
	checkClaim(t, p.Claims, "node-name", "node-7")

	images, ok := p.Claims["images"].(map[string]any)
	if !ok {
		t.Fatalf("images claim has wrong type: %T", p.Claims["images"])
	}
	if got := images[testAppName]; got != "ghcr.io/org/app@sha256:deadbeef" {
		t.Errorf("images.app = %v", got)
	}

	labels, _ := p.Claims["labels"].(map[string]any)
	if got := labels["tier"]; got != "critical" {
		t.Errorf("labels.tier = %v", got)
	}
	anns, _ := p.Claims["annotations"].(map[string]any)
	if got := anns["cabe/classification"]; got != "secret" {
		t.Errorf("annotations[cabe/classification] = %v", got)
	}
}

// TestMapIncludesInitAndEphemeralContainersWithPrefixes pins the
// schema contract that the `images` claim contains every container
// in the pod — main, init, and ephemeral — keyed by container name
// with "init:" / "ephemeral:" prefixes for the latter two. A Cedar
// policy written against `principal.images["app"]` sees only the
// main container's image; a malicious init container also named
// "app" surfaces at key "init:app", so policies requiring a
// specific image digest for key "app" cannot be bypassed by
// shadowing the main container's name from the init or ephemeral
// list.
//
// The prefixes use ':' — which is not a legal character in a
// Kubernetes container name (RFC 1123 label) — so bare main-
// container names and prefixed names can never collide.
//
// See SPEC-PROPOSALS.md "Init / ephemeral container images in
// claims".
func TestMapIncludesInitAndEphemeralContainersWithPrefixes(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod",
			Name:      "pod-a",
			UID:       types.UID("uid-1"),
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: testAppName,
			NodeName:           "node-7",
			Containers: []corev1.Container{
				{Name: testAppName, Image: "ghcr.io/org/app@sha256:main"},
			},
			InitContainers: []corev1.Container{
				{Name: "init-tool", Image: "ghcr.io/org/init@sha256:init"},
				// Edge: an init container with the same name as
				// a main container. The prefix keeps the two
				// namespaces disjoint so the main container's
				// image is not shadowed.
				{Name: testAppName, Image: "ghcr.io/org/shadow@sha256:shadow"},
			},
			EphemeralContainers: []corev1.EphemeralContainer{
				{EphemeralContainerCommon: corev1.EphemeralContainerCommon{
					Name: "debug", Image: "ghcr.io/org/debug@sha256:eph",
				}},
			},
		},
	}
	client := fake.NewSimpleClientset(pod)
	m := k8sattestation.NewWithClient(client, k8sattestation.Config{})
	defer m.Close() // best effort

	p, err := m.Map(context.Background(),
		identity(t, "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1"))
	if err != nil {
		t.Fatalf("map: %v", err)
	}

	images, ok := p.Claims["images"].(map[string]any)
	if !ok {
		t.Fatalf("images claim has wrong type: %T", p.Claims["images"])
	}
	if got := images[testAppName]; got != "ghcr.io/org/app@sha256:main" {
		t.Errorf("images[app] = %v, want main-container image", got)
	}
	if got := images["init:init-tool"]; got != "ghcr.io/org/init@sha256:init" {
		t.Errorf("images[init:init-tool] = %v, want init-container image", got)
	}
	if got := images["init:app"]; got != "ghcr.io/org/shadow@sha256:shadow" {
		t.Errorf("images[init:app] = %v, want shadow init-container image (main app must not be shadowed)", got)
	}
	if got := images["ephemeral:debug"]; got != "ghcr.io/org/debug@sha256:eph" {
		t.Errorf("images[ephemeral:debug] = %v, want ephemeral-container image", got)
	}
	if n := len(images); n != 4 {
		t.Errorf("images map has %d entries, want 4 (1 main + 2 init + 1 ephemeral)", n)
	}
}

func TestMapRejectsNonSPIFFEIdentity(t *testing.T) {
	client := fake.NewSimpleClientset()
	m := k8sattestation.NewWithClient(client, k8sattestation.Config{})
	defer m.Close() // best effort

	_, err := m.Map(context.Background(), bogusIdentity("x"))
	if !errors.Is(err, claimsmapping.ErrIdentityUnsupported) {
		t.Errorf("err = %v, want ErrIdentityUnsupported", err)
	}
}

type bogusIdentity string

func (b bogusIdentity) URI() string { return string(b) }

func TestMapRejectsNonPodSPIFFEID(t *testing.T) {
	client := fake.NewSimpleClientset()
	m := k8sattestation.NewWithClient(client, k8sattestation.Config{})
	defer m.Close() // best effort

	_, err := m.Map(context.Background(),
		identity(t, "spiffe://example.org/workloads/svc"))
	if !errors.Is(err, claimsmapping.ErrPrincipalUnknown) {
		t.Errorf("err = %v, want ErrPrincipalUnknown", err)
	}
}

func TestMapPodNotFound(t *testing.T) {
	client := fake.NewSimpleClientset() // no pods
	m := k8sattestation.NewWithClient(client, k8sattestation.Config{})
	defer m.Close() // best effort

	_, err := m.Map(context.Background(),
		identity(t, "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1"))
	if !errors.Is(err, claimsmapping.ErrPrincipalUnknown) {
		t.Errorf("err = %v, want ErrPrincipalUnknown", err)
	}
}

func TestMapUIDMismatch(t *testing.T) {
	pod := testPod("prod", "pod-a", "real-uid", testAppName, "node-7", "img", nil, nil)
	client := fake.NewSimpleClientset(pod)
	m := k8sattestation.NewWithClient(client, k8sattestation.Config{})
	defer m.Close() // best effort

	_, err := m.Map(context.Background(),
		identity(t, "spiffe://example.org/ns/prod/sa/app/pod/pod-a/attacker-uid"))
	if !errors.Is(err, claimsmapping.ErrPrincipalUnknown) {
		t.Errorf("err = %v, want ErrPrincipalUnknown for UID mismatch", err)
	}
}

func TestMapServiceAccountMismatch(t *testing.T) {
	pod := testPod("prod", "pod-a", "uid-1", "real-sa", "node-7", "img", nil, nil)
	client := fake.NewSimpleClientset(pod)
	m := k8sattestation.NewWithClient(client, k8sattestation.Config{})
	defer m.Close() // best effort

	_, err := m.Map(context.Background(),
		identity(t, "spiffe://example.org/ns/prod/sa/attacker-sa/pod/pod-a/uid-1"))
	if !errors.Is(err, claimsmapping.ErrPrincipalUnknown) {
		t.Errorf("err = %v, want ErrPrincipalUnknown for SA mismatch", err)
	}
}

func TestMapCachesSuccess(t *testing.T) {
	pod := testPod("prod", "pod-a", "uid-1", testAppName, "node-7", "img", nil, nil)
	client := fake.NewSimpleClientset(pod)

	var gets atomic.Int64
	client.PrependReactor("get", "pods", func(_ kubetesting.Action) (bool, runtime.Object, error) {
		gets.Add(1)
		return false, nil, nil // fall through to default handler
	})

	m := k8sattestation.NewWithClient(client, k8sattestation.Config{TTL: time.Hour})
	defer m.Close() // best effort

	id := identity(t, "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1")
	for i := range 5 {
		if _, err := m.Map(context.Background(), id); err != nil {
			t.Fatalf("map #%d: %v", i, err)
		}
	}
	if got := gets.Load(); got != 1 {
		t.Errorf("api GETs = %d, want 1 (cache should absorb the rest)", got)
	}
}

func TestMapNegativeCachesFailure(t *testing.T) {
	client := fake.NewSimpleClientset() // no pods

	var gets atomic.Int64
	client.PrependReactor("get", "pods", func(_ kubetesting.Action) (bool, runtime.Object, error) {
		gets.Add(1)
		return false, nil, nil
	})

	m := k8sattestation.NewWithClient(client, k8sattestation.Config{NegativeTTL: time.Hour})
	defer m.Close() // best effort

	id := identity(t, "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1")
	for i := range 5 {
		if _, err := m.Map(context.Background(), id); !errors.Is(err, claimsmapping.ErrPrincipalUnknown) {
			t.Fatalf("map #%d: err = %v", i, err)
		}
	}
	if got := gets.Load(); got != 1 {
		t.Errorf("api GETs = %d, want 1 (negative cache should absorb the rest)", got)
	}
}

// TestMapDoesNotCacheTransientErrors verifies that general API errors
// (not IsNotFound) are re-attempted rather than negative-cached. A
// single transient failure must not lock a valid workload out for
// the full NegativeTTL.
func TestMapDoesNotCacheTransientErrors(t *testing.T) {
	client := fake.NewSimpleClientset()
	var gets atomic.Int64
	var failed atomic.Bool
	failed.Store(true)

	client.PrependReactor("get", "pods", func(_ kubetesting.Action) (bool, runtime.Object, error) {
		n := gets.Add(1)
		if n == 1 {
			return true, nil, errors.New("simulated transient API error")
		}
		return true, testPod("prod", "pod-a", "uid-1", testAppName, "node-7", "img", nil, nil), nil
	})

	m := k8sattestation.NewWithClient(client, k8sattestation.Config{NegativeTTL: time.Hour, TTL: time.Hour})
	defer m.Close() // best effort

	id := identity(t, "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1")

	// First call: transient error propagates. Must NOT be
	// ErrPrincipalUnknown (negative caching would rewrap it).
	_, err := m.Map(context.Background(), id)
	if err == nil {
		t.Fatal("expected first call to error")
	}
	if errors.Is(err, claimsmapping.ErrPrincipalUnknown) {
		t.Fatalf("transient error must not be returned as ErrPrincipalUnknown: %v", err)
	}

	// Second call: the transient has cleared. Must succeed,
	// proving the cache did not hold the failure.
	if _, err := m.Map(context.Background(), id); err != nil {
		t.Fatalf("expected second call to succeed, got %v", err)
	}
	if got := gets.Load(); got != 2 {
		t.Errorf("api GETs = %d, want 2 (transient must not be cached)", got)
	}
}

// TestMapCacheRespectsTTL confirms that moving the injected clock
// past TTL causes the next lookup to miss the cache and re-fetch.
func TestMapCacheRespectsTTL(t *testing.T) {
	pod := testPod("prod", "pod-a", "uid-1", testAppName, "node-7", "img", nil, nil)
	client := fake.NewSimpleClientset(pod)
	var gets atomic.Int64
	client.PrependReactor("get", "pods", func(_ kubetesting.Action) (bool, runtime.Object, error) {
		gets.Add(1)
		return false, nil, nil
	})

	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	m := k8sattestation.NewWithClock(client, k8sattestation.Config{TTL: 30 * time.Second}, clock)
	defer m.Close() // best effort

	id := identity(t, "spiffe://example.org/ns/prod/sa/app/pod/pod-a/uid-1")
	if _, err := m.Map(context.Background(), id); err != nil {
		t.Fatalf("first map: %v", err)
	}
	// Advance past TTL.
	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()

	if _, err := m.Map(context.Background(), id); err != nil {
		t.Fatalf("second map: %v", err)
	}
	if got := gets.Load(); got != 2 {
		t.Errorf("api GETs = %d, want 2 (cache should miss after TTL expiry)", got)
	}
}
