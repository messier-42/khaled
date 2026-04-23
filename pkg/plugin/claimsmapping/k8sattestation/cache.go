package k8sattestation

import (
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	corev1 "k8s.io/api/core/v1"
)

// cacheKey identifies a pod attestation result. PodUID is part of the
// key so that an attacker cannot reuse a stale SVID against a
// recreated pod with the same (namespace, podName) but a different
// UID: such a request misses the cache, hits the API server, and
// fails UID verification before any data is returned.
type cacheKey struct {
	Namespace string
	PodName   string
	PodUID    string
}

// cacheEntry is one entry in the attestation cache. Exactly one of
// pod or errReason is set.
//
// errReason is a short identifier for the kind of failure (e.g.
// "not-found", "uid-mismatch"); the full error is not cached because
// we do not re-surface it to the caller — negative-cache hits are
// transformed back into ErrPrincipalUnknown.
type cacheEntry struct {
	pod       *corev1.Pod
	errReason string
	expiresAt time.Time
}

// ttlLRU wraps an LRU cache with per-entry expiry. Positive
// (successful attestation) and negative (confirmed failure) entries
// share a single cache but carry independent expiry deadlines in
// cacheEntry.expiresAt so the two TTLs can be tuned separately.
//
// The underlying LRU is internally synchronized; the clock is only
// used for expiry decisions and tests inject a controllable clock
// so TTL-expiry behaviour is deterministic and does not require
// real sleeps.
type ttlLRU struct {
	cache *lru.Cache[cacheKey, cacheEntry]
	clock func() time.Time
}

// newTTLLRU returns a cache bounded to capacity entries. clock is
// the time source used for expiry checks; pass time.Now in
// production.
func newTTLLRU(capacity int, clock func() time.Time) *ttlLRU {
	if capacity < 1 {
		capacity = 1
	}
	if clock == nil {
		clock = time.Now
	}
	// lru.New only errors on size < 1, which we just normalized.
	c, _ := lru.New[cacheKey, cacheEntry](capacity)
	return &ttlLRU{cache: c, clock: clock}
}

// get returns (entry, true) if a non-expired entry exists. An expired
// entry is removed and (zero, false) is returned.
func (c *ttlLRU) get(key cacheKey) (cacheEntry, bool) {
	entry, ok := c.cache.Get(key)
	if !ok {
		return cacheEntry{}, false
	}
	if c.clock().After(entry.expiresAt) {
		c.cache.Remove(key)
		return cacheEntry{}, false
	}
	return entry, true
}

// put inserts or replaces an entry. If capacity is exceeded, the
// least-recently-used entry is evicted by the underlying LRU.
func (c *ttlLRU) put(key cacheKey, value cacheEntry) {
	c.cache.Add(key, value)
}
