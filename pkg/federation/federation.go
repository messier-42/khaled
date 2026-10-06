// Package federation manages public peer discovery and volatile SFLP reuse.
// Local private Federation Keys belong exclusively to the unified key-storage
// plugin. A Runtime is an immutable configuration snapshot; its bounded caches
// are synchronized. Replacing a Runtime discards caches, never stored keys.
//
// Recovery proves integrity and context agreement, not Origin authenticity.
// Callers must authorize each request, including cache hits. Recovery never
// contacts an Origin or discovery endpoint. The cache retains encrypted packages
// only; it is optional and provides no durability guarantee.
package federation

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cfar"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
)

// Config holds runtime policy, not private keys or their lifecycle schedules.
type Config struct {
	DomainID       string
	KeyOptions     keystorage.FederationKeyOptions
	IdentityMaxAge time.Duration
	CacheBytes     int
	CacheTTL       time.Duration
	Peers          []Peer
}

// Runtime holds one domain's federation configuration and references its store.
type Runtime struct {
	cfg      Config
	domain   keystorage.FederationDomain
	peers    map[string]*peerState
	mu       sync.Mutex
	packages map[string]*list.Element
	lru      list.List
	size     int
}
type cachedPackage struct {
	context string
	raw     []byte
	until   time.Time
	size    int
}

// New validates all peer inputs before binding/initializing durable local keys.
func New(ctx context.Context, domain keystorage.FederationDomain, cfg Config) (*Runtime, error) {
	if domain == nil || cfg.DomainID == "" {
		return nil, errors.New("federation: domain and domainID required")
	}
	if cfg.CacheBytes < 0 || cfg.CacheTTL < 0 || cfg.IdentityMaxAge < 0 || (cfg.CacheBytes > 0 && cfg.CacheTTL == 0) {
		return nil, errors.New("federation: invalid cache settings")
	}
	cfg.Peers = append([]Peer(nil), cfg.Peers...)
	r := &Runtime{cfg: cfg, domain: domain, peers: map[string]*peerState{}, packages: map[string]*list.Element{}}
	seen := map[string]bool{}
	for _, p := range cfg.Peers {
		if p.DomainID == cfg.DomainID || r.peers[p.DomainID] != nil {
			return nil, errors.New("federation: duplicate or self peer")
		}
		state, err := newPeer(p)
		if err != nil {
			return nil, err
		}
		if p.Identity != nil {
			for _, k := range p.Identity.Keys {
				id := string(k.PublicKey.Kid())
				if seen[id] {
					return nil, errors.New("federation: conflicting peer FKID")
				}
				seen[id] = true
			}
		}
		r.peers[p.DomainID] = state
	}
	if err := domain.BindFederation(ctx, cfg.DomainID, cfg.KeyOptions); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Runtime) DomainID() string { return r.cfg.DomainID }
func (r *Runtime) Targets() []string {
	out := make([]string, 0, len(r.cfg.Peers))
	for _, p := range r.cfg.Peers {
		out = append(out, p.DomainID)
	}
	return out
}

// Identity computes both advertisement and freshness from the persisted key
// timeline. Private key parameters are never returned. Multiple current keys
// and advertised retired keys are valid.
func (r *Runtime) Identity(ctx context.Context, now time.Time) (ckapraw.FederationIdentity, time.Time, error) {
	out := ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: r.cfg.DomainID, Keys: []ckapraw.FederationPublicKey{}}
	until := now.Add(r.cfg.IdentityMaxAge)
	for k, err := range r.domain.ListFederationKeys(ctx) {
		if err != nil {
			return out, time.Time{}, err
		}
		if k.Advertised(now) {
			out.Keys = append(out.Keys, ckapraw.FederationPublicKey{PublicKey: k.PublicKey(), Status: string(k.Status(now))})
		}
		for _, transition := range []time.Time{k.ActivationTime(), k.RetirementTime(), k.UnadvertiseTime()} {
			if transition.After(now) && transition.Before(until) {
				until = transition
			}
		}
	}
	return out, until, nil
}

// Recipients resolves only targets already authorized by the caller.
func (r *Runtime) Recipients(ctx context.Context, targets []string, now time.Time) ([]key.Key, error) {
	var out []key.Key
	seen := map[string]bool{}
	for _, target := range targets {
		p := r.peers[target]
		if p == nil {
			return nil, fmt.Errorf("federation: unknown target %q", target)
		}
		keys, err := p.recipients(ctx, now)
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			id := string(k.Kid())
			if seen[id] {
				return nil, errors.New("federation: FKID used by multiple targets")
			}
			seen[id] = true
			out = append(out, k)
		}
	}
	return out, nil
}

func contextID(c cfar.LeaseContext) string {
	return string(key.MustMarshalCBOR([]any{c.OriginDomain, []byte(c.AttributeSet.Repr()), c.LeaseRef}))
}

// Recover tries quoted packages before the bounded cache, using all retained
// private keys regardless of advertisement status. Each cached package is
// decrypted again; successful decryption never replaces caller authorization.
func (r *Runtime) Recover(ctx context.Context, lc cfar.LeaseContext, packages cabe.FLPSet, now time.Time) (*cabe.LKAINonCaptive, error) {
	var keys []keystorage.FederationKey
	for k, err := range r.domain.ListFederationKeys(ctx) {
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	// Storage handles perform cryptography without exporting private keys or
	// registering algorithm providers. Try every retained key for each package.
	recoverPackage := func(raw []byte) (*cabe.LKAINonCaptive, error) {
		for _, k := range keys {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			got, err := k.Recover(ctx, lc, raw)
			if err == nil {
				return got, nil
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, cfar.ErrNoUsablePackage
	}
	id := contextID(lc)
	for _, raw := range packages {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		got, err := recoverPackage(raw)
		if err == nil {
			r.remember(id, raw, now)
			return got, nil
		}
		if !errors.Is(err, cfar.ErrNoUsablePackage) {
			return nil, err
		}
	}
	if raw := r.known(id, now); raw != nil {
		return recoverPackage(raw)
	}
	return nil, cfar.ErrNoUsablePackage
}
func (r *Runtime) remove(e *list.Element) {
	v := e.Value.(cachedPackage)
	delete(r.packages, v.context)
	r.size -= v.size
	r.lru.Remove(e)
}
func (r *Runtime) remember(id string, raw []byte, now time.Time) {
	size := len(id) + len(raw) + 128
	if r.cfg.CacheBytes == 0 || size > r.cfg.CacheBytes {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.packages[id]; e != nil {
		r.remove(e)
	}
	for r.size+size > r.cfg.CacheBytes {
		r.remove(r.lru.Back())
	}
	r.packages[id] = r.lru.PushFront(cachedPackage{id, bytes.Clone(raw), now.Add(r.cfg.CacheTTL), size})
	r.size += size
}
func (r *Runtime) known(id string, now time.Time) []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.packages[id]
	if e == nil {
		return nil
	}
	v := e.Value.(cachedPackage)
	if !now.Before(v.until) {
		r.remove(e)
		return nil
	}
	r.lru.MoveToFront(e)
	return bytes.Clone(v.raw)
}
