package federation

import (
	"bytes"
	"testing"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cfar"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/plugin/keystorage/disk"
)

const (
	testOriginDomain = "origin"
)

func testRuntime(t *testing.T) *Runtime {
	t.Helper()
	s, e := disk.New(t.Context(), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	d, e := s.DomainByName(t.Context(), "default")
	if e != nil {
		t.Fatal(e)
	}
	r, e := New(t.Context(), d.(keystorage.FederationDomain), Config{DomainID: "target", CacheBytes: 4096, CacheTTL: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestRecoveryKnownPackageAndContext(t *testing.T) {
	r := testRuntime(t)
	now := time.Now()
	identity, _, e := r.Identity(t.Context(), now)
	if e != nil {
		t.Fatal(e)
	}
	attrs, _ := attrset.New(map[string]any{"x": "y"})
	ctx := cfar.LeaseContext{OriginDomain: testOriginDomain, AttributeSet: attrs, LeaseRef: []byte("ref")}
	original := key.MustMarshalCBOR(ckapraw.COSEKey{1: 4, 3: 2, 5: []byte("foreign-base"), -1: []byte("012345678901234567890123")})
	raw, e := cfar.Generate(ctx, cabe.LKAINonCaptive{RawCOSEKey: original}, []key.Key{identity.Keys[0].PublicKey}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Recover(t.Context(), ctx, nil, now); e == nil {
		t.Fatal("unknown empty set succeeded")
	}
	for _, packages := range []cabe.FLPSet{{[]byte("irrelevant"), raw}, {}} {
		got, e := r.Recover(t.Context(), ctx, packages, now)
		if e != nil || !bytes.Equal(got.RawCOSEKey, original) {
			t.Fatalf("recover: %v", e)
		}
	}
	ctx.OriginDomain = "other"
	if _, e = r.Recover(t.Context(), ctx, nil, now); e == nil {
		t.Fatal("cross-origin cache hit")
	}
	ctx.OriginDomain = testOriginDomain
	if _, e = r.Recover(t.Context(), ctx, nil, now.Add(2*time.Minute)); e == nil {
		t.Fatal("expired package retained")
	}
}

func TestPackageCacheBudgetAndDisabled(t *testing.T) {
	r := testRuntime(t)
	now := time.Now()
	identity, _, err := r.Identity(t.Context(), now)
	if err != nil {
		t.Fatal(err)
	}
	attrs, _ := attrset.New(map[string]any{"cache": true})
	original := key.MustMarshalCBOR(ckapraw.COSEKey{1: 4, 3: 3, -1: make([]byte, 32)})
	contexts := []cfar.LeaseContext{
		{OriginDomain: testOriginDomain, AttributeSet: attrs, LeaseRef: []byte("first")},
		{OriginDomain: testOriginDomain, AttributeSet: attrs, LeaseRef: []byte("a longer second lease reference")},
	}
	packages := make([][]byte, 0, len(contexts))
	for _, lc := range contexts {
		raw, err := cfar.Generate(lc, cabe.LKAINonCaptive{RawCOSEKey: original}, []key.Key{identity.Keys[0].PublicKey}, nil)
		if err != nil {
			t.Fatal(err)
		}
		packages = append(packages, raw)
	}
	// Either entry must fit alone, but not both. Encoded ephemeral keys can
	// differ in length even when the lease references have the same size.
	r.cfg.CacheBytes = 0
	for i, lc := range contexts {
		r.cfg.CacheBytes = max(r.cfg.CacheBytes, len(contextID(lc))+len(packages[i])+128)
	}
	for i, lc := range contexts {
		if _, err := r.Recover(t.Context(), lc, cabe.FLPSet{packages[i]}, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := r.Recover(t.Context(), contexts[0], nil, now); err == nil {
		t.Fatal("evicted package recovered")
	}
	if _, err := r.Recover(t.Context(), contexts[1], nil, now); err != nil {
		t.Fatal("new package missing", err)
	}
	disabled := testRuntime(t)
	disabled.cfg.CacheBytes = 0
	disabled.remember("context", packages[0], now)
	if disabled.known("context", now) != nil {
		t.Fatal("disabled cache retained package")
	}
}

func TestRecoveryTriesEveryRetainedKey(t *testing.T) {
	r := testRuntime(t)
	r.cfg.CacheBytes = 0
	var originalKey keystorage.FederationKey
	for k, err := range r.domain.ListFederationKeys(t.Context()) {
		if err != nil {
			t.Fatal(err)
		}
		originalKey = k
	}
	if originalKey == nil {
		t.Fatal("missing initial federation key")
	}
	successor, err := r.domain.RotateFederationKey(t.Context(), originalKey, keystorage.FederationRollover{})
	if err != nil {
		t.Fatal(err)
	}
	attrs, err := attrset.New(map[string]any{"rollover": true})
	if err != nil {
		t.Fatal(err)
	}
	lease := cabe.LKAINonCaptive{RawCOSEKey: key.MustMarshalCBOR(ckapraw.COSEKey{1: 4, 3: 3, -1: make([]byte, 32)})}
	for _, k := range []keystorage.FederationKey{originalKey, successor} {
		lc := cfar.LeaseContext{OriginDomain: testOriginDomain, AttributeSet: attrs, LeaseRef: k.ID()}
		raw, err := cfar.Generate(lc, lease, []key.Key{k.PublicKey()}, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.Recover(t.Context(), lc, cabe.FLPSet{[]byte("irrelevant"), raw}, time.Now())
		if err != nil || !bytes.Equal(got.RawCOSEKey, lease.RawCOSEKey) {
			t.Fatalf("recover retained key %x: %v", k.ID(), err)
		}
	}
}
