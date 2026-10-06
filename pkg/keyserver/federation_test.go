package keyserver_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/khaled/pkg/federation"
	"github.com/messier-42/khaled/pkg/keyserver"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

const (
	testTargetDomain = "target"
	testOriginDomain = "origin"
	testLocalDomain  = "local"
)

func TestForeignResolutionPolicyAndContext(t *testing.T) {
	origin, target := newFixture(t), newFixture(t)
	tr, e := federation.New(t.Context(), target.domain.(keystorage.FederationDomain), federation.Config{DomainID: testTargetDomain, CacheBytes: 4096, CacheTTL: time.Minute})
	if e != nil {
		t.Fatal(e)
	}
	if err := target.srv.SetFederation(tr); err != nil {
		t.Fatal(err)
	}
	id, _, e := tr.Identity(t.Context(), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	or, e := federation.New(t.Context(), origin.domain.(keystorage.FederationDomain), federation.Config{DomainID: testOriginDomain, Peers: []federation.Peer{{DomainID: testTargetDomain, Identity: &id}}})
	if e != nil {
		t.Fatal(e)
	}
	if err := origin.srv.SetFederation(or); err != nil {
		t.Fatal(err)
	}
	// Release is denied by default even when local encapsulation is allowed.
	attrs := mustSet(t, map[string]any{"a": "b"})
	pro, e := origin.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: origin.principal, AttributeSet: attrs})
	if e != nil {
		t.Fatal(e)
	}
	if pro.Lease.Federation == nil || len(pro.Lease.Federation.FLPs) != 0 {
		t.Fatal("engine without release permission exported")
	}
	origin.engine.federate = func(req policyengine.FederateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: req.TargetDomain == testTargetDomain}, nil
	}
	pro, e = origin.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: origin.principal, AttributeSet: attrs})
	if e != nil {
		t.Fatal(e)
	}
	if len(pro.Lease.Federation.FLPs) != 1 {
		t.Fatal("authorized release missing")
	}
	req := keyserver.RetrogradeRequest{Principal: target.principal, AttributeSet: attrs, LeaseRef: pro.Lease.LeaseRef, Federation: &ckap.RetrogradeFederation{OriginDomain: testOriginDomain, FLPs: append(cabe.FLPSet{[]byte("irrelevant")}, pro.Lease.Federation.FLPs...)}}
	target.engine.decap = func(p policyengine.DecapsulateRequest) (policyengine.Decision, error) {
		if p.LeaseTime != nil || !p.Federated || p.OriginDomain != testOriginDomain {
			t.Error("incorrect foreign policy context")
		}
		return policyengine.Decision{Allow: true}, nil
	}
	got, e := target.srv.Retrograde(t.Context(), req)
	if e != nil {
		t.Fatal(e)
	}
	a, e := key.MarshalCBOR(pro.Lease.LKAI.NonCaptive.LeaseKey)
	if e != nil {
		t.Fatal(e)
	}
	b, e := key.MarshalCBOR(got.Lease.LKAI.NonCaptive.LeaseKey)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("foreign LKAI changed")
	}
	req.Federation.FLPs = nil
	if _, e = target.srv.Retrograde(t.Context(), req); e != nil {
		t.Fatal("empty known-package request", e)
	}
	for _, d := range []policyengine.Decision{{Allow: false}, {Allow: true, RequireCaptive: true}} {
		target.engine.decap = func(policyengine.DecapsulateRequest) (policyengine.Decision, error) { return d, nil }
		if _, e = target.srv.Retrograde(t.Context(), req); !errors.Is(e, keyserver.ErrDenied) {
			t.Fatalf("policy bypass: %v", e)
		}
	}
	target.engine.decap = nil
	req.Federation.FLPs = pro.Lease.Federation.FLPs
	for _, field := range []string{"reference", "attributes", testOriginDomain} {
		t.Run(field, func(t *testing.T) {
			mismatched := req
			metadata := *req.Federation
			mismatched.Federation = &metadata
			switch field {
			case "reference":
				mismatched.LeaseRef = []byte("different")
			case "attributes":
				mismatched.AttributeSet = mustSet(t, map[string]any{"a": "different"})
			case testOriginDomain:
				mismatched.Federation.OriginDomain = "different"
			}
			if _, err := target.srv.Retrograde(t.Context(), mismatched); !errors.Is(err, keyserver.ErrInvalidRef) {
				t.Fatalf("context mismatch: %v", err)
			}
		})
	}
}

func TestDisableFederationKeepsLocalLeaseResolution(t *testing.T) {
	f := newFixture(t)
	r, e := federation.New(t.Context(), f.domain.(keystorage.FederationDomain), federation.Config{DomainID: testLocalDomain})
	if e != nil {
		t.Fatal(e)
	}
	if err := f.srv.SetFederation(r); err != nil {
		t.Fatal(err)
	}
	as := mustSet(t, map[string]any{testLocalDomain: true})
	pro, e := f.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: f.principal, AttributeSet: as})
	if e != nil {
		t.Fatal(e)
	}
	if err := f.srv.SetFederation(nil); err != nil {
		t.Fatal(err)
	}
	req := keyserver.RetrogradeRequest{Principal: f.principal, AttributeSet: as, LeaseRef: pro.Lease.LeaseRef, Federation: &ckap.RetrogradeFederation{OriginDomain: testLocalDomain}}
	if _, e = f.srv.Retrograde(t.Context(), req); e != nil {
		t.Fatal("local lease lost after disabling federation", e)
	}
	req.Federation.OriginDomain = "foreign"
	if _, e = f.srv.Retrograde(t.Context(), req); !errors.Is(e, keyserver.ErrInvalidRef) {
		t.Fatalf("foreign request accepted: %v", e)
	}
}

func TestMultipleTargetsAndReleaseDiagnosticFailure(t *testing.T) {
	origin, a, b := newFixture(t), newFixture(t), newFixture(t)
	peers := make([]federation.Peer, 0, 2)
	for name, f := range map[string]*fixture{"a": a, "b": b} {
		r, err := federation.New(t.Context(), f.domain.(keystorage.FederationDomain), federation.Config{DomainID: name})
		if err != nil {
			t.Fatal(err)
		}
		if err = f.srv.SetFederation(r); err != nil {
			t.Fatal(err)
		}
		id, _, err := r.Identity(t.Context(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		peers = append(peers, federation.Peer{DomainID: name, Identity: &id})
	}
	r, err := federation.New(t.Context(), origin.domain.(keystorage.FederationDomain), federation.Config{DomainID: testOriginDomain, Peers: peers})
	if err != nil {
		t.Fatal(err)
	}
	if err = origin.srv.SetFederation(r); err != nil {
		t.Fatal(err)
	}
	attrs := mustSet(t, map[string]any{"a": "b"})
	origin.engine.federate = func(policyengine.FederateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, Diagnostics: []string{"forbid evaluation failed"}}, nil
	}
	if _, err = origin.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: origin.principal, AttributeSet: attrs}); err == nil {
		t.Fatal("release diagnostic bypass")
	}
	origin.engine.federate = func(policyengine.FederateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true}, nil
	}
	pro, err := origin.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: origin.principal, AttributeSet: attrs})
	if err != nil {
		t.Fatal(err)
	}
	if len(pro.Lease.Federation.FLPs) != 1 {
		t.Fatal("expected single multiple-recipient package")
	}
	for _, target := range []*fixture{a, b} {
		_, err = target.srv.Retrograde(t.Context(), keyserver.RetrogradeRequest{Principal: target.principal, AttributeSet: attrs, LeaseRef: pro.Lease.LeaseRef, Federation: &ckap.RetrogradeFederation{OriginDomain: testOriginDomain, FLPs: pro.Lease.Federation.FLPs}})
		if err != nil {
			t.Fatal("recipient cannot recover", err)
		}
	}
	origin.engine.encap = func(policyengine.EncapsulateRequest) (policyengine.Decision, error) {
		return policyengine.Decision{Allow: true, RequireCaptive: true}, nil
	}
	captive, err := origin.srv.Prograde(t.Context(), keyserver.ProgradeRequest{Principal: origin.principal, AttributeSet: attrs})
	if err != nil {
		t.Fatal(err)
	}
	if len(captive.Lease.Federation.FLPs) != 0 || captive.Lease.LKAI.NonCaptive != nil {
		t.Fatal("Captive lease exported")
	}
}
