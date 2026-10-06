package keyserver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cfar"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/federation"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// SetFederation atomically replaces runtime policy/caches while retaining the
// existing unified key store. In-flight operations keep their captured runtime.
func (s *Server) SetFederation(f *federation.Runtime) error {
	if f != nil {
		if err := s.BindFederationDomainID(f.DomainID()); err != nil {
			return err
		}
	}
	s.federation.Store(f)
	return nil
}

// BindFederationDomainID restores the durable identity even when federation is
// disabled. It permits local resolution of previously issued federated leases;
// an identity cannot be replaced within the lifetime of a Server.
func (s *Server) BindFederationDomainID(id string) error {
	if id == "" {
		return nil
	}
	if old := s.federationDomainID.Load(); old != nil {
		if *old != id {
			return errors.New("keyserver: federation identity changed")
		}
		return nil
	}
	if s.federationDomainID.CompareAndSwap(nil, &id) {
		return nil
	}
	return s.BindFederationDomainID(id)
}

// FederationIdentity returns public keys and their response freshness deadline.
// A disabled federation configuration returns nil without an error.
func (s *Server) FederationIdentity(ctx context.Context) (*ckapraw.FederationIdentity, time.Time, error) {
	f := s.federation.Load()
	if f == nil {
		return nil, time.Time{}, nil
	}
	id, until, err := f.Identity(ctx, s.now().UTC())
	return &id, until, err
}
func (s *Server) federate(ctx context.Context, pol policyengine.Engine, req ProgradeRequest, lease *Lease) error {
	f := s.federation.Load()
	if f == nil {
		return nil
	}
	lease.Federation = &cabe.LeaseFederation{OriginDomain: f.DomainID()}
	if lease.LKAI.NonCaptive == nil {
		return nil
	}
	release, ok := pol.(policyengine.FederationEngine)
	if !ok {
		return nil
	}
	var targets []string
	now := s.now().UTC()
	for _, target := range f.Targets() {
		d, err := release.DecideFederate(ctx, policyengine.FederateRequest{Principal: req.Principal, AttributeSet: req.AttributeSet, Now: now, TargetDomain: target})
		if err != nil {
			return fmt.Errorf("keyserver: federation release: %w", err)
		}
		if len(d.Diagnostics) > 0 {
			return errors.New("keyserver: federation policy evaluation failed")
		}
		if d.Allow && !d.RequireCaptive {
			targets = append(targets, target)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	recipients, err := f.Recipients(ctx, targets, now)
	if err != nil {
		return err
	}
	raw, err := key.MarshalCBOR(lease.LKAI.NonCaptive.LeaseKey)
	if err != nil {
		return err
	}
	defer clear(raw)
	pkg, err := cfar.Generate(cfar.LeaseContext{OriginDomain: f.DomainID(), AttributeSet: req.AttributeSet, LeaseRef: lease.LeaseRef}, cabe.LKAINonCaptive{RawCOSEKey: raw}, recipients, nil)
	if err != nil {
		return err
	}
	lease.Federation.FLPs = cabe.FLPSet{pkg}
	return nil
}
func (s *Server) foreignRetrograde(ctx context.Context, pol policyengine.Engine, f *federation.Runtime, req RetrogradeRequest, now time.Time) (RetrogradeResponse, error) {
	d, err := pol.DecideDecapsulate(ctx, policyengine.DecapsulateRequest{Principal: req.Principal, AttributeSet: req.AttributeSet, Now: now, Federated: true, OriginDomain: req.Federation.OriginDomain})
	if err != nil {
		return RetrogradeResponse{}, fmt.Errorf("keyserver: foreign policy: %w", err)
	}
	if !d.Allow || d.RequireCaptive || len(d.Diagnostics) > 0 {
		return RetrogradeResponse{}, deniedErr(ctx, "Retrograde", req.Principal.URI, d)
	}
	got, err := f.Recover(ctx, cfar.LeaseContext{OriginDomain: req.Federation.OriginDomain, AttributeSet: req.AttributeSet, LeaseRef: req.LeaseRef}, req.Federation.FLPs, now)
	if errors.Is(err, cfar.ErrNoUsablePackage) {
		return RetrogradeResponse{}, ErrInvalidRef
	}
	if err != nil {
		return RetrogradeResponse{}, err
	}
	defer clear(got.RawCOSEKey)
	var k ckapraw.COSEKey
	if err = key.UnmarshalCBOR(got.RawCOSEKey, &k); err != nil {
		return RetrogradeResponse{}, err
	}
	return RetrogradeResponse{Lease: Lease{LeaseRef: req.LeaseRef, AttributeSet: req.AttributeSet, Expiry: now.Add(s.leaseDuration), LKAI: LKAI{NonCaptive: &LKAINonCaptive{LeaseKey: k}}}}, nil
}
