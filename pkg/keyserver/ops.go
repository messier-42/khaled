package keyserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/khaled/pkg/keywrap"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// currentPolicy resolves the policy engine from the configured
// source.
func (s *Server) currentPolicy() (policyengine.Engine, error) {
	eng := s.policy.Engine()
	if eng == nil {
		return nil, errors.New("policy engine unavailable")
	}
	return eng, nil
}

// Prograde implements CKAP Prograde Key Resolution.
func (s *Server) Prograde(ctx context.Context, req ProgradeRequest) (ProgradeResponse, error) {
	now := s.now().UTC()
	pol, err := s.currentPolicy()
	if err != nil {
		return ProgradeResponse{}, fmt.Errorf("keyserver: Prograde: %w", err)
	}

	decision, err := pol.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal:    req.Principal,
		AttributeSet: req.AttributeSet,
		Now:          now,
	})
	if err != nil {
		return ProgradeResponse{}, fmt.Errorf("keyserver: Prograde: policy: %w", err)
	}
	if !decision.Allow {
		return ProgradeResponse{}, deniedErr(ctx, "Prograde", req.Principal.URI, decision)
	}

	lki, err := s.schedule.NewLease(ctx, req.AttributeSet)
	if err != nil {
		return ProgradeResponse{}, fmt.Errorf("keyserver: Prograde: mint lease: %w", err)
	}
	repr := req.AttributeSet.Repr()

	leaseRef, err := s.refs.WrapLeaseRef(ctx, lki.RefInfo, repr, decision.RequireCaptive)
	if err != nil {
		return ProgradeResponse{}, fmt.Errorf("keyserver: Prograde: wrap lease ref: %w", err)
	}

	lease := Lease{
		LeaseRef:     leaseRef,
		Expiry:       now.Add(s.leaseDuration),
		AttributeSet: req.AttributeSet,
	}
	if decision.RequireCaptive {
		lkat, err := s.refs.WrapLKAT(ctx, lki.RefInfo, repr)
		if err != nil {
			return ProgradeResponse{}, fmt.Errorf("keyserver: Prograde: wrap LKAT: %w", err)
		}
		lease.LKAI = LKAI{Captive: &LKAICaptive{LKAT: lkat}}
	} else {
		coseKey, err := newCOSESymmetricKey(lki.Key)
		if err != nil {
			clear(lki.Key)
			return ProgradeResponse{}, err
		}
		lease.LKAI = LKAI{NonCaptive: &LKAINonCaptive{LeaseKey: coseKey}}
	}

	if len(req.ARINToken) > 0 {
		lease.LeaseID = newLeaseID()
	}

	if err := s.federate(ctx, pol, req, &lease); err != nil {
		clear(lki.Key)
		return ProgradeResponse{}, err
	}

	return ProgradeResponse{Lease: lease}, nil
}

// Retrograde implements CKAP Retrograde Key Resolution.
func (s *Server) Retrograde(ctx context.Context, req RetrogradeRequest) (RetrogradeResponse, error) {
	now := s.now().UTC()
	pol, err := s.currentPolicy()
	if err != nil {
		return RetrogradeResponse{}, fmt.Errorf("keyserver: Retrograde: %w", err)
	}

	if req.Federation != nil {
		if err := (cabe.LeaseFederation{OriginDomain: req.Federation.OriginDomain, FLPs: req.Federation.FLPs}).Validate(); err != nil {
			return RetrogradeResponse{}, err
		}
		localID := s.federationDomainID.Load()
		if localID == nil || req.Federation.OriginDomain != *localID {
			fed := s.federation.Load()
			if fed == nil {
				return RetrogradeResponse{}, ErrInvalidRef
			}
			return s.foreignRetrograde(ctx, pol, fed, req, now)
		}
	}

	repr := req.AttributeSet.Repr()
	info, refWasCaptive, err := s.refs.UnwrapLeaseRef(ctx, req.LeaseRef, repr)
	if err != nil {
		return RetrogradeResponse{}, err
	}

	decision, err := pol.DecideDecapsulate(ctx, policyengine.DecapsulateRequest{
		Principal:    req.Principal,
		AttributeSet: req.AttributeSet,
		Now:          now,
		LeaseTime:    &info.Time,
	})
	if err != nil {
		return RetrogradeResponse{}, fmt.Errorf("keyserver: Retrograde: policy: %w", err)
	}
	if !decision.Allow {
		return RetrogradeResponse{}, deniedErr(ctx, "Retrograde", req.Principal.URI, decision)
	}

	lki, err := s.schedule.ResolveLease(ctx, info, req.AttributeSet)
	if err != nil {
		return RetrogradeResponse{}, fmt.Errorf("keyserver: Retrograde: resolve lease: %w", err)
	}

	lease := Lease{
		LeaseRef:     req.LeaseRef,
		Expiry:       now.Add(s.leaseDuration),
		AttributeSet: req.AttributeSet,
	}

	captive := refWasCaptive || decision.RequireCaptive
	if captive {
		lkat, err := s.refs.WrapLKAT(ctx, lki.RefInfo, repr)
		if err != nil {
			return RetrogradeResponse{}, fmt.Errorf("keyserver: Retrograde: wrap LKAT: %w", err)
		}
		lease.LKAI = LKAI{Captive: &LKAICaptive{LKAT: lkat}}
	} else {
		coseKey, err := newCOSESymmetricKey(lki.Key)
		if err != nil {
			clear(lki.Key)
			return RetrogradeResponse{}, err
		}
		lease.LKAI = LKAI{NonCaptive: &LKAINonCaptive{LeaseKey: coseKey}}
	}

	return RetrogradeResponse{Lease: lease}, nil
}

// AssistedEncapsulate implements CKAP Assisted Encapsulation: the
// Key Server wraps the client's CEK under the Lease Key identified
// by the quoted LKAT.
func (s *Server) AssistedEncapsulate(ctx context.Context, req AssistedEncapsulateRequest) (AssistedEncapsulateResponse, error) {
	pol, err := s.currentPolicy()
	if err != nil {
		return AssistedEncapsulateResponse{}, fmt.Errorf("keyserver: AssistedEncapsulate: %w", err)
	}
	info, repr, err := s.refs.UnwrapLKAT(ctx, req.LKAT)
	if err != nil {
		return AssistedEncapsulateResponse{}, err
	}
	attrSet, err := repr.Decode()
	if err != nil {
		return AssistedEncapsulateResponse{}, err
	}

	decision, err := pol.DecideEncapsulate(ctx, policyengine.EncapsulateRequest{
		Principal:    req.Principal,
		AttributeSet: attrSet,
		Now:          s.now().UTC(),
	})
	if err != nil {
		return AssistedEncapsulateResponse{}, fmt.Errorf("keyserver: AssistedEncapsulate: policy: %w", err)
	}
	if !decision.Allow {
		return AssistedEncapsulateResponse{}, deniedErr(ctx, "AssistedEncapsulate", req.Principal.URI, decision)
	}

	lki, err := s.schedule.ResolveLease(ctx, info, attrSet)
	if err != nil {
		return AssistedEncapsulateResponse{}, fmt.Errorf("keyserver: AssistedEncapsulate: resolve lease: %w", err)
	}
	// The Lease Key never leaves the server on this path, so zero
	// it as soon as the AES-KW wrap is done.
	defer clear(lki.Key)
	kw, err := keywrap.New(lki.Key)
	if err != nil {
		return AssistedEncapsulateResponse{}, fmt.Errorf("keyserver: AssistedEncapsulate: %w", err)
	}
	wrapped, err := kw.Wrap(req.CEK)
	if err != nil {
		return AssistedEncapsulateResponse{}, fmt.Errorf("keyserver: AssistedEncapsulate: %w", err)
	}
	return AssistedEncapsulateResponse{WrappedCEK: wrapped}, nil
}

// AssistedDecapsulate implements CKAP Assisted Decapsulation: the
// Key Server unwraps the client's wrapped CEK under the Lease Key
// identified by the quoted LKAT.
func (s *Server) AssistedDecapsulate(ctx context.Context, req AssistedDecapsulateRequest) (AssistedDecapsulateResponse, error) {
	pol, err := s.currentPolicy()
	if err != nil {
		return AssistedDecapsulateResponse{}, fmt.Errorf("keyserver: AssistedDecapsulate: %w", err)
	}
	info, repr, err := s.refs.UnwrapLKAT(ctx, req.LKAT)
	if err != nil {
		return AssistedDecapsulateResponse{}, err
	}
	attrSet, err := repr.Decode()
	if err != nil {
		return AssistedDecapsulateResponse{}, err
	}

	decision, err := pol.DecideDecapsulate(ctx, policyengine.DecapsulateRequest{
		Principal:    req.Principal,
		AttributeSet: attrSet,
		Now:          s.now().UTC(),
		LeaseTime:    &info.Time,
	})
	if err != nil {
		return AssistedDecapsulateResponse{}, fmt.Errorf("keyserver: AssistedDecapsulate: policy: %w", err)
	}
	if !decision.Allow {
		return AssistedDecapsulateResponse{}, deniedErr(ctx, "AssistedDecapsulate", req.Principal.URI, decision)
	}

	lki, err := s.schedule.ResolveLease(ctx, info, attrSet)
	if err != nil {
		return AssistedDecapsulateResponse{}, fmt.Errorf("keyserver: AssistedDecapsulate: resolve lease: %w", err)
	}
	// Assisted Decapsulate never discloses the Lease Key to the
	// client, so zero it as soon as the AES-KW unwrap is done. See
	// note on AssistedEncapsulate.
	defer clear(lki.Key)
	kw, err := keywrap.New(lki.Key)
	if err != nil {
		return AssistedDecapsulateResponse{}, fmt.Errorf("keyserver: AssistedDecapsulate: %w", err)
	}
	cek, err := kw.Unwrap(req.WrappedCEK)
	if err != nil {
		return AssistedDecapsulateResponse{}, fmt.Errorf("keyserver: AssistedDecapsulate: %w", err)
	}
	return AssistedDecapsulateResponse{CEK: cek}, nil
}

// GetSelf returns the Principal as seen by the server plus the
// configured ServerInfo. A non-empty Principal URI is required per
// CKAP; GetSelf rejects empty URIs rather than silently echoing.
func (s *Server) GetSelf(ctx context.Context, req GetSelfRequest) (GetSelfResponse, error) {
	if req.Principal.URI == "" {
		return GetSelfResponse{}, errors.New("keyserver: GetSelf: Principal.URI is required")
	}
	return GetSelfResponse{
		Principal: req.Principal,
		ServerInfo: map[string]any{
			"domainName": s.domainName,
			"version":    s.version,
		},
	}, nil
}

// AdvanceSubEpoch is an admin entry point. Delegates directly to the
// schedule; no policy gate.
func (s *Server) AdvanceSubEpoch(ctx context.Context, attrSet attrset.Set) error {
	return s.schedule.AdvanceSubEpoch(ctx, attrSet)
}

// RotateRootKey is an admin entry point. Delegates directly to the
// schedule; no policy gate.
func (s *Server) RotateRootKey(ctx context.Context) error {
	return s.schedule.RotateRootKey(ctx)
}

// newLeaseID returns an 8-byte random hex string for ARIN
// correlation. Uniqueness within a process is sufficient; CKAP only
// requires uniqueness within the scope of an ARIN stream.
func newLeaseID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
