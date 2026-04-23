package claimssub

import (
	"context"
	"math"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
)

func TestAsIntBoundsChecked(t *testing.T) {
	cases := []struct {
		name  string
		v     config.Value
		wantN int
		wantO bool
	}{
		{"int64 0", int64(0), 0, true},
		{"int64 small", int64(42), 42, true},
		{"int64 max", int64(math.MaxInt), math.MaxInt, true},
		{"int64 min", int64(math.MinInt), math.MinInt, true},
		{"uint64 small", uint64(42), 42, true},
		{"uint64 maxInt", uint64(math.MaxInt), math.MaxInt, true},
		{"uint64 overflow", uint64(math.MaxInt) + 1, 0, false},
		{"uint64 maxUint64", uint64(math.MaxUint64), 0, false},
		{"string rejected", "42", 0, false},
		{"float rejected", float64(42), 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotN, gotO := asInt(tc.v)
			if gotO != tc.wantO || (tc.wantO && gotN != tc.wantN) {
				t.Fatalf("asInt(%v) = (%d,%v), want (%d,%v)", tc.v, gotN, gotO, tc.wantN, tc.wantO)
			}
		})
	}
}

func TestStartTolerantOfMissingBlock(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{}}
	m, err := New(snap)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop() }()
	if got := m.Current(); got != nil {
		t.Errorf("expected nil mapper with no claimsMapping block")
	}
}

func TestStartStaticBuilds(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"claimsMapping": config.Map{
			"use": "static",
			"static": config.Map{
				"principals": config.Array{
					config.Map{
						"uri":    ".*",
						"claims": config.Map{"k": "v"},
					},
				},
			},
		},
	}}
	m, err := New(snap)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop() }()
	if got := m.Current(); got == nil {
		t.Errorf("expected non-nil mapper")
	}
}

func TestStartStaticRejectsEmptyPrincipals(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"claimsMapping": config.Map{
			"use": "static",
			"static": config.Map{
				"principals": config.Array{},
			},
		},
	}}
	if _, err := New(snap); err == nil {
		t.Fatalf("expected empty principals to fail")
	}
}

func TestManagerReconcileNoOp(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"claimsMapping": config.Map{
			"use": "static",
			"static": config.Map{
				"principals": config.Array{
					config.Map{"uri": ".*", "claims": config.Map{"k": "v"}},
				},
			},
		},
	}}
	m, err := New(snap)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop() }()

	before := m.Current()
	if err := m.Reconcile(context.Background(), snap); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	after := m.Current()
	if before != after {
		t.Errorf("expected no-op reconcile to leave mapper instance alone")
	}
}

func TestManagerReconcileRebuildsOnChange(t *testing.T) {
	oldSnap := config.Snapshot{Root: config.Map{
		"claimsMapping": config.Map{
			"use": "static",
			"static": config.Map{
				"principals": config.Array{
					config.Map{"uri": ".*", "claims": config.Map{"k": "v1"}},
				},
			},
		},
	}}
	m, err := New(oldSnap)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop() }()

	before := m.Current()

	newSnap := config.Snapshot{Root: config.Map{
		"claimsMapping": config.Map{
			"use": "static",
			"static": config.Map{
				"principals": config.Array{
					config.Map{"uri": ".*", "claims": config.Map{"k": "v2"}},
				},
			},
		},
	}}
	if err := m.Reconcile(context.Background(), newSnap); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	after := m.Current()
	if before == after {
		t.Errorf("expected reconcile to rebuild mapper instance")
	}
}

func TestManagerK8sAttestationParsesCache(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"claimsMapping": config.Map{
			"use": "k8s-attestation",
			"k8s-attestation": config.Map{
				"cache": config.Map{
					"ttl":         "1m",
					"negativeTTL": "10s",
					"maxEntries":  int64(100),
				},
			},
		},
	}}
	args, err := argsFromSnapshot(snap)
	if err != nil {
		t.Fatalf("ArgsFromSnapshot: %v", err)
	}
	if args.K8sCache.TTL.String() != "1m0s" {
		t.Errorf("TTL = %v", args.K8sCache.TTL)
	}
	if args.K8sCache.NegativeTTL.String() != "10s" {
		t.Errorf("NegativeTTL = %v", args.K8sCache.NegativeTTL)
	}
	if args.K8sCache.MaxEntries != 100 {
		t.Errorf("MaxEntries = %d", args.K8sCache.MaxEntries)
	}
}
