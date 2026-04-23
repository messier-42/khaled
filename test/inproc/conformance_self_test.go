//go:build integration

// Package inproc holds in-process integration tests that drive a real
// khaled instance via the cabe-go ckapclient. Tests live behind the
// "integration" build tag so the default `go test ./...` does not pay
// their startup cost.
package inproc

import (
	"context"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/ckap"

	"github.com/messier-42/khaled/test/ktutil"
)

// TestGetSelf_HappyPath_MTLS asserts the harness's default mTLS path
// round-trips: the SAN URI baked into the per-test client leaf must
// arrive back as PrincipalInfo.URI, and the static claims mapper's
// "mtls-client" role must come through unchanged.
func TestGetSelf_HappyPath_MTLS(t *testing.T) {
	t.Parallel()

	const principal = "spiffe://khaledtest.local/getself-mtls"
	srv := khaledtest.Start(t, khaledtest.WithPrincipal(principal))
	client := srv.Client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetSelf(ctx, ckap.GetSelfRequest{})
	if err != nil {
		t.Fatalf("GetSelf: %s", describeError(err))
	}
	if resp == nil {
		t.Fatal("GetSelf returned nil response with no error")
	}
	if got, want := resp.PrincipalInfo.URI, principal; got != want {
		t.Errorf("PrincipalInfo.URI = %q, want %q", got, want)
	}
	if role, ok := resp.PrincipalInfo.Claims["role"]; !ok {
		t.Errorf("PrincipalInfo.Claims missing 'role' key: %v", resp.PrincipalInfo.Claims)
	} else if role != "mtls-client" {
		t.Errorf("PrincipalInfo.Claims[role] = %v, want \"mtls-client\"", role)
	}
}

// TestGetSelf_HappyPath_Anonymous asserts the WithAnonymousAuth
// opt-in path still works: anonymous's DefaultURI comes back, and
// the mapper's "anonymous" role is attached.
func TestGetSelf_HappyPath_Anonymous(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t, khaledtest.WithAnonymousAuth())
	client := srv.Client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetSelf(ctx, ckap.GetSelfRequest{})
	if err != nil {
		t.Fatalf("GetSelf: %s", describeError(err))
	}
	if got, want := resp.PrincipalInfo.URI, srv.PrincipalURI(); got != want {
		t.Errorf("PrincipalInfo.URI = %q, want %q", got, want)
	}
	if role, ok := resp.PrincipalInfo.Claims["role"]; !ok {
		t.Errorf("PrincipalInfo.Claims missing 'role' key: %v", resp.PrincipalInfo.Claims)
	} else if role != "anonymous" {
		t.Errorf("PrincipalInfo.Claims[role] = %v, want \"anonymous\"", role)
	}
}
