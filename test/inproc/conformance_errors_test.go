//go:build integration

package inproc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/cabe-go/ckapraw"

	"github.com/messier-42/khaled/test/ktutil"
)

// denyAllPolicy is a Cedar policy that contains a single forbid
// statement that takes precedence over any permit. Combined with
// Cedar's deny-by-default semantics this guarantees every access
// decision returns Decision.Allow=false. Used by the policy-denied
// integration tests below; inlined here so the test file is
// self-contained.
const denyAllPolicy = "forbid(principal, action, resource);\n"

// permitEncapOnlyPolicy permits Encapsulate (so Prograde succeeds for
// any principal and any attribute set) and, by virtue of Cedar's
// deny-by-default semantics, denies Decapsulate (so Retrograde is
// rejected). Used to exercise the Retrograde policy gate in isolation
// from the Prograde gate that denyAllPolicy already covers.
const permitEncapOnlyPolicy = `permit(
  principal,
  action == Action::"Encapsulate",
  resource
);
`

// TestPrograde_PolicyDenied pins the wire-protocol surface of a
// keyserver.ErrDenied: when policy refuses the access, the response
// is a CKAP Error with CodePolicyDenied. Without this test, a
// regression that mapped ErrDenied to CodeInternal (or, conversely,
// silently let a denied request through) would only surface in
// production.
func TestPrograde_PolicyDenied(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t, khaledtest.WithPolicy(denyAllPolicy))
	client := srv.Client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	as, err := attrset.New(map[string]any{"env": "test"})
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}

	resp, err := client.Prograde(ctx, ckap.ProgradeRequest{AttributeSet: as})
	if err == nil {
		t.Fatalf("Prograde: want error, got resp=%+v", resp)
	}
	var cerr *ckap.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("Prograde: want *ckap.Error, got %T: %v", err, err)
	}
	if cerr.Code != cabe.CodePolicyDenied {
		t.Errorf("Prograde: code = %d, want CodePolicyDenied (%d) — %s",
			cerr.Code, cabe.CodePolicyDenied, describeError(err))
	}
}

// TestRetrograde_PolicyDenied pins the Retrograde policy gate as a
// path distinct from the Prograde gate exercised above. Under a Cedar
// policy that permits Encapsulate but denies Decapsulate, Prograde
// succeeds (so the test gets a real LeaseRef minted by the same
// server), but the subsequent Retrograde for that ref is rejected
// with CodePolicyDenied.
//
// A regression that bypassed DecideDecapsulate (or that mapped its
// deny outcome to a different code) would not be caught by the
// Prograde-denied test alone, since that one short-circuits before
// the Decapsulate path is ever consulted. Without this pairing, the
// suite cannot tell the two gates apart.
func TestRetrograde_PolicyDenied(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t, khaledtest.WithPolicy(permitEncapOnlyPolicy))
	client := srv.Client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	as, err := attrset.New(map[string]any{"env": "test"})
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}

	pro, err := client.Prograde(ctx, ckap.ProgradeRequest{AttributeSet: as})
	if err != nil {
		t.Fatalf("Prograde (expected to succeed under permit-encap-only): %s", describeError(err))
	}

	resp, err := client.Retrograde(ctx, ckap.RetrogradeRequest{
		AttributeSet: as,
		LeaseRef:     pro.Lease.LeaseRef,
	})
	if err == nil {
		t.Fatalf("Retrograde: want error, got resp=%+v", resp)
	}
	var cerr *ckap.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("Retrograde: want *ckap.Error, got %T: %v", err, err)
	}
	if cerr.Code != cabe.CodePolicyDenied {
		t.Errorf("Retrograde: code = %d, want CodePolicyDenied (%d) — %s",
			cerr.Code, cabe.CodePolicyDenied, describeError(err))
	}
}

// TestGetSelf_WrongContentTypeRejected pins the malformed-request
// path that cabe-go's client cannot itself produce: a POST to a
// CKAP endpoint with a Content-Type other than application/ckap+cbor.
// The server must respond with a CBOR-encoded CKAP Error carrying
// CodeMalformedRequest, not a plain-text 415 or an opaque body.
//
// Uses the harness's raw HTTPClient (not the cabe-go ckapclient)
// because the client always sets the correct Content-Type — the only
// way to exercise this path end-to-end is with a hand-rolled request.
func TestGetSelf_WrongContentTypeRejected(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	httpc := srv.HTTPClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		srv.BaseURL()+"GetSelf", bytes.NewReader([]byte("not cbor")))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Accept", ckap.MediaType)

	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("httpc.Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != ckap.MediaType {
		t.Errorf("Content-Type = %q, want %q (error responses must be CBOR-framed)", got, ckap.MediaType)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var ckapErr ckapraw.Error
	if err := cbor.Unmarshal(body, &ckapErr); err != nil {
		t.Fatalf("decode error body as CBOR: %v (raw=%x)", err, body)
	}
	if ckapErr.Kind != ckapraw.KindError {
		t.Errorf("Kind = %q, want %q", ckapErr.Kind, ckapraw.KindError)
	}
	if cabe.Code(ckapErr.ErrorCode) != cabe.CodeMalformedRequest {
		t.Errorf("ErrorCode = %d, want CodeMalformedRequest (%d)",
			ckapErr.ErrorCode, cabe.CodeMalformedRequest)
	}
}

// TestRetrograde_InvalidRefRejected pins that a Retrograde request
// quoting a LeaseRef the keyserver cannot authenticate (random bytes
// here) is rejected with CodeInvalidRef. This is the wire-protocol
// surface of the keyserver's macwrapper Unwrap failing — without
// this test, a regression that turned the Unwrap error into a 500
// (CodeInternal) would slip past the suite even though it would
// confuse every real client.
func TestRetrograde_InvalidRefRejected(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	client := srv.Client(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	as, err := attrset.New(map[string]any{"env": "test"})
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}

	// 32 deterministic bytes that cannot possibly authenticate against
	// the freshly-minted root key. The exact byte pattern is irrelevant
	// — any sequence that fails the macwrapper Unwrap check produces
	// the same outcome.
	bogusRef := make([]byte, 32)
	for i := range bogusRef {
		bogusRef[i] = byte(i)
	}

	resp, err := client.Retrograde(ctx, ckap.RetrogradeRequest{
		AttributeSet: as,
		LeaseRef:     bogusRef,
	})
	if err == nil {
		t.Fatalf("Retrograde: want error, got resp=%+v", resp)
	}
	var cerr *ckap.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("Retrograde: want *ckap.Error, got %T: %v", err, err)
	}
	if cerr.Code != cabe.CodeInvalidRef {
		t.Errorf("Retrograde: code = %d, want CodeInvalidRef (%d) — %s",
			cerr.Code, cabe.CodeInvalidRef, describeError(err))
	}
}

// TestPrograde_MalformedAttributeSetRejected pins the transport-layer
// rejection of a structurally-invalid AttributeSet. The cabe-go
// client validates attribute names locally and never lets one onto
// the wire, so this case is only reachable with a hand-rolled CBOR
// body. The transport's call to attrset.New surfaces the error as
// CodeMalformedRequest.
//
// Without this test, a regression that accepted invalid attribute
// names at the transport boundary would let malformed input flow
// into the keyserver, where downstream behaviour is undefined.
func TestPrograde_MalformedAttributeSetRejected(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	httpc := srv.HTTPClient(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// "1bad" violates the attribute-set name grammar (names must
	// begin with an ALPHA). cabe-go's attrset.New rejects this
	// locally; bypassing the client is the only way to exercise
	// the server-side rejection path.
	body, err := cbor.Marshal(map[string]any{
		"kind":         ckapraw.KindProgradeRequest,
		"attributeSet": map[string]any{"1bad": "x"},
	})
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		srv.BaseURL()+"Prograde", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequestWithContext: %v", err)
	}
	req.Header.Set("Content-Type", ckap.MediaType)
	req.Header.Set("Accept", ckap.MediaType)

	resp, err := httpc.Do(req)
	if err != nil {
		t.Fatalf("httpc.Do: %v", err)
	}
	defer resp.Body.Close()
	assertCKAPErrorResponse(t, resp, http.StatusBadRequest, cabe.CodeMalformedRequest)
}

// TestGetSelf_NoClientCertRejected_CABEGoClient pins that the
// cabe-go ckapclient's decodeServerError path correctly produces a
// typed *ckap.Error{Code: CodeUnauthorized} when khaled rejects an
// unauthenticated request. This is the wire-to-typed-error contract
// the ckaphttp-framed middleware response makes possible: a
// plain-text 401 (the prior behaviour) would decode to CodeReserved
// and the actual code would be lost to every real client.
func TestGetSelf_NoClientCertRejected_CABEGoClient(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	httpc := srv.HTTPClientNoClientCert(t)
	client, err := ckapclient.NewClient(ckapclient.Config{
		BaseURL:    srv.BaseURL(),
		HTTPClient: httpc,
	})
	if err != nil {
		t.Fatalf("ckapclient.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetSelf(ctx, ckap.GetSelfRequest{})
	if err == nil {
		t.Fatalf("GetSelf: want error, got resp=%+v", resp)
	}
	var cerr *ckap.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("GetSelf: want *ckap.Error, got %T: %v", err, err)
	}
	if cerr.Code != cabe.CodeUnauthorized {
		t.Errorf("GetSelf: code = %d, want CodeUnauthorized (%d) — %s",
			cerr.Code, cabe.CodeUnauthorized, describeError(err))
	}
}

// TestGetSelf_NoClientCertRejected pins the unauthenticated path
// under mTLS: a request that completes the TLS handshake without
// presenting a peer certificate is rejected by the tls-ca plugin
// with clientauthn.ErrNoClientCertificate, surfaced on the wire as
// CodeUnauthorized. Without the ckaphttp-framed middleware
// response (introduced alongside this test), the plain-text 401
// would decode to CodeReserved client-side and the actual code
// would be lost.
func TestGetSelf_NoClientCertRejected(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	httpc := srv.HTTPClientNoClientCert(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := getSelfRaw(ctx, httpc, srv.BaseURL())
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	defer resp.Body.Close()
	assertCKAPErrorResponse(t, resp, http.StatusUnauthorized, cabe.CodeUnauthorized)
}

// TestGetSelf_UntrustedCAClientCertRejected pins the same path for
// a peer cert presented by a chain whose root is *not* in khaled's
// configured tls-ca bundle. The TLS handshake succeeds (khaled uses
// RequestClientCert, not RequireAndVerify); validation happens in
// the authn layer and produces CodeUnauthorized.
func TestGetSelf_UntrustedCAClientCertRejected(t *testing.T) {
	t.Parallel()

	srv := khaledtest.Start(t)
	leaf := srv.IssueClientLeafFromForeignCA(t, "spiffe://untrusted.example/svc/x")
	httpc := srv.HTTPClientWithCert(t, leaf)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := getSelfRaw(ctx, httpc, srv.BaseURL())
	if err != nil {
		t.Fatalf("transport: %v", err)
	}
	defer resp.Body.Close()
	assertCKAPErrorResponse(t, resp, http.StatusUnauthorized, cabe.CodeUnauthorized)
}

// getSelfRaw issues a GetSelf POST using the given http.Client. The
// request body is a minimal valid CKAP GetSelfRequest so the only
// thing the server's authn layer can rule on is the client cert
// (or its absence). Returns the raw *http.Response so the caller
// can assert directly on status, headers, and body — bypassing the
// cabe-go ckapclient on purpose, because that client is the unit
// under test for these CodeUnauthorized cases (its decodeServerError
// is the path that previously fell back to CodeReserved when the
// middleware responded with plain text).
func getSelfRaw(ctx context.Context, httpc *http.Client, baseURL string) (*http.Response, error) {
	body, err := cbor.Marshal(ckapraw.GetSelfRequest{Kind: ckapraw.KindGetSelfRequest})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"GetSelf", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ckap.MediaType)
	req.Header.Set("Accept", ckap.MediaType)
	return httpc.Do(req)
}

// assertCKAPErrorResponse verifies that resp is a CBOR-framed CKAP
// Error with the expected HTTP status and ErrorCode. Mirrors
// assertCKAPError in pkg/httpmw/authn_test.go but operates on a
// real *http.Response rather than a httptest.ResponseRecorder.
func assertCKAPErrorResponse(t *testing.T, resp *http.Response, wantStatus int, wantCode cabe.Code) {
	t.Helper()
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d", resp.StatusCode, wantStatus)
	}
	if got := resp.Header.Get("Content-Type"); got != ckap.MediaType {
		t.Errorf("Content-Type = %q, want application/ckap+cbor", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var parsed ckapraw.Error
	if err := cbor.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode body as CBOR: %v (raw=%x)", err, body)
	}
	if parsed.Kind != ckapraw.KindError {
		t.Errorf("Kind = %q, want %q", parsed.Kind, ckapraw.KindError)
	}
	if cabe.Code(parsed.ErrorCode) != wantCode {
		t.Errorf("ErrorCode = %d, want %d", parsed.ErrorCode, wantCode)
	}
}
