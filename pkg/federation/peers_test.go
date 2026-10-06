package federation

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/ldclabs/cose/key/ecdh"
	"github.com/messier-42/cabe-go/ckapraw"
)

const (
	testPeerDomain    = "peer"
	testCurrentStatus = "current"
)

func TestPeerStatusAndNISTPolicy(t *testing.T) {
	for _, curve := range []int{iana.EllipticCurveP_256, iana.EllipticCurveP_384, iana.EllipticCurveP_521, iana.EllipticCurveX25519} {
		priv, e := ecdh.GenerateKey(curve)
		if e != nil {
			t.Fatal(e)
		}
		priv[iana.KeyParameterAlg] = iana.AlgorithmECDH_ES_A256KW
		pub, e := ecdh.ToPublicKey(priv)
		if e != nil {
			t.Fatal(e)
		}
		for _, status := range []string{testCurrentStatus, "future", "retired"} {
			p, e := newPeer(Peer{DomainID: testPeerDomain, Identity: &ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: testPeerDomain, Keys: []ckapraw.FederationPublicKey{{PublicKey: pub, Status: status}}}})
			if e != nil {
				t.Fatal(e)
			}
			keys, e := p.recipients(t.Context(), time.Now())
			if curve == iana.EllipticCurveX25519 {
				if e == nil {
					t.Fatal("DJB recipient allowed")
				}
			} else if e != nil || len(keys) != 1 {
				t.Fatalf("curve %d, %s: %v", curve, status, e)
			}
		}
	}
}
func TestDiscoveryFreshness(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for _, v := range []struct {
		control string
		seconds int
	}{{"max-age=60", 60}, {"max-age=60,no-cache", 0}, {"no-cache,max-age=60", 0}, {"no-store", 0}, {"max-age=invalid", 0}, {"", 0}} {
		if got := freshUntil(now, v.control, ""); !got.Equal(now.Add(time.Duration(v.seconds) * time.Second)) {
			t.Fatalf("%s: %v", v.control, got)
		}
	}
}

func TestInvalidFreshnessDoesNotExtendCache(t *testing.T) {
	now := time.Now()
	if got := freshUntil(now, "max-age=0,max-age=31536000", ""); !got.Equal(now) {
		t.Fatal("duplicate freshness cached")
	}
}
func TestPeerRejectsPrivateMaterialAcrossKeyTypes(t *testing.T) {
	for _, k := range []key.Key{{1: 4, 2: []byte("symmetric"), -1: []byte("secret")}, {1: 3, 2: []byte("rsa"), -3: []byte("private")}} {
		id := &ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: "p", Keys: []ckapraw.FederationPublicKey{{PublicKey: k, Status: testCurrentStatus}}}
		if err := validateIdentity("p", id); err == nil {
			t.Fatal("accepted private peer material")
		}
	}
}

func TestHTTPSDiscoveryRefreshAndFailure(t *testing.T) {
	priv, err := ecdh.GenerateKey(iana.EllipticCurveP_256)
	if err != nil {
		t.Fatal(err)
	}
	priv[iana.KeyParameterAlg] = iana.AlgorithmECDH_ES_A256KW
	pub, err := ecdh.ToPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	id := ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: testPeerDomain, Keys: []ckapraw.FederationPublicKey{{PublicKey: pub, Status: "retired"}}}
	var calls atomic.Int64
	var fail atomic.Bool
	now := time.Now().UTC().Truncate(time.Second)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/ckap/FederationIdentity" || r.Header.Get("Accept") != "application/ckap+cbor" {
			t.Error("incorrect discovery request")
		}
		if fail.Load() {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/ckap+cbor")
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Expires", now.Add(time.Second).Format(http.TimeFormat))
		raw, e := key.MarshalCBOR(id)
		if e != nil {
			t.Error(e)
			return
		}
		_, _ = w.Write(raw)
	}))
	defer ts.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := newPeer(Peer{DomainID: testPeerDomain, URL: ts.URL + "/ckap", CAFile: ca})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.recipients(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if _, err = p.recipients(t.Context(), now); err != nil || calls.Load() != 1 {
		t.Fatalf("fresh identity not reused: %v", err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err = p.recipients(canceled, now); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cached lookup: got %v, want context.Canceled", err)
	}
	fail.Store(true)
	if _, err = p.recipients(t.Context(), now.Add(2*time.Second)); err == nil {
		t.Fatal("stale keys used after expired discovery failed")
	}
	if calls.Load() != 2 {
		t.Fatal("absolute expiry did not force refresh")
	}
}

func TestHTTPSDiscoveryWaitHonorsContext(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancellation"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			priv, err := ecdh.GenerateKey(iana.EllipticCurveP_256)
			if err != nil {
				t.Fatal(err)
			}
			priv[iana.KeyParameterAlg] = iana.AlgorithmECDH_ES_A256KW
			pub, err := ecdh.ToPublicKey(priv)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := key.MarshalCBOR(ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: testPeerDomain, Keys: []ckapraw.FederationPublicKey{{PublicKey: pub, Status: testCurrentStatus}}})
			if err != nil {
				t.Fatal(err)
			}
			started := make(chan struct{})
			release := make(chan struct{})
			var calls atomic.Int64
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) == 1 {
					close(started)
				}
				<-release
				w.Header().Set("Content-Type", "application/ckap+cbor")
				w.Header().Set("Cache-Control", "max-age=60")
				_, _ = w.Write(raw)
			}))
			defer ts.Close()
			// Unblock the handler even when a fatal assertion ends the test.
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			ca := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0600); err != nil {
				t.Fatal(err)
			}
			p, err := newPeer(Peer{DomainID: testPeerDomain, URL: ts.URL + "/ckap", CAFile: ca})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			first := make(chan error, 1)
			go func() {
				_, err := p.recipients(t.Context(), now)
				first <- err
			}()
			select {
			case <-started:
			case err := <-first:
				t.Fatalf("first discovery ended before reaching handler: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("first discovery did not reach handler")
			}
			ctx, cancel := context.WithCancel(t.Context())
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
			}
			defer cancel()
			second := make(chan error, 1)
			waiting := make(chan struct{})
			go func() {
				close(waiting)
				_, err := p.recipients(ctx, now)
				second <- err
			}()
			<-waiting
			if !deadline {
				cancel()
			}
			<-ctx.Done()
			select {
			case err := <-second:
				if !errors.Is(err, ctx.Err()) {
					t.Fatalf("waiting discovery: got %v, want %v", err, ctx.Err())
				}
			case <-time.After(time.Second):
				t.Fatal("waiting discovery ignored its context while first discovery was blocked")
			}
			unblock()
			if err := <-first; err != nil {
				t.Fatalf("waiter cancellation affected first discovery: %v", err)
			}
			if _, err := p.recipients(t.Context(), now); err != nil || calls.Load() != 1 {
				t.Fatalf("completed discovery not reused: err=%v, calls=%d", err, calls.Load())
			}
		})
	}
}
