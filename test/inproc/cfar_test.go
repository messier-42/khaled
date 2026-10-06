//go:build integration

package inproc

import (
	"bytes"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"

	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cabecap"
	"github.com/messier-42/cabe-go/cbes"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/keyschedule"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/plugin/keystorage/disk"

	"testing"

	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckapclient"
	"github.com/messier-42/khaled/pkg/config"
	khaledtest "github.com/messier-42/khaled/test/ktutil"
)

const (
	federationDomainIDField = "domainID"
	federationTargetDomain  = "target"
	federationLocalDomain   = "local"
)

func TestFederationDiscoveryIsPublic(t *testing.T) {
	s := khaledtest.Start(t, khaledtest.WithFederation(config.Map{federationDomainIDField: "public-domain"}))
	client, err := ckapclient.NewClient(ckapclient.Config{BaseURL: s.BaseURL(), HTTPClient: s.HTTPClientNoClientCert(t)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Error(err)
		}
	}()
	got, err := client.FederationIdentity(t.Context(), ckap.FederationIdentityRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Identity.DomainID != "public-domain" || len(got.Identity.Keys) != 1 || got.Expires == "" || got.CacheControl == "" {
		t.Fatalf("identity: %+v", got)
	}
	if _, err = client.GetSelf(t.Context(), ckap.GetSelfRequest{}); err == nil {
		t.Fatal("public discovery bypass leaked into private operations")
	}
}

// TestCFARPartitionAndRollover uses two real mTLS services and their separate
// SQLite histories. The Origin's discovery address is partitioned throughout;
// any attempted Target connection is counted and fails the test.
func TestCFARPartitionAndRollover(t *testing.T) {
	var attempts atomic.Int64
	blocked := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "partitioned", http.StatusServiceUnavailable)
	}))
	blocked.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			attempts.Add(1)
		}
	}
	blocked.StartTLS()
	defer blocked.Close()
	targetDir, originDir := t.TempDir(), t.TempDir()
	targetCfg := config.Map{federationDomainIDField: federationTargetDomain, "peers": config.Array{config.Map{federationDomainIDField: "origin", "url": blocked.URL}}}
	target := khaledtest.Start(t, khaledtest.WithKeyStorageDir(targetDir), khaledtest.WithFederation(targetCfg))
	identity, err := target.Client(t).FederationIdentity(t.Context(), ckap.FederationIdentityRequest{})
	if err != nil {
		t.Fatal(err)
	}
	rawID := ckapraw.FederationIdentity{Kind: ckapraw.KindFederationIdentity, DomainID: federationTargetDomain}
	for _, k := range identity.Identity.Keys {
		var pub key.Key
		if err = key.UnmarshalCBOR(k.RawCOSEKey, &pub); err != nil {
			t.Fatal(err)
		}
		rawID.Keys = append(rawID.Keys, ckapraw.FederationPublicKey{PublicKey: pub, Status: k.Status})
	}
	raw, err := key.MarshalCBOR(rawID)
	if err != nil {
		t.Fatal(err)
	}
	originCfg := config.Map{federationDomainIDField: "origin", "peers": config.Array{config.Map{federationDomainIDField: federationTargetDomain, "identity": base64.StdEncoding.EncodeToString(raw)}}}
	origin := khaledtest.Start(t, khaledtest.WithKeyStorageDir(originDir), khaledtest.WithFederation(originCfg))
	attrs, err := attrset.New(map[string]any{"mission": "ddil"})
	if err != nil {
		t.Fatal(err)
	}
	before, err := origin.Client(t).Prograde(t.Context(), ckap.ProgradeRequest{AttributeSet: attrs})
	if err != nil {
		t.Fatal(err)
	}
	if err = origin.Stop(); err != nil {
		t.Fatal(err)
	}
	// Offline maintenance after partition advances only Origin's Set-Key series.
	store, err := disk.New(t.Context(), originDir)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := store.DomainByName(t.Context(), "default")
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := keyschedule.New(t.Context(), keyschedule.Config{Domain: domain})
	if err != nil {
		t.Fatal(err)
	}
	if err = schedule.AdvanceSubEpoch(t.Context(), attrs); err != nil {
		t.Fatal(err)
	}
	if err = schedule.Close(); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	origin = khaledtest.Start(t, khaledtest.WithKeyStorageDir(originDir), khaledtest.WithFederation(originCfg))
	after, err := origin.Client(t).Prograde(t.Context(), ckap.ProgradeRequest{AttributeSet: attrs})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before.Lease.LKAI.NonCaptive.RawCOSEKey, after.Lease.LKAI.NonCaptive.RawCOSEKey) {
		t.Fatal("Origin rollover did not change LKAI")
	}
	sender, err := cabecap.NewWithClient(ckapclient.Config{BaseURL: origin.BaseURL(), HTTPClient: origin.HTTPClient(t)}, cabecap.WithARIN(false))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := sender.Close(); err != nil {
			t.Error(err)
		}
	}()
	envelope, err := sender.Encapsulate(t.Context(), cabe.Message{Attributes: attrs, Payload: []byte("new envelope after partition and rollover")})
	if err != nil {
		t.Fatal(err)
	}
	if err = origin.Stop(); err != nil {
		t.Fatal(err)
	}
	// Retire and unadvertise Target's original FK, then restart with its database.
	if err = target.Stop(); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	store, err = disk.NewWithClock(t.Context(), targetDir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	domain, err = store.DomainByName(t.Context(), "default")
	if err != nil {
		t.Fatal(err)
	}
	fd := domain.(keystorage.FederationDomain)
	var old keystorage.FederationKey
	for k, e := range fd.ListFederationKeys(t.Context()) {
		if e != nil {
			t.Fatal(e)
		}
		old = k
		break
	}
	if _, err = fd.RotateFederationKey(t.Context(), old, keystorage.FederationRollover{Activate: now, Retire: now, Unadvertise: now}); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	target = khaledtest.Start(t, khaledtest.WithKeyStorageDir(targetDir), khaledtest.WithFederation(targetCfg))
	for _, inline := range []bool{true, false} {
		receiver, e := cabecap.NewWithClient(ckapclient.Config{BaseURL: target.BaseURL(), HTTPClient: target.HTTPClient(t)}, cabecap.WithARIN(false))
		if e != nil {
			t.Fatal(e)
		}
		input := envelope
		if !inline {
			input, e = cbes.SetFLPs(envelope, nil)
			if e != nil {
				t.Fatal(e)
			}
		}
		message, e := receiver.Decapsulate(t.Context(), input)
		_ = receiver.Close()
		if e != nil || string(message.Payload) != "new envelope after partition and rollover" {
			t.Fatalf("inline=%v: %v", inline, e)
		}
	}
	if attempts.Load() != 0 {
		t.Fatalf("Target attempted %d Origin connections", attempts.Load())
	}
}

func TestLocalFederatedLeaseSurvivesDisabledRestart(t *testing.T) {
	dir := t.TempDir()
	service := khaledtest.Start(t, khaledtest.WithKeyStorageDir(dir), khaledtest.WithFederation(config.Map{federationDomainIDField: federationLocalDomain}))
	attrs, err := attrset.New(map[string]any{federationLocalDomain: true})
	if err != nil {
		t.Fatal(err)
	}
	pro, err := service.Client(t).Prograde(t.Context(), ckap.ProgradeRequest{AttributeSet: attrs})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.Stop(); err != nil {
		t.Fatal(err)
	}
	service = khaledtest.Start(t, khaledtest.WithKeyStorageDir(dir))
	retro, err := service.Client(t).Retrograde(t.Context(), ckap.RetrogradeRequest{AttributeSet: attrs, LeaseRef: pro.Lease.LeaseRef, Federation: &ckap.RetrogradeFederation{OriginDomain: federationLocalDomain}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pro.Lease.LKAI.NonCaptive.RawCOSEKey, retro.LKAI.NonCaptive.RawCOSEKey) {
		t.Fatal("local key changed")
	}
}
