package keyserversub

import (
	"bytes"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
)

const (
	federationDomainIDField = "domainID"
	testFederationDomain    = "domain"
)

func TestFederationReloadKeepsStoreAndIdentity(t *testing.T) {
	dir := t.TempDir()
	snap := snapshotForKeyStorage(dir)
	snap.Root["federation"] = config.Map{federationDomainIDField: testFederationDomain}
	m, err := New(t.Context(), snap, stubPolicyEngine{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := m.Stop(); err != nil {
			t.Error(err)
		}
	}()
	before := m.Current()
	id, _, err := before.Server().FederationIdentity(t.Context())
	if err != nil || id == nil {
		t.Fatalf("identity: %v", err)
	}
	kid := id.Keys[0].PublicKey.Kid()
	next := snapshotForKeyStorage(dir)
	next.Root["federation"] = config.Map{federationDomainIDField: testFederationDomain, "identityMaxAge": "2m"}
	if err = m.Reconcile(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	if m.Current() != before {
		t.Fatal("federation reload rebuilt shared key store")
	}
	id, _, err = m.Current().Server().FederationIdentity(t.Context())
	if err != nil || !bytes.Equal(kid, id.Keys[0].PublicKey.Kid()) {
		t.Fatal("reload replaced FK")
	}
	bad := snapshotForKeyStorage(dir)
	bad.Root["federation"] = config.Map{federationDomainIDField: "other"}
	if err = m.Reconcile(t.Context(), bad); err == nil {
		t.Fatal("identity rebound")
	}
	id, _, err = m.Current().Server().FederationIdentity(t.Context())
	if err != nil || id.DomainID != testFederationDomain {
		t.Fatal("invalid reload lost identity")
	}
}
