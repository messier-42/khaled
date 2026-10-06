package authnsub

import (
	"context"
	"strings"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
)

const (
	pluginSelector  = "use"
	anonymousPlugin = "anonymous"
	clientAuthnKey  = "clientAuthn"
	principalURIKey = "uri"
)

func TestStartTolerantOfMissingBlock(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{}}
	m, err := New(snap, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop() }()
	if got := m.Current(); got != nil {
		t.Errorf("expected nil authenticator with no clientAuthn block")
	}
}

func TestStartTLSSpiffeRequiresSharedSource(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		clientAuthnKey: config.Map{pluginSelector: "tls-spiffe"},
	}}
	_, err := New(snap, nil)
	if err == nil {
		t.Fatalf("expected tls-spiffe without shared source to fail")
	}
	if !strings.Contains(err.Error(), "shared SPIFFE source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagerReconcileNoOp(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{}}
	m, _ := New(snap, nil)
	defer func() { _ = m.Stop() }()

	if err := m.Reconcile(context.Background(), snap); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func TestManagerReconcileRejectsUnsupportedPlugin(t *testing.T) {
	m, _ := New(config.Snapshot{Root: config.Map{}}, nil)
	defer func() { _ = m.Stop() }()

	snap := config.Snapshot{Root: config.Map{
		clientAuthnKey: config.Map{pluginSelector: "ftp-kerberos"},
	}}
	if err := m.Reconcile(context.Background(), snap); err == nil {
		t.Fatalf("expected unknown plugin to fail")
	}
}

func TestStartAnonymous(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		clientAuthnKey: config.Map{
			pluginSelector: anonymousPlugin,
			anonymousPlugin: config.Map{
				principalURIKey: "https://example.test/anon",
			},
		},
	}}
	m, err := New(snap, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop() }()
	if got := m.Current(); got == nil {
		t.Fatalf("expected an anonymous authenticator to be installed")
	}
}

func TestStartAnonymousWithoutURI(t *testing.T) {
	// Omitting the anonymous subblock is valid — the plugin substitutes
	// its DefaultURI.
	snap := config.Snapshot{Root: config.Map{
		clientAuthnKey: config.Map{pluginSelector: anonymousPlugin},
	}}
	m, err := New(snap, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop() }()
	if got := m.Current(); got == nil {
		t.Fatalf("expected an anonymous authenticator to be installed")
	}
}

func TestManagerReconcileRebuildsOnAnonymousURIChange(t *testing.T) {
	snap1 := config.Snapshot{Root: config.Map{
		clientAuthnKey: config.Map{
			pluginSelector: anonymousPlugin,
			anonymousPlugin: config.Map{
				principalURIKey: "https://example.test/one",
			},
		},
	}}
	m, err := New(snap1, nil)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = m.Stop() }()
	first := m.Current()

	snap2 := config.Snapshot{Root: config.Map{
		clientAuthnKey: config.Map{
			pluginSelector: anonymousPlugin,
			anonymousPlugin: config.Map{
				principalURIKey: "https://example.test/two",
			},
		},
	}}
	if err := m.Reconcile(context.Background(), snap2); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	second := m.Current()
	if second == nil {
		t.Fatalf("expected an authenticator after reconcile")
	}
	if first == second {
		t.Errorf("expected reconcile to rebuild the authenticator on uri change")
	}
}
