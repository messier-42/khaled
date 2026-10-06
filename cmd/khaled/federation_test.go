package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/plugin"
)

const (
	federationInitCommand   = "init"
	federationTestDomainID  = "domain-a"
	federationTestCurrent   = "current"
	federationRotateCommand = "rotate"
	federationFKIDFlag      = "--fkid"
	federationActivateFlag  = "--activate"
	federationDomainIDFlag  = "--domain-id"
)

func federationCLI(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()
	var out, stderr bytes.Buffer
	cmd := newRootCmd(nil, &out, &stderr)
	cmd.SetArgs(append([]string{"federation", "--store", dir}, args...))
	err := cmd.ExecuteContext(t.Context())
	return out.String(), err
}

func federationCLIIdentity(t *testing.T, dir string) (string, ckapraw.FederationIdentity) {
	t.Helper()
	out, err := federationCLI(t, dir, "identity")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("identity is not base64: %v", err)
	}
	var identity ckapraw.FederationIdentity
	if err := key.UnmarshalCBOR(raw, &identity); err != nil {
		t.Fatal(err)
	}
	if identity.Kind != ckapraw.KindFederationIdentity {
		t.Fatalf("kind = %q", identity.Kind)
	}
	if _, err := identity.ToCABE(); err != nil {
		t.Fatal(err)
	}
	for _, k := range identity.Keys {
		if k.PublicKey.Has(iana.EC2KeyParameterD) {
			t.Fatal("identity exposes private key")
		}
	}
	return out, identity
}

func TestFederationCLIInitPersistsIdentity(t *testing.T) {
	dir := t.TempDir()
	if _, err := federationCLI(t, dir, federationInitCommand, federationDomainIDFlag, federationTestDomainID); err != nil {
		t.Fatal(err)
	}
	before, identity := federationCLIIdentity(t, dir)
	if identity.DomainID != federationTestDomainID || len(identity.Keys) != 1 {
		t.Fatalf("identity = %+v", identity)
	}
	if _, err := federationCLI(t, dir, federationInitCommand, federationDomainIDFlag, federationTestDomainID); err != nil {
		t.Fatal(err)
	}
	after, _ := federationCLIIdentity(t, dir)
	if before != after {
		t.Fatal("restart or repeated initialization changed identity")
	}
	if _, err := federationCLI(t, dir, federationInitCommand, federationDomainIDFlag, "domain-b"); err == nil {
		t.Fatal("rebound domain identity")
	}
}

func TestFederationCLIRotationRetainsHistory(t *testing.T) {
	dir := t.TempDir()
	if _, err := federationCLI(t, dir, federationInitCommand, federationDomainIDFlag, federationTestDomainID); err != nil {
		t.Fatal(err)
	}
	_, initial := federationCLIIdentity(t, dir)
	oldID := hex.EncodeToString(initial.Keys[0].PublicKey.Kid())
	if _, err := federationCLI(t, dir, federationRotateCommand, federationFKIDFlag, oldID, "--curve", "P-384", "--algorithm", "ECDH-ES+A128KW"); err != nil {
		t.Fatal(err)
	}
	_, rotated := federationCLIIdentity(t, dir)
	if len(rotated.Keys) != 2 {
		t.Fatalf("keys = %d", len(rotated.Keys))
	}
	var successor string
	for _, k := range rotated.Keys {
		id := hex.EncodeToString(k.PublicKey.Kid())
		if id == oldID {
			if k.Status != "retired" {
				t.Fatalf("old status = %q", k.Status)
			}
		} else {
			successor = id
			if k.Status != federationTestCurrent {
				t.Fatalf("new status = %q", k.Status)
			}
			if k.PublicKey.Alg() != iana.AlgorithmECDH_ES_A128KW {
				t.Fatal("wrong successor algorithm")
			}
		}
	}
	if successor == "" {
		t.Fatal("missing successor")
	}
	list, err := federationCLI(t, dir, "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{oldID, successor, "retired", federationTestCurrent, "CREATED", "ACTIVATE", "RETIRE", "UNADVERTISE"} {
		if !strings.Contains(list, want) {
			t.Fatalf("list missing %q: %s", want, list)
		}
	}
}

func TestFederationCLIInvalidRotationDoesNotMutate(t *testing.T) {
	dir := t.TempDir()
	if _, err := federationCLI(t, dir, federationInitCommand, federationDomainIDFlag, federationTestDomainID); err != nil {
		t.Fatal(err)
	}
	before, initial := federationCLIIdentity(t, dir)
	fkid := hex.EncodeToString(initial.Keys[0].PublicKey.Kid())
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	for _, args := range [][]string{
		{federationRotateCommand},
		{federationRotateCommand, federationFKIDFlag, "invalid"},
		{federationRotateCommand, federationFKIDFlag, fkid, "--curve", "X25519"},
		{federationRotateCommand, federationFKIDFlag, fkid, "--algorithm", "ECDH-ES"},
		{federationRotateCommand, federationFKIDFlag, fkid, federationActivateFlag, "invalid"},
		{federationRotateCommand, federationFKIDFlag, fkid, federationActivateFlag, "2000-01-01T00:00:00Z"},
		{federationRotateCommand, federationFKIDFlag, fkid, "--retire", future, "--unadvertise", "2000-01-01T00:00:00Z"},
	} {
		if _, err := federationCLI(t, dir, args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
		after, _ := federationCLIIdentity(t, dir)
		if before != after {
			t.Fatalf("invalid rotation changed keys: %v", args)
		}
	}
}

func TestFederationCLIRejectsExplicitZeroSchedule(t *testing.T) {
	for _, flag := range []string{federationActivateFlag, "--retire", "--unadvertise"} {
		t.Run(flag, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := federationCLI(t, dir, federationInitCommand, federationDomainIDFlag, federationTestDomainID); err != nil {
				t.Fatal(err)
			}
			_, initial := federationCLIIdentity(t, dir)
			before, err := federationCLI(t, dir, "list")
			if err != nil {
				t.Fatal(err)
			}
			fkid := hex.EncodeToString(initial.Keys[0].PublicKey.Kid())
			if _, err := federationCLI(t, dir, federationRotateCommand, federationFKIDFlag, fkid, flag, "0001-01-01T00:00:00Z"); err == nil {
				t.Errorf("accepted explicit zero time for %s", flag)
			}
			after, err := federationCLI(t, dir, "list")
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Errorf("explicit zero time for %s mutated keys or schedules", flag)
			}
		})
	}
}

func TestFederationCLIRejectsLiveStore(t *testing.T) {
	dir := t.TempDir()
	args := plugin.KeyStorageArgs{PluginName: "disk"}
	args.Disk.Path = dir
	store, err := plugin.NewKeyStorage(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	for _, command := range [][]string{{federationInitCommand, federationDomainIDFlag, federationTestDomainID}, {"identity"}, {"list"}} {
		if _, err := federationCLI(t, dir, command...); err == nil || !strings.Contains(err.Error(), "lock") {
			t.Fatalf("live store accepted or wrong error: %v", err)
		}
	}
}

func TestFederationCLIRequiredOptionsAndCurves(t *testing.T) {
	for _, args := range [][]string{{federationInitCommand}, {federationInitCommand, federationDomainIDFlag, ""}, {federationInitCommand, federationDomainIDFlag, federationTestDomainID, "--curve", "X25519"}, {"identity"}, {"list", "--domain-name", "absent"}} {
		if _, err := federationCLI(t, t.TempDir(), args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	var out bytes.Buffer
	cmd := newRootCmd(nil, &out, &out)
	cmd.SetArgs([]string{"federation", federationInitCommand, federationDomainIDFlag, federationTestDomainID})
	if err := cmd.ExecuteContext(t.Context()); err == nil {
		t.Fatal("accepted missing store")
	}
	for _, curve := range []string{"P-256", "P-384", "P-521"} {
		dir := t.TempDir()
		if _, err := federationCLI(t, dir, federationInitCommand, federationDomainIDFlag, federationTestDomainID, "--curve", curve, "--algorithm", "ECDH-ES+A192KW"); err != nil {
			t.Fatal(err)
		}
		_, identity := federationCLIIdentity(t, dir)
		if identity.Keys[0].PublicKey.Alg() != iana.AlgorithmECDH_ES_A192KW {
			t.Fatal("wrong configured algorithm")
		}
	}
}

func TestFederationCLIScheduledRollover(t *testing.T) {
	dir := t.TempDir()
	if _, err := federationCLI(t, dir, federationInitCommand, federationDomainIDFlag, federationTestDomainID); err != nil {
		t.Fatal(err)
	}
	_, initial := federationCLIIdentity(t, dir)
	oldID := hex.EncodeToString(initial.Keys[0].PublicKey.Kid())
	activate := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	retire := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	unadvertise := time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339)
	if _, err := federationCLI(t, dir, federationRotateCommand, federationFKIDFlag, oldID, federationActivateFlag, activate, "--retire", retire, "--unadvertise", unadvertise); err != nil {
		t.Fatal(err)
	}
	_, identity := federationCLIIdentity(t, dir)
	if len(identity.Keys) != 2 {
		t.Fatalf("keys = %d", len(identity.Keys))
	}
	for _, k := range identity.Keys {
		want := "future"
		if hex.EncodeToString(k.PublicKey.Kid()) == oldID {
			want = federationTestCurrent
		}
		if k.Status != want {
			t.Fatalf("status = %q, want %q", k.Status, want)
		}
	}
	list, err := federationCLI(t, dir, "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, timestamp := range []string{activate, retire, unadvertise} {
		if !strings.Contains(list, timestamp) {
			t.Fatalf("list missing schedule %q: %s", timestamp, list)
		}
	}
	if _, err := federationCLI(t, dir, federationRotateCommand, federationFKIDFlag, oldID); err == nil {
		t.Fatal("overwrote scheduled retirement")
	}
}
