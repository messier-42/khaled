package disk

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cfar"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
)

const (
	unadvertiseColumn = "t_unadvertise"
)

func TestMigrateV1PreservesLocalHistory(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	db, err := sql.Open("sqlite", buildSQLiteDSN(filepath.Join(dir, dbFilename)))
	if err != nil {
		t.Fatal(err)
	}
	// This is the original v1 schema, independent of future schema changes.
	_, err = db.ExecContext(t.Context(), `CREATE TABLE khaled_meta(key TEXT NOT NULL PRIMARY KEY,value TEXT NOT NULL);
 INSERT INTO khaled_meta VALUES('schema_version','1');
 CREATE TABLE domain(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL);
 CREATE UNIQUE INDEX u_domain__name ON domain(name);
 CREATE TABLE root_key(id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,domain_id INTEGER NOT NULL REFERENCES domain(id),t_create TIMESTAMP NOT NULL,t_retire TIMESTAMP,seq_num INTEGER NOT NULL,secret BLOB NOT NULL,CHECK(seq_num>=0),CHECK(t_retire IS NULL OR t_retire>=t_create));
 CREATE UNIQUE INDEX u_root_key__seq_num ON root_key(domain_id,seq_num);
 CREATE UNIQUE INDEX u_root_key__current ON root_key(domain_id) WHERE t_retire IS NULL;
 CREATE TABLE key_series(domain_id INTEGER NOT NULL REFERENCES domain(id),attr_set_h BLOB NOT NULL,subepoch_num INTEGER NOT NULL,t_advance TIMESTAMP NOT NULL,PRIMARY KEY(domain_id,attr_set_h),CHECK(subepoch_num>=1));
 INSERT INTO domain VALUES(1,'default');
 INSERT INTO root_key VALUES(1,1,'2026-01-01T00:00:00.000000000Z','2026-01-02T00:00:00.000000000Z',0,zeroblob(32));
 INSERT INTO root_key VALUES(2,1,'2026-01-02T00:00:00.000000000Z',NULL,1,randomblob(32));
 INSERT INTO key_series VALUES(1,x'01',7,'2026-01-02T00:00:00.000000000Z');`)
	if err != nil {
		t.Fatal(err)
	}
	old := &Store{db: db}
	d := &domain{store: old, rowID: 1, name: "default"}
	root, err := d.RootKeyBySeqNum(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	info := &keystorage.DerivationInfo{Context: []byte("migration"), Length: 32}
	before, err := d.DeriveKey(ctx, root, info)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	var version string
	if err := s.db.QueryRowContext(t.Context(), `SELECT value FROM khaled_meta WHERE key='schema_version'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != "2" {
		t.Fatalf("schema version = %q, want 2", version)
	}
	dom, err := s.DomainByName(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	root, err = dom.RootKeyBySeqNum(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	after, err := dom.DeriveKey(ctx, root, info)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before.KeyBytes, after.KeyBytes) {
		t.Fatal("old derivation changed")
	}
	if root.RetirementTime().IsZero() {
		t.Fatal("retirement lost")
	}
	current, err := dom.CurrentRootKey(ctx)
	if err != nil || current.SeqNum() != 1 {
		t.Fatalf("current=%v err=%v", current, err)
	}
	sub, err := dom.CurrentSubEpoch(ctx, []byte{1})
	if err != nil || sub != 7 {
		t.Fatalf("subepoch=%d err=%v", sub, err)
	}
}

func TestFederationBootstrapBindingAndRecovery(t *testing.T) {
	dir := t.TempDir()
	ctx := t.Context()
	s, err := New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	d0, err := s.DomainByName(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	d, ok := d0.(keystorage.FederationDomain)
	if !ok {
		t.Fatal("storage lacks federation support")
	}
	if err := d.BindFederation(ctx, "domain-a", keystorage.FederationKeyOptions{}); err != nil {
		t.Fatal(err)
	}
	keys := federationKeys(t, d)
	if len(keys) != 1 {
		t.Fatalf("keys=%d", len(keys))
	}
	k := keys[0]
	if len(k.ID()) != 16 || !bytes.Equal(k.ID(), k.PublicKey().Kid()) {
		t.Fatal("FKID must be UUID bytes and match kid")
	}
	if k.PublicKey().Has(iana.EC2KeyParameterD) {
		t.Fatal("private key exported")
	}
	pub := k.PublicKey()
	pub.Kid()[0] ^= 255
	delete(pub, iana.KeyParameterAlg)
	if !bytes.Equal(k.ID(), k.PublicKey().Kid()) || !k.PublicKey().Has(iana.KeyParameterAlg) {
		t.Fatal("public key aliases handle")
	}
	raw, lc, lk := federationPackage(t, k)
	checkRecovery(t, ctx, k, raw, lc, lk)
	if err := d.BindFederation(ctx, "domain-a", keystorage.FederationKeyOptions{}); err != nil {
		t.Fatal(err)
	}
	if len(federationKeys(t, d)) != 1 {
		t.Fatal("bootstrap not idempotent")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	d0, err = s.DomainByName(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	d = d0.(keystorage.FederationDomain)
	if id, err := d.FederationIdentity(ctx); err != nil || id != "domain-a" {
		t.Fatalf("identity=%s err=%v", id, err)
	}
	if err := d.BindFederation(ctx, "domain-b", keystorage.FederationKeyOptions{}); !errors.Is(err, keystorage.ErrFederationDomainMismatch) {
		t.Fatalf("mismatch err=%v", err)
	}
	k2, err := d.FederationKeyByID(ctx, k.ID())
	if err != nil {
		t.Fatal(err)
	}
	checkRecovery(t, ctx, k2, raw, lc, lk)
}

func federationKeys(t *testing.T, d keystorage.FederationDomain) []keystorage.FederationKey {
	t.Helper()
	var out []keystorage.FederationKey
	for k, err := range d.ListFederationKeys(t.Context()) {
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, k)
	}
	return out
}
func federationPackage(t *testing.T, k keystorage.FederationKey) ([]byte, cfar.LeaseContext, cabe.LKAINonCaptive) {
	t.Helper()
	attrs, err := attrset.New(map[string]any{"project": "federation"})
	if err != nil {
		t.Fatal(err)
	}
	lc := cfar.LeaseContext{OriginDomain: "origin", AttributeSet: attrs, LeaseRef: []byte("lease-ref")}
	lk := cabe.LKAINonCaptive{RawCOSEKey: key.MustMarshalCBOR(key.Key{1: 4, 2: []byte("lease-kid"), 3: 1, 5: []byte("abcdefghijkl"), -1: []byte("0123456789abcdef"), "extension": []byte("preserve")})}
	raw, err := cfar.Generate(lc, lk, []key.Key{k.PublicKey()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return raw, lc, lk
}
func checkRecovery(t *testing.T, ctx context.Context, k keystorage.FederationKey, raw []byte, lc cfar.LeaseContext, lk cabe.LKAINonCaptive) {
	t.Helper()
	got, err := k.Recover(ctx, lc, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.RawCOSEKey, lk.RawCOSEKey) {
		t.Fatal("lease COSE key changed")
	}
}

func TestFederationRolloverLifecycleRecoveryAndCAS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	s, err := NewWithClock(ctx, dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	// The store closes explicitly before reopen; guard the fallback so a reused
	// lock descriptor cannot be closed a second time during test cleanup.
	storeClosed := false
	defer func() {
		if !storeClosed {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		}
	}()
	d0, _ := s.DomainByName(ctx, "default")
	d, ok := d0.(keystorage.FederationDomain)
	if !ok {
		t.Fatal("missing federation storage")
	}
	if err := d.BindFederation(ctx, "a", keystorage.FederationKeyOptions{}); err != nil {
		t.Fatal(err)
	}
	old := federationKeys(t, d)[0]
	raw, lc, lk := federationPackage(t, old)
	root, _ := d0.CurrentRootKey(ctx)
	info := &keystorage.DerivationInfo{Context: []byte("local"), Length: 32}
	before, _ := d0.DeriveKey(ctx, root, info)
	if _, err := d0.AdvanceSubEpoch(ctx, []byte{1}); err != nil {
		t.Fatal(err)
	}
	activate := now.Add(time.Hour)
	retire := now.Add(2 * time.Hour)
	unadvertise := now.Add(3 * time.Hour)
	schedule := keystorage.FederationRollover{Activate: activate, Retire: retire, Unadvertise: unadvertise}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Go(func() { _, err := d.RotateFederationKey(ctx, old, schedule); results <- err })
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, keystorage.ErrStaleFederationKey) {
			t.Fatal(err)
		}
	}
	if wins != 1 {
		t.Fatalf("rollover winners=%d", wins)
	}
	keys := federationKeys(t, d)
	if len(keys) != 2 {
		t.Fatalf("keys=%d", len(keys))
	}
	successor := keys[1]
	old = keys[0]
	if successor.Status(activate.Add(-time.Nanosecond)) != keystorage.FederationKeyFuture || successor.Status(activate) != keystorage.FederationKeyCurrent {
		t.Fatal("activation boundary")
	}
	if old.Status(retire.Add(-time.Nanosecond)) != keystorage.FederationKeyCurrent || old.Status(retire) != keystorage.FederationKeyRetired {
		t.Fatal("retirement boundary")
	}
	if !old.Advertised(unadvertise.Add(-time.Nanosecond)) || old.Advertised(unadvertise) {
		t.Fatal("advertisement boundary")
	}
	now = unadvertise.Add(time.Hour)
	// Callbacks must be free to query the one-connection database.
	for k, err := range d.ListFederationKeys(ctx) {
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(k.ID(), old.ID()) {
			checkRecovery(t, ctx, k, raw, lc, lk)
		}
	}
	after, _ := d0.DeriveKey(ctx, root, info)
	sub, _ := d0.CurrentSubEpoch(ctx, []byte{1})
	if !bytes.Equal(before.KeyBytes, after.KeyBytes) || sub != 1 {
		t.Fatal("federation rollover changed local history")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	storeClosed = true
	s, err = NewWithClock(ctx, dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	d0, _ = s.DomainByName(ctx, "default")
	d = d0.(keystorage.FederationDomain)
	old, err = d.FederationKeyByID(ctx, old.ID())
	if err != nil {
		t.Fatal(err)
	}
	checkRecovery(t, ctx, old, raw, lc, lk)
}

func TestFederationSupportedParametersAndAtomicRejection(t *testing.T) {
	for _, curve := range []int{0, iana.EllipticCurveP_256, iana.EllipticCurveP_384, iana.EllipticCurveP_521} {
		for _, alg := range []int{0, iana.AlgorithmECDH_ES_A128KW, iana.AlgorithmECDH_ES_A192KW, iana.AlgorithmECDH_ES_A256KW} {
			t.Run(fmt.Sprintf("%d/%d", curve, alg), func(t *testing.T) {
				s, err := New(t.Context(), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := s.Close(); err != nil {
						t.Error(err)
					}
				}()
				dom, _ := s.DomainByName(t.Context(), "default")
				d, ok := dom.(keystorage.FederationDomain)
				if !ok {
					t.Fatal("missing federation storage")
				}
				if err := d.BindFederation(t.Context(), "a", keystorage.FederationKeyOptions{Curve: curve, Algorithm: alg}); err != nil {
					t.Fatal(err)
				}
				k := federationKeys(t, d)[0]
				raw, lc, lk := federationPackage(t, k)
				checkRecovery(t, t.Context(), k, raw, lc, lk)
				if curve == 0 {
					got, _ := k.PublicKey().GetInt(iana.EC2KeyParameterCrv)
					if got != iana.EllipticCurveP_256 {
						t.Fatal("wrong default curve")
					}
				}
				if alg == 0 {
					got, _ := k.PublicKey().GetInt(iana.KeyParameterAlg)
					if got != iana.AlgorithmECDH_ES_A256KW {
						t.Fatal("wrong default algorithm")
					}
				}
			})
		}
	}
	for _, options := range []keystorage.FederationKeyOptions{{Curve: iana.EllipticCurveX25519}, {Curve: 999}, {Algorithm: iana.AlgorithmA256KW}} {
		s, err := New(t.Context(), t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := s.Close(); err != nil {
				t.Error(err)
			}
		}()
		dom, _ := s.DomainByName(t.Context(), "default")
		d := dom.(keystorage.FederationDomain)
		if err := d.BindFederation(t.Context(), "a", options); err == nil {
			t.Fatal("accepted unsupported parameters")
		}
		if id, err := d.FederationIdentity(t.Context()); err != nil || id != "" {
			t.Fatalf("partial binding: %q %v", id, err)
		}
		if len(federationKeys(t, d)) != 0 {
			t.Fatal("partial key insert")
		}
	}
}

func TestFederationRejectsCorruptPersistedKeys(t *testing.T) {
	for _, mutation := range []string{"invalid-cbor", "mismatched-kid", "missing-private", "mismatched-public"} {
		t.Run(mutation, func(t *testing.T) {
			s, err := New(t.Context(), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			}()
			dom, _ := s.DomainByName(t.Context(), "default")
			d := dom.(keystorage.FederationDomain)
			if err := d.BindFederation(t.Context(), "a", keystorage.FederationKeyOptions{}); err != nil {
				t.Fatal(err)
			}
			k := federationKeys(t, d)[0]
			raw, lc, _ := federationPackage(t, k)
			var stored []byte
			if err := s.db.QueryRowContext(t.Context(), `SELECT cose_key FROM federation_key WHERE fkid=?`, k.ID()).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			var full key.Key
			if err := key.UnmarshalCBOR(stored, &full); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "invalid-cbor":
				stored = []byte{0xff}
			case "mismatched-kid":
				full[iana.KeyParameterKid] = []byte("other")
				stored = key.MustMarshalCBOR(full)
			case "missing-private":
				delete(full, iana.EC2KeyParameterD)
				stored = key.MustMarshalCBOR(full)
			case "mismatched-public":
				full[iana.EC2KeyParameterX] = make([]byte, 32)
				stored = key.MustMarshalCBOR(full)
			}
			if _, err := s.db.ExecContext(t.Context(), `UPDATE federation_key SET cose_key=? WHERE fkid=?`, stored, k.ID()); err != nil {
				t.Fatal(err)
			}
			if _, err := d.FederationKeyByID(t.Context(), k.ID()); err == nil {
				t.Fatal("corrupt stored key accepted")
			}
			if _, err := k.Recover(t.Context(), lc, raw); err == nil {
				t.Fatalf("cached handle accepted corrupt key: %v", err)
			}
		})
	}
}

func TestFederationInvalidScheduleRollsBack(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	s, err := NewWithClock(t.Context(), t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	dom, _ := s.DomainByName(t.Context(), "default")
	d := dom.(keystorage.FederationDomain)
	if err := d.BindFederation(t.Context(), "a", keystorage.FederationKeyOptions{}); err != nil {
		t.Fatal(err)
	}
	old := federationKeys(t, d)[0]
	for _, schedule := range []keystorage.FederationRollover{{Activate: now.Add(-time.Second)}, {Retire: now.Add(-time.Second)}, {Retire: now.Add(time.Hour), Unadvertise: now}, {Options: keystorage.FederationKeyOptions{Curve: iana.EllipticCurveX25519}}} {
		if _, err := d.RotateFederationKey(t.Context(), old, schedule); err == nil {
			t.Fatal("invalid schedule accepted")
		}
		keys := federationKeys(t, d)
		if len(keys) != 1 || !keys[0].RetirementTime().IsZero() || !keys[0].UnadvertiseTime().IsZero() {
			t.Fatal("failed rollover was not atomic")
		}
	}
	if _, err := d.RotateFederationKey(t.Context(), old, keystorage.FederationRollover{}); err != nil {
		t.Fatal(err)
	}
}

func TestStorageIteratorsAllowNestedDatabaseUse(t *testing.T) {
	s, err := New(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	t.Run("domain", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		for d, err := range s.ListDomains(ctx) {
			if err != nil {
				t.Fatal(err)
			}
			if err := d.(keystorage.FederationDomain).BindFederation(ctx, "a", keystorage.FederationKeyOptions{}); err != nil {
				t.Fatal(err)
			}
		}
	})
	t.Run("root", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		d, err := s.DomainByName(ctx, "default")
		if err != nil {
			t.Fatal(err)
		}
		for k, err := range d.ListRootKeys(ctx) {
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.RootKeyByID(ctx, k.ID()); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func TestFederationRejectsNoncanonicalAndDisorderedStoredTimes(t *testing.T) {
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, column, value string
		nullRetire          bool
	}{
		{name: "create precision", column: "t_create", value: "2026-09-01T00:00:00Z"},
		{name: "activate offset", column: "t_activate", value: "2026-09-01T01:00:00.000000000+02:00"},
		{name: "retire precision", column: "t_retire", value: "2026-09-01T01:00:00Z"},
		{name: "unadvertise offset", column: unadvertiseColumn, value: "2026-09-01T02:00:00.000000000+00:00"},
		{name: "activation before creation", column: "t_activate", value: "2026-08-31T23:00:00.000000000Z"},
		{name: "retirement before activation", column: "t_retire", value: "2026-08-31T23:00:00.000000000Z"},
		{name: "unadvertise before retirement", column: unadvertiseColumn, value: "2026-09-01T00:30:00.000000000Z"},
		{name: "unadvertise without retirement", column: unadvertiseColumn, value: "2026-09-01T02:00:00.000000000Z", nullRetire: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewWithClock(t.Context(), t.TempDir(), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			}()
			dom, _ := s.DomainByName(t.Context(), "default")
			d := dom.(keystorage.FederationDomain)
			if err := d.BindFederation(t.Context(), "a", keystorage.FederationKeyOptions{}); err != nil {
				t.Fatal(err)
			}
			k := federationKeys(t, d)[0]
			if _, err := s.db.ExecContext(t.Context(), `UPDATE federation_key SET t_retire=?,t_unadvertise=?`, now.Add(time.Hour).Format(timestampFormat), now.Add(2*time.Hour).Format(timestampFormat)); err != nil {
				t.Fatal(err)
			}
			// Simulate damaged or externally edited storage as well as noncanonical text
			// that SQLite's lexical timestamp comparisons do not validate.
			if _, err := s.db.ExecContext(t.Context(), `PRAGMA ignore_check_constraints=ON`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.ExecContext(t.Context(), `UPDATE federation_key SET `+tc.column+`=?`, tc.value); err != nil {
				t.Fatal(err)
			}
			if tc.nullRetire {
				if _, err := s.db.ExecContext(t.Context(), `UPDATE federation_key SET t_retire=NULL`); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := d.FederationKeyByID(t.Context(), k.ID()); err == nil {
				t.Fatal("accepted malformed or disordered timestamps")
			}
		})
	}
}

func TestFederationRejectsUnrepresentableWriteTimes(t *testing.T) {
	for _, field := range []string{"bootstrap", "now", "activate", "retire", "unadvertise"} {
		t.Run(field, func(t *testing.T) {
			now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
			bad := time.Date(30000, 1, 1, 0, 0, 0, 0, time.UTC)
			s, err := NewWithClock(t.Context(), t.TempDir(), func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			}()
			dom, _ := s.DomainByName(t.Context(), "default")
			d := dom.(keystorage.FederationDomain)
			if field == "bootstrap" {
				now = bad
				if err := d.BindFederation(t.Context(), "a", keystorage.FederationKeyOptions{}); err == nil {
					t.Fatal("accepted unrepresentable bootstrap time")
				}
				id, err := d.FederationIdentity(t.Context())
				if err != nil || id != "" {
					t.Fatalf("binding persisted: %q %v", id, err)
				}
				var n int
				if err := s.db.QueryRowContext(t.Context(), `SELECT count(*) FROM federation_key`).Scan(&n); err != nil || n != 0 {
					t.Fatalf("key persisted: %d %v", n, err)
				}
				return
			}
			if err := d.BindFederation(t.Context(), "a", keystorage.FederationKeyOptions{}); err != nil {
				t.Fatal(err)
			}
			old := federationKeys(t, d)[0]
			schedule := keystorage.FederationRollover{}
			switch field {
			case "now":
				now = bad
			case "activate":
				schedule.Activate = bad
			case "retire":
				schedule.Retire = bad
			case "unadvertise":
				schedule.Unadvertise = bad
			}
			if _, err := d.RotateFederationKey(t.Context(), old, schedule); err == nil {
				t.Fatal("accepted unrepresentable rollover time")
			}
			keys := federationKeys(t, d)
			if len(keys) != 1 || !keys[0].RetirementTime().IsZero() || !keys[0].UnadvertiseTime().IsZero() {
				t.Fatal("failed rollover changed persisted keys")
			}
		})
	}
}

func TestFederationRecoveryKeepsPrivateKeyInStorage(t *testing.T) {
	s, err := New(t.Context(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	dom, err := s.DomainByName(t.Context(), "default")
	if err != nil {
		t.Fatal(err)
	}
	d := dom.(keystorage.FederationDomain)
	if err := d.BindFederation(t.Context(), "a", keystorage.FederationKeyOptions{}); err != nil {
		t.Fatal(err)
	}
	k := federationKeys(t, d)[0]
	public := k.PublicKey()
	if public.Has(iana.EC2KeyParameterD) {
		t.Fatal("private key exported")
	}
	raw, lc, expected := federationPackage(t, k)
	// Public snapshots are independent of the recovery handle.
	public[iana.KeyParameterKid] = []byte("different-handle")
	checkRecovery(t, t.Context(), k, raw, lc, expected)

	other, err := d.RotateFederationKey(t.Context(), k, keystorage.FederationRollover{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Recover(t.Context(), lc, raw); !errors.Is(err, cfar.ErrNoUsablePackage) {
		t.Fatalf("different key recovered package: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := k.Recover(ctx, lc, raw); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled recovery: %v", err)
	}
}
