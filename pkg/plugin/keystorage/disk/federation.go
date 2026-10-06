package disk

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"maps"
	"time"

	"github.com/google/uuid"
	"github.com/ldclabs/cose/iana"
	"github.com/ldclabs/cose/key"
	coseecdh "github.com/ldclabs/cose/key/ecdh"
	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/cfar"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
)

const federationSchemaDDL = `
CREATE TABLE federation_key (
  id            INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  domain_id     INTEGER NOT NULL REFERENCES domain (id),
  fkid          BLOB NOT NULL UNIQUE,
  t_create      TIMESTAMP NOT NULL,
  t_activate    TIMESTAMP NOT NULL,
  t_retire      TIMESTAMP,
  t_unadvertise TIMESTAMP,
  cose_key      BLOB NOT NULL,
  CHECK (typeof(fkid) = 'blob' AND length(fkid) > 0),
  CHECK (typeof(cose_key) = 'blob' AND length(cose_key) > 0),
  CHECK (t_activate >= t_create),
  CHECK (t_retire IS NULL OR t_retire >= t_activate),
  CHECK (
    t_unadvertise IS NULL OR
    (t_retire IS NOT NULL AND t_unadvertise >= t_retire)
  )
);
CREATE INDEX i_federation_key__domain_id
  ON federation_key (domain_id);
`

// federationKey holds only public material. Every unwrap loads the private COSE
// key anew from its own domain; callers never receive cached private bytes.
type federationKey struct {
	domain                                *domain
	id                                    []byte
	public                                key.Key
	create, activate, retire, unadvertise time.Time
}

func (k *federationKey) ID() []byte                 { return bytes.Clone(k.id) }
func (k *federationKey) CreationTime() time.Time    { return k.create }
func (k *federationKey) ActivationTime() time.Time  { return k.activate }
func (k *federationKey) RetirementTime() time.Time  { return k.retire }
func (k *federationKey) UnadvertiseTime() time.Time { return k.unadvertise }
func (k *federationKey) PublicKey() key.Key {
	out := make(key.Key, len(k.public))
	for label, v := range k.public {
		if b, ok := v.([]byte); ok {
			v = bytes.Clone(b)
		}
		out[label] = v
	}
	return out
}
func (k *federationKey) Status(at time.Time) keystorage.FederationKeyStatus {
	if at.Before(k.activate) {
		return keystorage.FederationKeyFuture
	}
	if !k.retire.IsZero() && !at.Before(k.retire) {
		return keystorage.FederationKeyRetired
	}
	return keystorage.FederationKeyCurrent
}
func (k *federationKey) Advertised(at time.Time) bool {
	return k.unadvertise.IsZero() || at.Before(k.unadvertise)
}

func (d *domain) federationIdentityMetaKey() string {
	return fmt.Sprintf("federation/domain/%d/domain-id", d.rowID)
}
func (d *domain) FederationIdentity(ctx context.Context) (string, error) {
	var id string
	err := d.store.db.QueryRowContext(ctx, `SELECT value FROM khaled_meta WHERE key=?`, d.federationIdentityMetaKey()).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}
func (d *domain) BindFederation(ctx context.Context, id string, options keystorage.FederationKeyOptions) error {
	if id == "" {
		return errors.New("disk keystorage: empty federation identity")
	}
	tx, err := d.store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var existing string
	err = tx.QueryRowContext(ctx, `SELECT value FROM khaled_meta WHERE key=?`, d.federationIdentityMetaKey()).Scan(&existing)
	if err == nil {
		if existing != id {
			return keystorage.ErrFederationDomainMismatch
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	now := d.store.now().UTC()
	if _, err := d.insertFederationKey(ctx, tx, options, now, now); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO khaled_meta(key,value) VALUES(?,?)`, d.federationIdentityMetaKey(), id); err != nil {
		return err
	}
	return tx.Commit()
}
func federationParameters(options keystorage.FederationKeyOptions) (ecdh.Curve, int, error) {
	var curve ecdh.Curve
	switch options.Curve {
	case 0, iana.EllipticCurveP_256:
		curve = ecdh.P256()
	case iana.EllipticCurveP_384:
		curve = ecdh.P384()
	case iana.EllipticCurveP_521:
		curve = ecdh.P521()
	default:
		return nil, 0, errors.New("disk keystorage: unsupported federation curve")
	}
	alg := options.Algorithm
	if alg == 0 {
		alg = iana.AlgorithmECDH_ES_A256KW
	}
	switch alg {
	case iana.AlgorithmECDH_ES_A128KW, iana.AlgorithmECDH_ES_A192KW, iana.AlgorithmECDH_ES_A256KW:
	default:
		return nil, 0, errors.New("disk keystorage: unsupported federation algorithm")
	}
	return curve, alg, nil
}
func (d *domain) insertFederationKey(ctx context.Context, tx *sql.Tx, options keystorage.FederationKeyOptions, created, activate time.Time) (*federationKey, error) {
	createdText, err := formatFederationTime(created)
	if err != nil {
		return nil, err
	}
	activateText, err := formatFederationTime(activate)
	if err != nil {
		return nil, err
	}
	if activate.Before(created) {
		return nil, errors.New("disk keystorage: federation activation precedes creation")
	}
	curve, alg, err := federationParameters(options)
	if err != nil {
		return nil, err
	}
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	public, err := coseecdh.KeyFromPublic(private.PublicKey())
	if err != nil {
		return nil, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	public[iana.KeyParameterKid] = bytes.Clone(id[:])
	public[iana.KeyParameterAlg] = alg
	full := make(key.Key, len(public)+1)
	maps.Copy(full, public)
	secret := private.Bytes()
	defer clear(secret)
	full[iana.EC2KeyParameterD] = secret
	raw, err := key.MarshalCBOR(full)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if _, err := tx.ExecContext(ctx, `INSERT INTO federation_key(domain_id,fkid,t_create,t_activate,cose_key) VALUES(?,?,?,?,?)`, d.rowID, id[:], createdText, activateText, raw); err != nil {
		return nil, err
	}
	return &federationKey{domain: d, id: bytes.Clone(id[:]), public: public, create: created, activate: activate}, nil
}

// Federation timestamps use canonical fixed-width UTC text because the schema
// compares them lexically. Reject noncanonical persisted values rather than
// letting timezone offsets or fractional precision change their ordering.
func parseFederationTime(raw string) (time.Time, error) {
	parsed, err := time.Parse(timestampFormat, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("disk keystorage: invalid federation timestamp: %w", err)
	}
	if parsed.UTC().Format(timestampFormat) != raw {
		return time.Time{}, errors.New("disk keystorage: noncanonical federation timestamp")
	}
	return parsed, nil
}

// Go time.Time permits years outside the four-digit database representation.
// Validate the serialized form before beginning any mutation that persists it.
func formatFederationTime(value time.Time) (string, error) {
	raw := value.UTC().Format(timestampFormat)
	parsed, err := parseFederationTime(raw)
	if err != nil {
		return "", err
	}
	if !parsed.Equal(value) {
		return "", errors.New("disk keystorage: unrepresentable federation timestamp")
	}
	return raw, nil
}

// CAST avoids the driver's TIMESTAMP-to-time.Time conversion, which would
// normalize malformed storage text and discard trailing fractional zeros.
const federationColumns = `fkid,CAST(t_create AS TEXT),CAST(t_activate AS TEXT),CAST(t_retire AS TEXT),CAST(t_unadvertise AS TEXT),cose_key`

func (d *domain) scanFederationKey(scanner interface{ Scan(dest ...any) error }) (*federationKey, error) {
	k := &federationKey{domain: d}
	var created, activate string
	var retire, unadvertise sql.NullString
	var raw []byte
	if err := scanner.Scan(&k.id, &created, &activate, &retire, &unadvertise, &raw); err != nil {
		return nil, err
	}
	defer clear(raw)
	var err error
	if k.create, err = parseFederationTime(created); err != nil {
		return nil, err
	}
	if k.activate, err = parseFederationTime(activate); err != nil {
		return nil, err
	}
	if retire.Valid {
		if k.retire, err = parseFederationTime(retire.String); err != nil {
			return nil, err
		}
	}
	if unadvertise.Valid {
		if k.unadvertise, err = parseFederationTime(unadvertise.String); err != nil {
			return nil, err
		}
	}
	if k.activate.Before(k.create) || (retire.Valid && k.retire.Before(k.activate)) ||
		(unadvertise.Valid && (!retire.Valid || k.unadvertise.Before(k.retire))) {
		return nil, errors.New("disk keystorage: invalid federation timestamp order")
	}
	full, err := decodeFederationKey(raw, k.id)
	if err != nil {
		return nil, err
	}
	defer clearPrivate(full)
	k.public, err = coseecdh.ToPublicKey(full)
	return k, err
}

// decodeFederationKey validates FKID and persisted key parameters before a key
// can be advertised or used. The returned private map stays inside this package.
func decodeFederationKey(raw, id []byte) (key.Key, error) {
	var full key.Key
	if err := key.UnmarshalCBOR(raw, &full); err != nil {
		return nil, fmt.Errorf("disk keystorage: invalid federation COSE key: %w", err)
	}
	fail := func() (key.Key, error) {
		clearPrivate(full)
		return nil, errors.New("disk keystorage: invalid federation key identity or material")
	}
	if len(id) == 0 || !bytes.Equal(id, full.Kid()) {
		return fail()
	}
	curve, err := full.GetInt(iana.EC2KeyParameterCrv)
	if err != nil {
		return fail()
	}
	alg, err := full.GetInt(iana.KeyParameterAlg)
	if err != nil {
		return fail()
	}
	if curve == 0 || alg == 0 {
		return fail()
	}
	c, _, err := federationParameters(keystorage.FederationKeyOptions{Curve: curve, Algorithm: alg})
	if err != nil {
		return fail()
	}
	kty, err := full.GetInt(iana.KeyParameterKty)
	if err != nil || kty != iana.KeyTypeEC2 {
		return fail()
	}
	secret, err := full.GetBytes(iana.EC2KeyParameterD)
	if err != nil {
		return fail()
	}
	private, err := c.NewPrivateKey(secret)
	if err != nil {
		return fail()
	}
	expected, err := coseecdh.KeyFromPublic(private.PublicKey())
	if err != nil {
		return fail()
	}
	for _, label := range []int{iana.EC2KeyParameterX, iana.EC2KeyParameterY} {
		got, err := full.GetBytes(label)
		want, _ := expected.GetBytes(label)
		if err != nil || !bytes.Equal(got, want) {
			return fail()
		}
	}
	return full, nil
}
func clearPrivate(k key.Key) {
	if b, ok := k[iana.EC2KeyParameterD].([]byte); ok {
		clear(b)
	}
}
func (d *domain) FederationKeyByID(ctx context.Context, id []byte) (keystorage.FederationKey, error) {
	k, err := d.scanFederationKey(d.store.db.QueryRowContext(ctx, `SELECT `+federationColumns+` FROM federation_key WHERE domain_id=? AND fkid=?`, d.rowID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, keystorage.ErrNoSuchFederationKey
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}
func (d *domain) ListFederationKeys(ctx context.Context) iter.Seq2[keystorage.FederationKey, error] {
	return func(yield func(keystorage.FederationKey, error) bool) {
		rows, err := d.store.db.QueryContext(ctx, `SELECT `+federationColumns+` FROM federation_key WHERE domain_id=? ORDER BY id`, d.rowID)
		if err != nil {
			yield(nil, err)
			return
		}
		defer func() { _ = rows.Close() }()
		var keys []*federationKey
		for rows.Next() {
			k, e := d.scanFederationKey(rows)
			if e != nil {
				err = e
				break
			}
			keys = append(keys, k)
		}
		if err == nil {
			err = rows.Err()
		}
		// Release the sole connection before callbacks use these recovery handles.
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			yield(nil, err)
			return
		}
		for _, k := range keys {
			if !yield(k, nil) {
				return
			}
		}
	}
}

// Recover loads and clears private material within the storage boundary. Each
// attempt revalidates the persisted key, even when the public handle is cached.
func (k *federationKey) Recover(ctx context.Context, lease cfar.LeaseContext, raw []byte) (*cabe.LKAINonCaptive, error) {
	var stored []byte
	err := k.domain.store.db.QueryRowContext(ctx, `SELECT cose_key FROM federation_key WHERE domain_id=? AND fkid=?`, k.domain.rowID, k.id).Scan(&stored)
	if err != nil {
		return nil, err
	}
	defer clear(stored)
	full, err := decodeFederationKey(stored, k.id)
	if err != nil {
		return nil, err
	}
	defer clearPrivate(full)
	return cfar.Recover(lease, cabe.FLPSet{raw}, []key.Key{full})
}

var _ keystorage.FederationDomain = (*domain)(nil)
var _ keystorage.FederationKey = (*federationKey)(nil)

func (d *domain) RotateFederationKey(ctx context.Context, old keystorage.FederationKey, schedule keystorage.FederationRollover) (keystorage.FederationKey, error) {
	// Accept handles only from this storage domain; FKIDs are globally unique but
	// a caller must not accidentally use a handle from a different open store.
	previous, ok := old.(*federationKey)
	if !ok || previous == nil || previous.domain.store != d.store || previous.domain.rowID != d.rowID {
		return nil, keystorage.ErrStaleFederationKey
	}
	now := d.store.now().UTC()
	activate := schedule.Activate.UTC()
	retire := schedule.Retire.UTC()
	unadvertise := schedule.Unadvertise.UTC()
	if activate.IsZero() {
		activate = now
	}
	if retire.IsZero() {
		retire = now
	}
	if _, err := formatFederationTime(now); err != nil {
		return nil, err
	}
	if _, err := formatFederationTime(activate); err != nil {
		return nil, err
	}
	retireText, err := formatFederationTime(retire)
	if err != nil {
		return nil, err
	}
	var unadvertiseValue any
	if !unadvertise.IsZero() {
		unadvertiseText, err := formatFederationTime(unadvertise)
		if err != nil {
			return nil, err
		}
		unadvertiseValue = unadvertiseText
	}
	if activate.Before(now) || retire.Before(now) || retire.Before(previous.activate) || (!unadvertise.IsZero() && unadvertise.Before(retire)) {
		return nil, errors.New("disk keystorage: invalid federation rollover schedule")
	}
	tx, err := d.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `UPDATE federation_key SET t_retire=?,t_unadvertise=? WHERE domain_id=? AND fkid=? AND t_retire IS NULL`, retireText, unadvertiseValue, d.rowID, previous.id)
	if err != nil {
		return nil, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, keystorage.ErrStaleFederationKey
	}
	successor, err := d.insertFederationKey(ctx, tx, schedule.Options, now, activate)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return successor, nil
}
