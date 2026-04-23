package disk

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"strconv"
	"time"

	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/messier-42/khaled/pkg/plugin/keystorage"
)

// domain is the disk plugin's KeyStoreDomain implementation.
type domain struct {
	store *Store
	id    keystorage.DomainID
	rowID int64
	name  string
}

var _ keystorage.KeyStoreDomain = &domain{}

func (d *domain) ID() keystorage.DomainID { return d.id }
func (d *domain) Name() string            { return d.name }

// rootKey is a Root Key snapshot taken at the time of the database
// read. retireTime is zero for the unretired key (NULL t_retire in the row).
type rootKey struct {
	id         keystorage.KeyID
	seqNum     uint64
	createTime time.Time
	retireTime time.Time
	secret     []byte
	domainID   int64
}

var _ keystorage.RootKey = &rootKey{}

func (k *rootKey) ID() keystorage.KeyID      { return k.id }
func (k *rootKey) SeqNum() uint64            { return k.seqNum }
func (k *rootKey) CreationTime() time.Time   { return k.createTime }
func (k *rootKey) RetirementTime() time.Time { return k.retireTime }

const rootKeyColumns = `t_create, t_retire, seq_num, secret`

// CurrentRootKey returns the unretired root key for the domain.
func (d *domain) CurrentRootKey(ctx context.Context) (keystorage.RootKey, error) {
	row := d.store.db.QueryRowContext(ctx,
		`SELECT `+rootKeyColumns+` FROM root_key
		  WHERE domain_id = ? AND t_retire IS NULL`,
		d.rowID,
	)
	k, err := scanRootKey(row, d.rowID)
	if err != nil {
		return nil, fmt.Errorf("disk keystorage: current root key for domain %q: %w", d.name, err)
	}
	return k, nil
}

// RootKeyByID returns the root key with the given ID. The disk
// plugin's KeyID is the stringified seq_num.
func (d *domain) RootKeyByID(ctx context.Context, id keystorage.KeyID) (keystorage.RootKey, error) {
	seqNum, err := parseSeqNum(id)
	if err != nil {
		return nil, fmt.Errorf("disk keystorage: parse root key id %q: %w", id, keystorage.ErrNoSuchRootKey)
	}
	return d.rootKeyBySeqNum(ctx, seqNum)
}

// RootKeyBySeqNum returns the root key with the given seq_num.
// This is the direct-by-seqnum path callers reach for when they
// have a serialised wire-format seqnum and shouldn't have to
// know the plugin's KeyID encoding.
func (d *domain) RootKeyBySeqNum(ctx context.Context, seqNum uint64) (keystorage.RootKey, error) {
	return d.rootKeyBySeqNum(ctx, seqNum)
}

func (d *domain) rootKeyBySeqNum(ctx context.Context, seqNum uint64) (keystorage.RootKey, error) {
	row := d.store.db.QueryRowContext(ctx,
		`SELECT `+rootKeyColumns+` FROM root_key
		  WHERE domain_id = ? AND seq_num = ?`,
		d.rowID, seqNum,
	)
	k, err := scanRootKey(row, d.rowID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("disk keystorage: root key seq_num=%d in domain %q: %w", seqNum, d.name, keystorage.ErrNoSuchRootKey)
	}
	if err != nil {
		return nil, fmt.Errorf("disk keystorage: root key seq_num=%d in domain %q: %w", seqNum, d.name, err)
	}
	return k, nil
}

// ListRootKeys yields root keys in descending seq_num order.
func (d *domain) ListRootKeys(ctx context.Context) iter.Seq2[keystorage.RootKey, error] {
	return func(yield func(keystorage.RootKey, error) bool) {
		rows, err := d.store.db.QueryContext(ctx,
			`SELECT `+rootKeyColumns+` FROM root_key
			  WHERE domain_id = ?
			  ORDER BY seq_num DESC`,
			d.rowID,
		)
		if err != nil {
			yield(nil, fmt.Errorf("disk keystorage: list root keys for domain %q: %w", d.name, err))
			return
		}
		defer rows.Close() // best effort

		for rows.Next() {
			k, err := scanRootKey(rows, d.rowID)
			if err != nil {
				yield(nil, fmt.Errorf("disk keystorage: scan root key for domain %q: %w", d.name, err))
				return
			}
			if !yield(k, nil) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			yield(nil, fmt.Errorf("disk keystorage: iterate root keys for domain %q: %w", d.name, err))
		}
	}
}

// RotateRootKey atomically retires oldKey and inserts its successor.
// The CAS check (oldKey.ID() must match the current key's ID at
// commit time) is enforced both at the application layer (the UPDATE
// targets t_retire IS NULL) and at the storage layer (the partial
// unique index on (domain_id) WHERE t_retire IS NULL).
func (d *domain) RotateRootKey(ctx context.Context, oldKey keystorage.RootKey) (keystorage.RootKey, error) {
	if oldKey == nil {
		return nil, errors.New("disk keystorage: RotateRootKey: oldKey is nil")
	}

	oldSeqNum, err := parseSeqNum(oldKey.ID())
	if err != nil {
		return nil, fmt.Errorf("disk keystorage: parse old root key id: %w", keystorage.ErrStaleRootKey)
	}

	now := d.store.now().UTC()
	nowStr := now.Format(timestampFormat)
	newSecret := make([]byte, rootKeyLen)

	// Best effort zeroization.
	committed := false
	defer func() {
		if !committed {
			clear(newSecret)
		}
	}()

	if _, err := rand.Read(newSecret); err != nil {
		return nil, fmt.Errorf("disk keystorage: generate root secret: %w", err)
	}

	tx, err := d.store.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("disk keystorage: begin rotate tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// CAS: only retire the row if it is still the current key AND
	// has the seq_num the caller observed.
	res, err := tx.ExecContext(ctx,
		`UPDATE root_key SET t_retire = ?
		   WHERE domain_id = ? AND seq_num = ? AND t_retire IS NULL`,
		nowStr, d.rowID, oldSeqNum,
	)
	if err != nil {
		return nil, fmt.Errorf("disk keystorage: retire root key: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("disk keystorage: rows affected: %w", err)
	}
	if rows == 0 {
		return nil, keystorage.ErrStaleRootKey
	}

	newSeqNum := oldSeqNum + 1
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO root_key (domain_id, t_create, t_retire, seq_num, secret)
		 VALUES (?, ?, NULL, ?, ?)`,
		d.rowID, nowStr, newSeqNum, newSecret,
	); err != nil {
		if isUniqueConstraint(err) {
			return nil, keystorage.ErrStaleRootKey
		}
		return nil, fmt.Errorf("disk keystorage: insert successor root key: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM key_series WHERE domain_id = ?`, d.rowID,
	); err != nil {
		return nil, fmt.Errorf("disk keystorage: clear subepoch counters: %w", err)
	}

	if err := tx.Commit(); err != nil {
		if isUniqueConstraint(err) {
			return nil, keystorage.ErrStaleRootKey
		}
		return nil, fmt.Errorf("disk keystorage: commit rotate: %w", err)
	}

	committed = true
	return &rootKey{
		id:         keystorage.KeyID(strconv.FormatUint(newSeqNum, 10)),
		seqNum:     newSeqNum,
		createTime: now,
		retireTime: time.Time{},
		secret:     newSecret,
		domainID:   d.rowID,
	}, nil
}

// DeriveKey derives a key of info.Length bytes from rootKey using
// HKDF-SHA-256, with info.Context as the HKDF info parameter and a
// fixed all-zero salt.
func (d *domain) DeriveKey(ctx context.Context, root keystorage.RootKey, info *keystorage.DerivationInfo) (*keystorage.DerivedKey, error) {
	if root == nil {
		return nil, errors.New("disk keystorage: DeriveKey: rootKey is nil")
	}
	if info == nil {
		return nil, errors.New("disk keystorage: DeriveKey: info is nil")
	}
	if info.Length <= 0 {
		return nil, fmt.Errorf("disk keystorage: DeriveKey: invalid length %d", info.Length)
	}

	rk, err := d.materialise(ctx, root)
	if err != nil {
		return nil, err
	}

	out, err := hkdf.Key(sha256.New, rk.secret, nil, string(info.Context), info.Length)
	if err != nil {
		return nil, fmt.Errorf("disk keystorage: HKDF: %w", err)
	}
	return &keystorage.DerivedKey{KeyBytes: out}, nil
}

// materialise returns a *rootKey with the secret loaded.
func (d *domain) materialise(ctx context.Context, root keystorage.RootKey) (*rootKey, error) {
	if rk, ok := root.(*rootKey); ok && rk.domainID == d.rowID && len(rk.secret) > 0 {
		return rk, nil
	}

	rk, err := d.RootKeyByID(ctx, root.ID())
	if err != nil {
		return nil, err
	}

	concrete, ok := rk.(*rootKey)
	if !ok {
		return nil, fmt.Errorf("disk keystorage: unexpected RootKey type %T", rk)
	}

	return concrete, nil
}

// scanRootKey reads a row whose columns are
// (t_create, t_retire, seq_num, secret) in that order.
func scanRootKey(scanner interface {
	Scan(dest ...any) error
}, domainID int64) (*rootKey, error) {
	var (
		tCreateStr string
		tRetireStr sql.NullString
		seqNum     int64
		secret     []byte
	)
	if err := scanner.Scan(&tCreateStr, &tRetireStr, &seqNum, &secret); err != nil {
		return nil, err
	}
	tCreate, err := time.Parse(time.RFC3339Nano, tCreateStr)
	if err != nil {
		return nil, fmt.Errorf("disk keystorage: parse t_create: %w", err)
	}
	var tRetire time.Time
	if tRetireStr.Valid {
		tRetire, err = time.Parse(time.RFC3339Nano, tRetireStr.String)
		if err != nil {
			return nil, fmt.Errorf("disk keystorage: parse t_retire: %w", err)
		}
	}
	if seqNum < 0 {
		return nil, fmt.Errorf("disk keystorage: negative seq_num %d", seqNum)
	}
	return &rootKey{
		id:         keystorage.KeyID(strconv.FormatInt(seqNum, 10)),
		seqNum:     uint64(seqNum),
		createTime: tCreate,
		retireTime: tRetire,
		secret:     secret,
		domainID:   domainID,
	}, nil
}

func parseSeqNum(id keystorage.KeyID) (uint64, error) {
	if id == "" {
		return 0, errors.New("empty key id")
	}
	return strconv.ParseUint(string(id), 10, 64)
}

// validateAttrSetHash returns an error tagged with the calling
// method name if attrSetHash is empty.
func validateAttrSetHash(method string, attrSetHash []byte) error {
	if len(attrSetHash) == 0 {
		return fmt.Errorf("disk keystorage: %s: empty attrSetHash", method)
	}
	return nil
}

// isUniqueConstraint reports whether err is a SQLite
// SQLITE_CONSTRAINT_UNIQUE error.
func isUniqueConstraint(err error) bool {
	var serr *sqlite.Error
	return errors.As(err, &serr) && serr.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}

// CurrentSubEpoch returns the subepoch counter for attrSetHash, or a default of 0.
func (d *domain) CurrentSubEpoch(ctx context.Context, attrSetHash []byte) (uint64, error) {
	if err := validateAttrSetHash("CurrentSubEpoch", attrSetHash); err != nil {
		return 0, err
	}
	var n int64
	err := d.store.db.QueryRowContext(ctx,
		`SELECT subepoch_num FROM key_series
		  WHERE domain_id = ? AND attr_set_h = ?`,
		d.rowID, attrSetHash,
	).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("disk keystorage: read subepoch: %w", err)
	}
	if n < 0 {
		return 0, fmt.Errorf("disk keystorage: negative subepoch_num %d", n)
	}
	return uint64(n), nil
}

// AdvanceSubEpoch atomically increments the subepoch counter for
// attrSetHash, returning the new counter.
func (d *domain) AdvanceSubEpoch(ctx context.Context, attrSetHash []byte) (uint64, error) {
	if err := validateAttrSetHash("AdvanceSubEpoch", attrSetHash); err != nil {
		return 0, err
	}
	now := d.store.now().UTC().Format(timestampFormat)
	var n int64
	err := d.store.db.QueryRowContext(ctx,
		`INSERT INTO key_series (domain_id, attr_set_h, subepoch_num, t_advance)
		 VALUES (?, ?, 1, ?)
		 ON CONFLICT (domain_id, attr_set_h) DO UPDATE
		   SET subepoch_num = subepoch_num + 1,
		       t_advance    = excluded.t_advance
		 RETURNING subepoch_num`,
		d.rowID, attrSetHash, now,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("disk keystorage: advance subepoch: %w", err)
	}
	if n < 1 {
		return 0, fmt.Errorf("disk keystorage: invalid subepoch_num %d", n)
	}
	return uint64(n), nil
}
