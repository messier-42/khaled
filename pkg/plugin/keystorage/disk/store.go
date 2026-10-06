// Package disk implements a SQLite-backed Key Storage plugin.
//
// # Single-process invariant
//
// The plugin acquires an exclusive OS-level advisory lock (flock)
// on the SQLite database file at construction and holds it for the
// lifetime of the KeyStore. Only one process at a time may operate
// against a given directory. A concurrent open fails at startup.
// Multi-process operation is not supported.
package disk

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"iter"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"

	"github.com/messier-42/khaled/pkg/plugin/keystorage"
)

const (
	// dbFilename is the name of the SQLite database file under the
	// configured directory.
	dbFilename = "khaled-key-store.db"

	// schemaVersion is the current schema version.
	// Bumped by future migrations.
	schemaVersion = "2"

	// rootKeyLen is the length in bytes of newly-generated Root
	// Keys.
	rootKeyLen = 32

	// defaultDomainName is the name of the domain that is created on
	// initial bootstrap of an empty store.
	defaultDomainName = "default"

	// timestampFormat is the RFC 3339 layout used when writing
	// t_create and t_retire columns. UTC, nanosecond precision,
	// trailing 'Z'. Reads accept any RFC 3339 / RFC 3339 Nano value
	// via time.Parse with time.RFC3339Nano (which accepts variable
	// fractional precision).
	timestampFormat = "2006-01-02T15:04:05.000000000Z"
)

// Store provides a disk-backed KeyStore implementation.
type Store struct {
	dir    string
	db     *sql.DB
	lockFD int

	// now is the time source used for timestamps written to the database.
	// This is usually time.Now but can be overridden in tests.
	now func() time.Time

	mu      sync.Mutex
	domains map[string]*domain
}

var _ keystorage.KeyStore = &Store{}

// New opens an existing (or if necessary, creates a new) disk-backed
// Key Store rooted at `dir`. The directory must exist and be writable.
// The plugin acquires an exclusive OS lock on the database file for the
// lifetime of the returned store.
//
// Upon initialization of a fresh store, a "default" domain is created automatically
// with an initial Root Key with sequence number 0.
func New(ctx context.Context, dir string) (*Store, error) {
	return NewWithClock(ctx, dir, nil)
}

// NewWithClock is New with an injectable clock, used for testing purposes.
func NewWithClock(ctx context.Context, dir string, now func() time.Time) (store *Store, retErr error) {
	if now == nil {
		now = time.Now
	}

	if dir == "" {
		return nil, errors.New("disk key storage: empty directory path")
	}

	if info, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("disk key storage: stat %q: %w", dir, err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("disk key storage: %q is not a directory", dir)
	}

	dbPath := filepath.Join(dir, dbFilename)

	lockFD, err := acquireExclusiveLock(dbPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			_ = unix.Close(lockFD)
		}
	}()

	dsn := buildSQLiteDSN(dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("disk key storage: open db: %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = db.Close()
		}
	}()

	// Single in-process writer is fine for SQLite's serialised writer
	// model; cap connections to keep behaviour deterministic.
	db.SetMaxOpenConns(1)

	if err := bootstrap(ctx, db, now); err != nil {
		return nil, err
	}

	return &Store{
		dir:     dir,
		db:      db,
		lockFD:  lockFD,
		now:     now,
		domains: make(map[string]*domain),
	}, nil
}

// buildSQLiteDSN builds the SQLite3 DSN for dbPath.
//
// The driver parses the DSN as a URI, so it needs to be correctly encoded
// in case the path contains special characters.
//
// We encode database settings in the DSN to avoid the need to set them via
// queries after opening the database. This avoids any momentary state
// where e.g. WAL mode is not enabled.
func buildSQLiteDSN(dbPath string) string {
	u := url.URL{
		Scheme: "file",
		Opaque: (&url.URL{Path: dbPath}).EscapedPath(),
		RawQuery: "_pragma=journal_mode(WAL)" +
			"&_pragma=foreign_keys(ON)" +
			"&_pragma=synchronous(FULL)" +
			"&_pragma=busy_timeout(5000)",
	}
	return u.String()
}

// acquireExclusiveLock takes an exclusive non-blocking flock on the
// database file path, creating the file if necessary. The file
// descriptor is held for the lifetime of the Store.
func acquireExclusiveLock(dbPath string) (int, error) {
	fd, err := unix.Open(dbPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return -1, fmt.Errorf("disk key storage: open db file for locking: %w", err)
	}

	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return -1, fmt.Errorf("disk key storage: another process holds an exclusive lock on %q", dbPath)
		}
		return -1, fmt.Errorf("disk key storage: flock %q: %w", dbPath, err)
	}

	return fd, nil
}

// bootstrap creates the schema and initial data for a fresh database,
// or validates the schema of an existing database being opened. now
// supplies the t_create timestamp for the initial Root Key.
func bootstrap(ctx context.Context, db *sql.DB, now func() time.Time) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("disk key storage: begin bootstrap tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var hasMeta int
	err = tx.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_master WHERE type='table' AND name='khaled_meta'`,
	).Scan(&hasMeta)
	if err != nil {
		return fmt.Errorf("disk key storage: probe schema: %w", err)
	}

	if hasMeta == 0 {
		if err := createSchema(ctx, tx); err != nil {
			return err
		}
		if err := createInitialDomain(ctx, tx, defaultDomainName, now().UTC()); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("disk key storage: commit bootstrap: %w", err)
		}
		return nil
	}

	var got string
	err = tx.QueryRowContext(ctx,
		`SELECT value FROM khaled_meta WHERE key='schema_version'`,
	).Scan(&got)
	if err != nil {
		return fmt.Errorf("disk key storage: read schema_version: %w", err)
	}
	if got == "1" {
		if _, err := tx.ExecContext(ctx, federationSchemaDDL); err != nil {
			return fmt.Errorf("disk key storage: migrate federation schema: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE khaled_meta SET value=? WHERE key='schema_version'`, schemaVersion); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("disk key storage: commit migration: %w", err)
		}
		return nil
	}
	if got != schemaVersion {
		return fmt.Errorf("disk key storage: unsupported schema_version %q (expected %q)", got, schemaVersion)
	}
	return nil
}

const schemaDDL = `
-- Basic key/value metadata about this database.
CREATE TABLE khaled_meta (
  key   TEXT NOT NULL PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE domain (
  id   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL
);
CREATE UNIQUE INDEX u_domain__name ON domain (name);

CREATE TABLE root_key (
  id        INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  domain_id INTEGER NOT NULL REFERENCES domain (id),
  t_create  TIMESTAMP NOT NULL,
  t_retire  TIMESTAMP,
  seq_num   INTEGER NOT NULL,
  secret    BLOB NOT NULL,
  CHECK (seq_num >= 0),
  CHECK (t_retire IS NULL OR t_retire >= t_create)
);
CREATE UNIQUE INDEX u_root_key__seq_num ON root_key (domain_id, seq_num);
CREATE UNIQUE INDEX u_root_key__current ON root_key (domain_id) WHERE t_retire IS NULL;

CREATE TABLE key_series (
  domain_id    INTEGER NOT NULL REFERENCES domain (id),
  attr_set_h   BLOB    NOT NULL,
  subepoch_num INTEGER NOT NULL,
  t_advance    TIMESTAMP NOT NULL,
  PRIMARY KEY (domain_id, attr_set_h),
  CHECK (subepoch_num >= 1)
);
`

func createSchema(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, schemaDDL+federationSchemaDDL); err != nil {
		return fmt.Errorf("disk key storage: create schema: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO khaled_meta (key, value) VALUES ('schema_version', ?)`, schemaVersion,
	); err != nil {
		return fmt.Errorf("disk key storage: write schema_version: %w", err)
	}
	return nil
}

// createInitialDomain inserts a domain row and a single seq_num=0
// root key under it.
func createInitialDomain(ctx context.Context, tx *sql.Tx, name string, now time.Time) error {
	res, err := tx.ExecContext(ctx, `INSERT INTO domain (name) VALUES (?)`, name)
	if err != nil {
		return fmt.Errorf("disk key storage: create domain %q: %w", name, err)
	}
	domainID, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("disk key storage: domain rowid: %w", err)
	}

	secret := make([]byte, rootKeyLen)
	if _, err := rand.Read(secret); err != nil {
		clear(secret)
		return fmt.Errorf("disk key storage: generate root secret: %w", err)
	}

	// Best effort key zeroization.
	defer clear(secret)

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO root_key (domain_id, t_create, t_retire, seq_num, secret)
		 VALUES (?, ?, NULL, 0, ?)`,
		domainID, now.UTC().Format(timestampFormat), secret,
	); err != nil {
		return fmt.Errorf("disk key storage: insert initial root key: %w", err)
	}

	return nil
}

// ListDomains yields all domains in ascending id order.
func (s *Store) ListDomains(ctx context.Context) iter.Seq2[keystorage.KeyStoreDomain, error] {
	return func(yield func(keystorage.KeyStoreDomain, error) bool) {
		rows, err := s.db.QueryContext(ctx, `SELECT id, name FROM domain ORDER BY id ASC`)
		if err != nil {
			yield(nil, fmt.Errorf("disk key storage: list domains: %w", err))
			return
		}
		defer func() { _ = rows.Close() }()
		// Release the sole connection before callers perform nested storage work.
		var domains []*domain
		for rows.Next() {
			var id int64
			var name string
			if err = rows.Scan(&id, &name); err != nil {
				break
			}
			domains = append(domains, s.domainFor(id, name))
		}
		if err == nil {
			err = rows.Err()
		}
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			yield(nil, fmt.Errorf("disk key storage: iterate domains: %w", err))
			return
		}
		for _, d := range domains {
			if !yield(d, nil) {
				return
			}
		}
	}
}

// DomainByName returns the named domain.
func (s *Store) DomainByName(ctx context.Context, name string) (keystorage.KeyStoreDomain, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM domain WHERE name = ?`, name,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("disk key storage: domain %q: %w", name, keystorage.ErrNoSuchDomain)
	}
	if err != nil {
		return nil, fmt.Errorf("disk key storage: lookup domain %q: %w", name, err)
	}
	return s.domainFor(id, name), nil
}

// domainFor returns the cached *domain for (id, name), creating one
// on first use. Caching is purely so callers receive the same handle
// for the same backing row; the plugin holds no per-domain state
// beyond identity.
func (s *Store) domainFor(id int64, name string) *domain {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strconv.FormatInt(id, 10)
	if d, ok := s.domains[key]; ok {
		return d
	}
	d := &domain{
		store: s,
		id:    keystorage.DomainID(key),
		rowID: id,
		name:  name,
	}
	s.domains[key] = d
	return d
}

// Close releases the database handle and the OS-level file lock.
func (s *Store) Close() error {
	var errs []error
	if err := s.db.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := unix.Close(s.lockFD); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return fmt.Errorf("disk key storage: close: %w", errors.Join(errs...))
	}
	return nil
}
