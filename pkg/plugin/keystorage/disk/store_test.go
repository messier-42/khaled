package disk_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/plugin/keystorage/disk"
)

func newStore(t *testing.T) (*disk.Store, string) {
	t.Helper()
	dir := t.TempDir()
	store, err := disk.New(t.Context(), dir)
	if err != nil {
		t.Fatalf("disk.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, dir
}

// TestNewWithClock_InjectsTimestamps drives the Store with a
// controllable clock and verifies every timestamp the Store writes
// (initial t_create, post-rotation t_create, subepoch t_advance)
// comes from the injected source. Guards against a regression where
// a code path reaches for wall-clock time directly.
func TestNewWithClock_InjectsTimestamps(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	fixed := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	now := fixed
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
	}

	store, err := disk.NewWithClock(t.Context(), dir, clock)
	if err != nil {
		t.Fatalf("NewWithClock: %v", err)
	}
	defer store.Close() // best effort

	d, _ := store.DomainByName(ctx, "default")

	// Initial root key's CreationTime equals the injected clock.
	cur, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	if !cur.CreationTime().Equal(fixed) {
		t.Fatalf("initial t_create = %v, want %v", cur.CreationTime(), fixed)
	}

	// Advance the clock and rotate; the new key's t_create follows.
	advance(time.Hour)
	newKey, err := d.RotateRootKey(ctx, cur)
	if err != nil {
		t.Fatalf("RotateRootKey: %v", err)
	}
	wantRotate := fixed.Add(time.Hour)
	if !newKey.CreationTime().Equal(wantRotate) {
		t.Fatalf("post-rotate t_create = %v, want %v", newKey.CreationTime(), wantRotate)
	}

	// The retired key picks up RetirementTime from the same
	// injected instant.
	retired, err := d.RootKeyByID(ctx, cur.ID())
	if err != nil {
		t.Fatalf("RootKeyByID retired: %v", err)
	}
	if !retired.RetirementTime().Equal(wantRotate) {
		t.Fatalf("retired t_retire = %v, want %v", retired.RetirementTime(), wantRotate)
	}

	// Subepoch advance also uses the injected clock (no direct
	// field exposure, but we exercise the code path to ensure it
	// does not reach for time.Now).
	advance(time.Minute)
	hash := make([]byte, 32)
	if _, err := d.AdvanceSubEpoch(ctx, hash); err != nil {
		t.Fatalf("AdvanceSubEpoch: %v", err)
	}
}

func TestNew_BootstrapsDefaultDomainAndInitialKey(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)

	d, err := store.DomainByName(ctx, "default")
	if err != nil {
		t.Fatalf("Domain(default): %v", err)
	}
	if d.Name() != "default" {
		t.Fatalf("Name = %q, want %q", d.Name(), "default")
	}
	if d.ID() == "" {
		t.Fatal("DomainID is empty")
	}

	cur, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	if cur.SeqNum() != 0 {
		t.Fatalf("initial SeqNum = %d, want 0", cur.SeqNum())
	}
	if cur.ID() != "0" {
		t.Fatalf("initial ID = %q, want %q", cur.ID(), "0")
	}
	if !cur.RetirementTime().IsZero() {
		t.Fatalf("initial key has non-zero RetirementTime: %v", cur.RetirementTime())
	}
	if cur.CreationTime().IsZero() {
		t.Fatal("initial key has zero CreationTime")
	}
}

func TestNew_ReopenPreservesState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	store, err := disk.New(t.Context(), dir)
	if err != nil {
		t.Fatalf("disk.New: %v", err)
	}
	d, err := store.DomainByName(ctx, "default")
	if err != nil {
		t.Fatalf("Domain: %v", err)
	}
	cur1, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	store2, err := disk.New(t.Context(), dir)
	if err != nil {
		t.Fatalf("disk.New (reopen): %v", err)
	}
	defer store2.Close() // best effort
	d2, err := store2.DomainByName(ctx, "default")
	if err != nil {
		t.Fatalf("Domain (reopen): %v", err)
	}
	cur2, err := d2.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey (reopen): %v", err)
	}
	if cur1.ID() != cur2.ID() || cur1.SeqNum() != cur2.SeqNum() {
		t.Fatalf("key drifted across reopen: %v vs %v", cur1.ID(), cur2.ID())
	}
}

// TestNew_RejectsConcurrentOpen verifies that two Stores cannot hold
// the same directory open simultaneously. Note this is a same-process
// test: it relies on the Linux flock(2) semantic that distinct open-
// file-descriptions (separate open() calls) of the same file DO
// conflict, even within one process. POSIX fcntl locks, by contrast,
// are per-process and would let the second New succeed — so this
// test is effectively Linux- (and macOS-)specific. On BSDs where
// flock() collapses to fcntl (e.g. historical kFreeBSD) it would
// false-pass.
//
// The cross-process case (the deployment scenario operators actually
// care about) is not covered here; it would require spawning a second
// khaled binary.
func TestNew_RejectsConcurrentOpen(t *testing.T) {
	dir := t.TempDir()
	first, err := disk.New(t.Context(), dir)
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	defer first.Close() // best effort

	if _, err := disk.New(t.Context(), dir); err == nil {
		t.Fatal("second New succeeded; expected lock failure")
	}
}

// TestNew_DirectoryWithSpecialChars exercises the DSN builder on
// directory paths that would break a naive "file:"+path
// concatenation: space, '?', '#', '%', '&'. The driver parses DSNs
// as URIs when they start with "file:", so unescaped '?' / '#' would
// split the path into a bogus URI-query / URI-fragment. When that
// happens the driver silently opens the DB at a truncated path
// (everything before the first '?' or '#'), the rotation still
// commits (because the driver happily writes to the wrong file),
// and a reopen reads back the same wrong file — so a content-level
// check alone misses the bug. The test instead asserts that the DB
// file actually ends up at the expected dbPath inside the caller's
// directory.
func TestNew_DirectoryWithSpecialChars(t *testing.T) {
	for _, sub := range []string{
		"with space",
		"with?question",
		"with#hash",
		"with%percent",
		"with&amp",
	} {
		t.Run(sub, func(t *testing.T) {
			ctx := context.Background()
			base := t.TempDir()
			dir := base + "/" + sub
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatalf("mkdir %q: %v", dir, err)
			}
			expectedDB := dir + "/khaled-key-store.db"

			s, err := disk.New(t.Context(), dir)
			if err != nil {
				t.Fatalf("New(%q): %v", dir, err)
			}
			defer s.Close() // best effort
			d, err := s.DomainByName(ctx, "default")
			if err != nil {
				t.Fatalf("Domain: %v", err)
			}
			if _, err := d.CurrentRootKey(ctx); err != nil {
				t.Fatalf("CurrentRootKey: %v", err)
			}

			// The DB file must live at the expected path — not at a
			// truncated path produced by URI-misparsing of '?' / '#'.
			// On the pre-fix code, the SQLite driver would write to
			// e.g. "with" (prefix before '?'), leaving the expected
			// file at size 0 (only the flock open created it).
			fi, err := os.Stat(expectedDB)
			if err != nil {
				t.Fatalf("stat expected DB %q: %v", expectedDB, err)
			}
			if fi.Size() == 0 {
				t.Fatalf("expected DB %q is empty — driver likely wrote to a different path due to DSN misparsing", expectedDB)
			}
		})
	}
}

func TestDomain_NoSuchDomain(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	_, err := store.DomainByName(ctx, "does-not-exist")
	if !errors.Is(err, keystorage.ErrNoSuchDomain) {
		t.Fatalf("err = %v, want wraps ErrNoSuchDomain", err)
	}
}

func TestRootKeyByID_NotFound(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")
	_, err := d.RootKeyByID(ctx, "999999")
	if !errors.Is(err, keystorage.ErrNoSuchRootKey) {
		t.Fatalf("err = %v, want wraps ErrNoSuchRootKey", err)
	}
	_, err = d.RootKeyByID(ctx, "not-a-number")
	if !errors.Is(err, keystorage.ErrNoSuchRootKey) {
		t.Fatalf("malformed id: err = %v, want wraps ErrNoSuchRootKey", err)
	}
}

func TestRootKeyBySeqNum_HappyPath(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	// Rotate so we have seqnums 0 (retired) and 1 (current).
	cur, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	if _, err := d.RotateRootKey(ctx, cur); err != nil {
		t.Fatalf("RotateRootKey: %v", err)
	}

	k0, err := d.RootKeyBySeqNum(ctx, 0)
	if err != nil {
		t.Fatalf("RootKeyBySeqNum(0): %v", err)
	}
	if k0.SeqNum() != 0 {
		t.Errorf("seqnum = %d, want 0", k0.SeqNum())
	}
	k1, err := d.RootKeyBySeqNum(ctx, 1)
	if err != nil {
		t.Fatalf("RootKeyBySeqNum(1): %v", err)
	}
	if k1.SeqNum() != 1 {
		t.Errorf("seqnum = %d, want 1", k1.SeqNum())
	}
}

func TestRootKeyBySeqNum_NotFound(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")
	_, err := d.RootKeyBySeqNum(ctx, 999999)
	if !errors.Is(err, keystorage.ErrNoSuchRootKey) {
		t.Fatalf("err = %v, want wraps ErrNoSuchRootKey", err)
	}
}

func TestRotateRootKey_HappyPath(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	cur, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	newKey, err := d.RotateRootKey(ctx, cur)
	if err != nil {
		t.Fatalf("RotateRootKey: %v", err)
	}
	if newKey.SeqNum() != cur.SeqNum()+1 {
		t.Fatalf("new SeqNum = %d, want %d", newKey.SeqNum(), cur.SeqNum()+1)
	}
	if !newKey.RetirementTime().IsZero() {
		t.Fatal("new key already has retirement time")
	}

	// Old key should now be retired.
	old, err := d.RootKeyByID(ctx, cur.ID())
	if err != nil {
		t.Fatalf("RootKeyByID(old): %v", err)
	}
	if old.RetirementTime().IsZero() {
		t.Fatal("old key not marked retired")
	}

	// Current must now be the new key.
	again, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey (post-rotate): %v", err)
	}
	if again.ID() != newKey.ID() {
		t.Fatalf("post-rotate current ID = %q, want %q", again.ID(), newKey.ID())
	}
}

func TestRotateRootKey_StaleReturnsSentinel(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	cur, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	if _, err := d.RotateRootKey(ctx, cur); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	// Second rotation with the same (now retired) handle must fail.
	_, err = d.RotateRootKey(ctx, cur)
	if !errors.Is(err, keystorage.ErrStaleRootKey) {
		t.Fatalf("err = %v, want ErrStaleRootKey", err)
	}
}

func TestRotateRootKey_ConcurrentOnlyOneWins(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	cur, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}

	const racers = 8
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		wins   int
		stales int
		others []error
	)
	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			_, err := d.RotateRootKey(ctx, cur)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, keystorage.ErrStaleRootKey):
				stales++
			default:
				others = append(others, err)
			}
		}()
	}
	wg.Wait()

	if len(others) != 0 {
		t.Fatalf("unexpected errors: %v", others)
	}
	if wins != 1 {
		t.Fatalf("wins = %d, want 1", wins)
	}
	if stales != racers-1 {
		t.Fatalf("stales = %d, want %d", stales, racers-1)
	}
}

// TestDeriveKey_RacesWithRotateRootKey stresses the boundary
// between RotateRootKey and DeriveKey on a retired handle. Under
// -race, the test exposes any unsynchronised access to the backing
// rowKey secret, the partial unique index, or the per-domain
// state that RotateRootKey mutates. Correctness contract: DeriveKey
// against a handle that RotateRootKey is about to retire (or has
// just retired) must either:
//
//   - succeed and return bytes matching a fresh DeriveKey against
//     the same handle (retirement does not invalidate the in-memory
//     secret; the handle's derivation is deterministic in its
//     seqnum); or
//   - return a deterministic error.
//
// In particular, it must never produce bytes that differ from the
// handle's HKDF(secret, info) output, and it must never data-race
// (which -race would flag).
func TestDeriveKey_RacesWithRotateRootKey(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	cur, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	info := &keystorage.DerivationInfo{Context: []byte("race-ctx"), Length: 32}

	// Expected bytes for the pre-rotation handle. Compute them
	// sequentially (no rotation in flight) so we have a known good
	// value to compare concurrent derivations against.
	expected, err := d.DeriveKey(ctx, cur, info)
	if err != nil {
		t.Fatalf("sequential DeriveKey: %v", err)
	}

	const racers = 8
	var wg sync.WaitGroup
	wg.Add(racers + 1)

	errs := make(chan error, racers+1)
	mismatches := make(chan string, racers)

	// Rotator goroutine: retires `cur` exactly once.
	go func() {
		defer wg.Done()
		_, err := d.RotateRootKey(ctx, cur)
		if err != nil && !errors.Is(err, keystorage.ErrStaleRootKey) {
			errs <- err
		}
	}()

	// Derivers racing against the rotation. Each must either
	// succeed and match `expected`, or return an error the contract
	// permits.
	for range racers {
		go func() {
			defer wg.Done()
			out, err := d.DeriveKey(ctx, cur, info)
			if err != nil {
				// An error here would be a contract violation: the
				// in-memory handle carries the secret, so derivation
				// should not depend on the row's retirement state.
				errs <- err
				return
			}
			if !bytes.Equal(out.KeyBytes, expected.KeyBytes) {
				mismatches <- "derived bytes differ from pre-rotation baseline"
			}
		}()
	}

	wg.Wait()
	close(errs)
	close(mismatches)

	for err := range errs {
		t.Errorf("unexpected error under race: %v", err)
	}
	for m := range mismatches {
		t.Error(m)
	}

	// After the dust settles, the handle is retired but derivation
	// must still produce the same bytes.
	final, err := d.DeriveKey(ctx, cur, info)
	if err != nil {
		t.Fatalf("post-race DeriveKey on retired handle: %v", err)
	}
	if !bytes.Equal(final.KeyBytes, expected.KeyBytes) {
		t.Fatal("post-race derivation on retired handle yielded different bytes")
	}
}

func TestListRootKeys_DescendingOrder(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	for i := range 3 {
		cur, err := d.CurrentRootKey(ctx)
		if err != nil {
			t.Fatalf("CurrentRootKey iter %d: %v", i, err)
		}
		if _, err := d.RotateRootKey(ctx, cur); err != nil {
			t.Fatalf("Rotate iter %d: %v", i, err)
		}
	}

	var seen []uint64
	for k, err := range d.ListRootKeys(ctx) {
		if err != nil {
			t.Fatalf("ListRootKeys yield error: %v", err)
		}
		seen = append(seen, k.SeqNum())
	}
	want := []uint64{3, 2, 1, 0}
	if len(seen) != len(want) {
		t.Fatalf("seen = %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("seen[%d] = %d, want %d (full: %v)", i, seen[i], want[i], seen)
		}
	}
}

func TestListRootKeys_EarlyStop(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	for range 3 {
		cur, _ := d.CurrentRootKey(ctx)
		if _, err := d.RotateRootKey(ctx, cur); err != nil {
			t.Fatalf("Rotate: %v", err)
		}
	}
	count := 0
	for _, err := range d.ListRootKeys(ctx) {
		if err != nil {
			t.Fatalf("ListRootKeys: %v", err)
		}
		count++
		if count == 2 {
			break
		}
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
}

// TestListRootKeys_CtxCancelledUpFront verifies the iterator
// surfaces context cancellation promptly via the first yield call.
// QueryContext aborts when the caller context is already cancelled,
// so we observe a single yield(nil, error) and then the range loop
// terminates.
func TestListRootKeys_CtxCancelledUpFront(t *testing.T) {
	store, _ := newStore(t)
	d, _ := store.DomainByName(context.Background(), "default")

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before we even start iterating

	var sawErr bool
	var yields int
	for _, err := range d.ListRootKeys(ctx) {
		yields++
		if err != nil {
			sawErr = true
		}
		if yields > 1 {
			t.Fatalf("expected at most 1 yield after cancelled ctx, got %d", yields)
		}
	}
	if !sawErr {
		t.Fatal("expected ListRootKeys to yield an error for a pre-cancelled context")
	}
}

// TestListRootKeys_CtxCancelledMidIteration cancels ctx after the
// first element is yielded, then verifies the caller's range-loop
// exit (early break) terminates the iterator cleanly — the
// deferred rows.Close() in ListRootKeys must not leave the SQLite
// connection held.
func TestListRootKeys_CtxCancelledMidIteration(t *testing.T) {
	setupCtx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(setupCtx, "default")
	for range 4 {
		cur, _ := d.CurrentRootKey(setupCtx)
		if _, err := d.RotateRootKey(setupCtx, cur); err != nil {
			t.Fatalf("Rotate: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	count := 0
	for _, err := range d.ListRootKeys(ctx) {
		if err != nil {
			t.Fatalf("ListRootKeys: %v", err)
		}
		count++
		if count == 2 {
			cancel()
			break
		}
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}

	// The single-connection pool must have been released. A fresh
	// operation should succeed: if rows.Close was leaked this
	// query would block waiting for the connection.
	if _, err := d.CurrentRootKey(setupCtx); err != nil {
		t.Fatalf("follow-up CurrentRootKey: %v (iterator may have leaked the connection)", err)
	}
}

// TestListDomains_CtxCancelledUpFront is the ListDomains analogue
// of the ListRootKeys pre-cancelled test.
func TestListDomains_CtxCancelledUpFront(t *testing.T) {
	store, _ := newStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var sawErr bool
	for _, err := range store.ListDomains(ctx) {
		if err != nil {
			sawErr = true
			break
		}
	}
	if !sawErr {
		t.Fatal("expected ListDomains to yield an error for a pre-cancelled context")
	}
}

func TestListDomains(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)

	var names []string
	for d, err := range store.ListDomains(ctx) {
		if err != nil {
			t.Fatalf("ListDomains: %v", err)
		}
		names = append(names, d.Name())
	}
	if len(names) != 1 || names[0] != "default" {
		t.Fatalf("names = %v, want [default]", names)
	}
}

func TestDeriveKey_Determinism(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")
	root, _ := d.CurrentRootKey(ctx)

	info := &keystorage.DerivationInfo{Context: []byte("ctx-1"), Length: 32}
	k1, err := d.DeriveKey(ctx, root, info)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	k2, err := d.DeriveKey(ctx, root, info)
	if err != nil {
		t.Fatalf("DeriveKey (repeat): %v", err)
	}
	if !bytes.Equal(k1.KeyBytes, k2.KeyBytes) {
		t.Fatal("derivation not deterministic")
	}
	if len(k1.KeyBytes) != 32 {
		t.Fatalf("len = %d, want 32", len(k1.KeyBytes))
	}
}

func TestDeriveKey_ContextDomainSeparation(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")
	root, _ := d.CurrentRootKey(ctx)

	a, _ := d.DeriveKey(ctx, root, &keystorage.DerivationInfo{Context: []byte("a"), Length: 32})
	b, _ := d.DeriveKey(ctx, root, &keystorage.DerivationInfo{Context: []byte("b"), Length: 32})
	if bytes.Equal(a.KeyBytes, b.KeyBytes) {
		t.Fatal("distinct contexts yielded equal derived keys")
	}
}

func TestDeriveKey_DifferentRootsDifferent(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	r0, _ := d.CurrentRootKey(ctx)
	k0, _ := d.DeriveKey(ctx, r0, &keystorage.DerivationInfo{Context: []byte("ctx"), Length: 32})

	r1, err := d.RotateRootKey(ctx, r0)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	k1, _ := d.DeriveKey(ctx, r1, &keystorage.DerivationInfo{Context: []byte("ctx"), Length: 32})

	if bytes.Equal(k0.KeyBytes, k1.KeyBytes) {
		t.Fatal("different roots derived equal keys")
	}
}

func TestDeriveKey_LengthValidation(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")
	root, _ := d.CurrentRootKey(ctx)

	if _, err := d.DeriveKey(ctx, root, &keystorage.DerivationInfo{Length: 0}); err == nil {
		t.Fatal("Length=0 was accepted")
	}
	if _, err := d.DeriveKey(ctx, root, &keystorage.DerivationInfo{Length: -1}); err == nil {
		t.Fatal("Length=-1 was accepted")
	}
}

func TestDeriveKey_ByIDRoundTrip(t *testing.T) {
	// Using a RootKey looked up by ID (rather than the handle returned
	// by CurrentRootKey) must yield the same derived key.
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")
	r0, _ := d.CurrentRootKey(ctx)
	r0byID, err := d.RootKeyByID(ctx, r0.ID())
	if err != nil {
		t.Fatalf("RootKeyByID: %v", err)
	}
	info := &keystorage.DerivationInfo{Context: []byte("ctx"), Length: 32}
	a, _ := d.DeriveKey(ctx, r0, info)
	b, _ := d.DeriveKey(ctx, r0byID, info)
	if !bytes.Equal(a.KeyBytes, b.KeyBytes) {
		t.Fatal("derivation differs for same root via different handles")
	}
}

func TestNew_RejectsBadDir(t *testing.T) {
	if _, err := disk.New(t.Context(), ""); err == nil {
		t.Fatal("empty dir was accepted")
	}
	// Existing file masquerading as a directory.
	f, err := os.CreateTemp(t.TempDir(), "kstore-bad-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	_ = f.Close()
	if _, err := disk.New(t.Context(), f.Name()); err == nil {
		t.Fatal("file path was accepted as directory")
	}
}

func TestRotate_OldKeyNotInThisDomain(t *testing.T) {
	// Sanity: a hand-rolled RootKey with a wildly-wrong ID must
	// produce ErrStaleRootKey, not a different error.
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	bogus := bogusKey{id: "999"}
	_, err := d.RotateRootKey(ctx, bogus)
	if !errors.Is(err, keystorage.ErrStaleRootKey) {
		t.Fatalf("err = %v, want ErrStaleRootKey", err)
	}
}

// bogusKey is an external RootKey implementation used to verify that
// rotations against a non-current key fail with ErrStaleRootKey.
type bogusKey struct{ id keystorage.KeyID }

func (b bogusKey) ID() keystorage.KeyID      { return b.id }
func (b bogusKey) SeqNum() uint64            { return 999 }
func (b bogusKey) CreationTime() time.Time   { return time.Time{} }
func (b bogusKey) RetirementTime() time.Time { return time.Time{} }

func TestSubEpoch_DefaultsToZero(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	hash := bytes.Repeat([]byte{0xab}, 32)
	got, err := d.CurrentSubEpoch(ctx, hash)
	if err != nil {
		t.Fatalf("CurrentSubEpoch: %v", err)
	}
	if got != 0 {
		t.Fatalf("default subepoch = %d, want 0", got)
	}
}

func TestSubEpoch_AdvanceMonotonic(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	hash := bytes.Repeat([]byte{0xcd}, 32)
	for want := uint64(1); want <= 5; want++ {
		got, err := d.AdvanceSubEpoch(ctx, hash)
		if err != nil {
			t.Fatalf("AdvanceSubEpoch (iter %d): %v", want, err)
		}
		if got != want {
			t.Fatalf("AdvanceSubEpoch returned %d, want %d", got, want)
		}
		cur, err := d.CurrentSubEpoch(ctx, hash)
		if err != nil {
			t.Fatalf("CurrentSubEpoch: %v", err)
		}
		if cur != want {
			t.Fatalf("CurrentSubEpoch = %d, want %d", cur, want)
		}
	}
}

func TestSubEpoch_PerAttrSetIndependent(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	hashA := bytes.Repeat([]byte{0x01}, 32)
	hashB := bytes.Repeat([]byte{0x02}, 32)

	for range 3 {
		if _, err := d.AdvanceSubEpoch(ctx, hashA); err != nil {
			t.Fatalf("Advance A: %v", err)
		}
	}
	if _, err := d.AdvanceSubEpoch(ctx, hashB); err != nil {
		t.Fatalf("Advance B: %v", err)
	}

	a, _ := d.CurrentSubEpoch(ctx, hashA)
	b, _ := d.CurrentSubEpoch(ctx, hashB)
	if a != 3 {
		t.Fatalf("A subepoch = %d, want 3", a)
	}
	if b != 1 {
		t.Fatalf("B subepoch = %d, want 1", b)
	}
}

func TestSubEpoch_ConcurrentAdvance(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")
	hash := bytes.Repeat([]byte{0x11}, 32)

	const racers = 16
	var wg sync.WaitGroup
	wg.Add(racers)
	results := make([]uint64, racers)
	for i := range racers {
		go func(i int) {
			defer wg.Done()
			n, err := d.AdvanceSubEpoch(ctx, hash)
			if err != nil {
				t.Errorf("AdvanceSubEpoch: %v", err)
				return
			}
			results[i] = n
		}(i)
	}
	wg.Wait()

	// Every result must be in [1, racers] and all results must be
	// distinct (UPSERT serialises increments).
	seen := make(map[uint64]bool, racers)
	for _, n := range results {
		if n < 1 || n > racers {
			t.Fatalf("result out of range: %d", n)
		}
		if seen[n] {
			t.Fatalf("duplicate subepoch %d in %v", n, results)
		}
		seen[n] = true
	}

	cur, _ := d.CurrentSubEpoch(ctx, hash)
	if cur != racers {
		t.Fatalf("final CurrentSubEpoch = %d, want %d", cur, racers)
	}
}

func TestSubEpoch_ClearedOnRotate(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	hash := bytes.Repeat([]byte{0x42}, 32)
	for range 4 {
		if _, err := d.AdvanceSubEpoch(ctx, hash); err != nil {
			t.Fatalf("Advance: %v", err)
		}
	}
	if cur, _ := d.CurrentSubEpoch(ctx, hash); cur != 4 {
		t.Fatalf("pre-rotate subepoch = %d, want 4", cur)
	}

	cur, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	if _, err := d.RotateRootKey(ctx, cur); err != nil {
		t.Fatalf("RotateRootKey: %v", err)
	}

	if got, err := d.CurrentSubEpoch(ctx, hash); err != nil {
		t.Fatalf("CurrentSubEpoch (post-rotate): %v", err)
	} else if got != 0 {
		t.Fatalf("post-rotate subepoch = %d, want 0", got)
	}
}

func TestSubEpoch_StaleRotateLeavesSubepochsIntact(t *testing.T) {
	// If RotateRootKey fails (CAS miss), the subepoch table must
	// not be cleared — the rollback should be transactional.
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	hash := bytes.Repeat([]byte{0x55}, 32)
	if _, err := d.AdvanceSubEpoch(ctx, hash); err != nil {
		t.Fatalf("Advance: %v", err)
	}

	// Rotate once successfully so the original handle is stale.
	cur, _ := d.CurrentRootKey(ctx)
	if _, err := d.RotateRootKey(ctx, cur); err != nil {
		t.Fatalf("first rotate: %v", err)
	}
	// The first rotate cleared the table. Re-advance under the new root.
	if _, err := d.AdvanceSubEpoch(ctx, hash); err != nil {
		t.Fatalf("Advance after rotate: %v", err)
	}

	// Now attempt a stale rotate. It must fail and leave the new
	// subepoch intact.
	_, err := d.RotateRootKey(ctx, cur)
	if !errors.Is(err, keystorage.ErrStaleRootKey) {
		t.Fatalf("stale rotate err = %v, want ErrStaleRootKey", err)
	}
	if got, _ := d.CurrentSubEpoch(ctx, hash); got != 1 {
		t.Fatalf("post-stale-rotate subepoch = %d, want 1", got)
	}
}

func TestSubEpoch_EmptyHashRejected(t *testing.T) {
	ctx := context.Background()
	store, _ := newStore(t)
	d, _ := store.DomainByName(ctx, "default")

	if _, err := d.CurrentSubEpoch(ctx, nil); err == nil {
		t.Fatal("nil hash accepted by CurrentSubEpoch")
	}
	if _, err := d.AdvanceSubEpoch(ctx, nil); err == nil {
		t.Fatal("nil hash accepted by AdvanceSubEpoch")
	}
}
