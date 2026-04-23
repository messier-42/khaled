package keyschedule_test

import (
	"bytes"
	"context"
	"errors"
	"iter"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/keyschedule"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/plugin/keystorage/disk"
)

func newSchedule(t *testing.T) (*keyschedule.Schedule, keystorage.KeyStoreDomain) {
	t.Helper()
	ctx := context.Background()
	store, err := disk.New(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("disk.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d, err := store.DomainByName(ctx, "default")
	if err != nil {
		t.Fatalf("Domain: %v", err)
	}
	s, err := keyschedule.New(t.Context(), keyschedule.Config{Domain: d})
	if err != nil {
		t.Fatalf("keyschedule.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, d
}

func mustAttrSet(t *testing.T, m map[string]any) attrset.Set {
	t.Helper()
	s, err := attrset.New(m)
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}
	return s
}

func TestNew_Validation(t *testing.T) {
	if _, err := keyschedule.New(t.Context(), keyschedule.Config{}); err == nil {
		t.Fatal("nil Domain accepted")
	}
	if _, err := keyschedule.New(t.Context(), keyschedule.Config{
		Domain:               stubDomain{},
		RootRotationInterval: -1,
	}); err == nil {
		t.Fatal("negative RootRotationInterval accepted")
	}
}

func TestNewLease_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s, _ := newSchedule(t)
	as := mustAttrSet(t, map[string]any{"sensitivity": "secret"})

	li, err := s.NewLease(ctx, as)
	if err != nil {
		t.Fatalf("NewLease: %v", err)
	}
	if len(li.Key) != 32 {
		t.Fatalf("Key len = %d, want 32", len(li.Key))
	}
	if li.RefInfo.Time.IsZero() {
		t.Fatal("RefInfo.Time is zero")
	}

	resolved, err := s.ResolveLease(ctx, li.RefInfo, as)
	if err != nil {
		t.Fatalf("ResolveLease: %v", err)
	}
	if !bytes.Equal(li.Key, resolved.Key) {
		t.Fatal("re-derived Key differs from minted Key")
	}
	if !li.RefInfo.Time.Equal(resolved.RefInfo.Time) {
		t.Fatalf("Time differs: minted %v, resolved %v", li.RefInfo.Time, resolved.RefInfo.Time)
	}
	if li.RefInfo.RootSeqNum != resolved.RefInfo.RootSeqNum {
		t.Fatalf("RootSeqNum differs")
	}
	if li.RefInfo.SubEpoch != resolved.RefInfo.SubEpoch {
		t.Fatalf("SubEpoch differs")
	}
}

func TestResolveLease_WrongAttrSetGivesDifferentKey(t *testing.T) {
	// With Ref authentication factored out, ResolveLease will derive
	// *some* key for any tuple supplied. Verify that using a
	// different attrset yields a different key, so an unauthenticated
	// caller cannot impersonate one by passing the wrong attrset.
	ctx := context.Background()
	s, _ := newSchedule(t)
	asA := mustAttrSet(t, map[string]any{"k": "vA"})
	asB := mustAttrSet(t, map[string]any{"k": "vB"})

	li, err := s.NewLease(ctx, asA)
	if err != nil {
		t.Fatalf("NewLease: %v", err)
	}
	wrong, err := s.ResolveLease(ctx, li.RefInfo, asB)
	if err != nil {
		t.Fatalf("ResolveLease: %v", err)
	}
	if bytes.Equal(li.Key, wrong.Key) {
		t.Fatal("different attrsets produced equal Lease Keys")
	}
}

func TestResolveLease_UnknownRootKey(t *testing.T) {
	// A RefInfo referencing a root seqno that doesn't exist must
	// return an error (the keystorage lookup fails).
	ctx := context.Background()
	s, _ := newSchedule(t)
	as := mustAttrSet(t, map[string]any{"k": "v"})
	bogus := keyschedule.LeaseRefInfo{
		Time:       time.Now().UTC(),
		RootSeqNum: 9999,
		SubEpoch:   0,
	}
	if _, err := s.ResolveLease(ctx, bogus, as); err == nil {
		t.Fatal("unknown root seqno accepted")
	}
}

// TestNewLease_RejectsPre1970Clock verifies that a clock set before
// the Unix epoch produces a clean error rather than silently
// deriving a key under a wrapped-unsigned time argument. The HKDF
// wire encoding is unsigned; silent coercion would round-trip
// within one process but break interop with any spec test vector.
func TestNewLease_RejectsPre1970Clock(t *testing.T) {
	ctx := context.Background()
	d, _ := newScheduleWithClock(t)
	d.mu.Lock()
	d.t = time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC)
	d.mu.Unlock()

	as := mustAttrSet(t, map[string]any{"k": "v"})
	_, err := d.s.NewLease(ctx, as)
	if err == nil {
		t.Fatal("expected NewLease to reject pre-epoch clock")
	}
	if !strings.Contains(err.Error(), "before Unix epoch") {
		t.Fatalf("expected pre-epoch diagnostic, got %v", err)
	}
}

func TestNewLease_DistinctTimesProduceDistinctKeys(t *testing.T) {
	ctx := context.Background()
	d, _ := newScheduleWithClock(t)
	as := mustAttrSet(t, map[string]any{"k": "v"})
	a, err := d.s.NewLease(ctx, as)
	if err != nil {
		t.Fatalf("NewLease A: %v", err)
	}
	d.advance(time.Millisecond)
	b, err := d.s.NewLease(ctx, as)
	if err != nil {
		t.Fatalf("NewLease B: %v", err)
	}
	if bytes.Equal(a.Key, b.Key) {
		t.Fatal("two NewLease calls at distinct times produced equal Lease Keys")
	}
}

func TestSubEpochAdvance_NewLeaseGetsDifferentKey(t *testing.T) {
	ctx := context.Background()
	d, _ := newScheduleWithClock(t)
	as := mustAttrSet(t, map[string]any{"k": "v"})

	pre, err := d.s.NewLease(ctx, as)
	if err != nil {
		t.Fatalf("NewLease pre: %v", err)
	}
	if err := d.s.AdvanceSubEpoch(ctx, as); err != nil {
		t.Fatalf("AdvanceSubEpoch: %v", err)
	}
	d.advance(time.Microsecond)
	post, err := d.s.NewLease(ctx, as)
	if err != nil {
		t.Fatalf("NewLease post: %v", err)
	}
	if bytes.Equal(pre.Key, post.Key) {
		t.Fatal("subepoch advance did not change the derived Lease Key")
	}
	if pre.RefInfo.SubEpoch != 0 {
		t.Fatalf("pre.SubEpoch = %d, want 0", pre.RefInfo.SubEpoch)
	}
	if post.RefInfo.SubEpoch != 1 {
		t.Fatalf("post.SubEpoch = %d, want 1", post.RefInfo.SubEpoch)
	}

	// Re-resolving at the prior subepoch yields the prior key: the
	// SubEpoch is in RefInfo, so the schedule re-derives at whatever
	// subepoch the caller supplies.
	resolved, err := d.s.ResolveLease(ctx, pre.RefInfo, as)
	if err != nil {
		t.Fatalf("ResolveLease pre.RefInfo: %v", err)
	}
	if !bytes.Equal(pre.Key, resolved.Key) {
		t.Fatal("pre.RefInfo resolved to wrong Lease Key")
	}
}

func TestRotateRootKey_ResolvesPreRotationLeases(t *testing.T) {
	// A Lease minted under root R0 must remain resolvable after
	// rotation: R0 stays in keystorage, and ResolveLease loads it
	// via RefInfo.RootSeqNum.
	ctx := context.Background()
	s, _ := newSchedule(t)
	as := mustAttrSet(t, map[string]any{"k": "v"})

	pre, err := s.NewLease(ctx, as)
	if err != nil {
		t.Fatalf("NewLease pre: %v", err)
	}
	if err := s.RotateRootKey(ctx); err != nil {
		t.Fatalf("RotateRootKey: %v", err)
	}
	resolved, err := s.ResolveLease(ctx, pre.RefInfo, as)
	if err != nil {
		t.Fatalf("ResolveLease post-rotation: %v", err)
	}
	if !bytes.Equal(pre.Key, resolved.Key) {
		t.Fatal("post-rotation resolve returned wrong Lease Key")
	}

	post, err := s.NewLease(ctx, as)
	if err != nil {
		t.Fatalf("NewLease post: %v", err)
	}
	if bytes.Equal(pre.Key, post.Key) {
		t.Fatal("post-rotation NewLease yielded pre-rotation Lease Key")
	}
	if post.RefInfo.RootSeqNum <= pre.RefInfo.RootSeqNum {
		t.Fatalf("post RootSeqNum = %d, want > %d", post.RefInfo.RootSeqNum, pre.RefInfo.RootSeqNum)
	}
}

func TestRotateRootKey_ConcurrentSafe(t *testing.T) {
	ctx := context.Background()
	s, _ := newSchedule(t)

	const racers = 8
	var wg sync.WaitGroup
	wg.Add(racers)
	errs := make(chan error, racers)
	for range racers {
		go func() {
			defer wg.Done()
			if err := s.RotateRootKey(ctx); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent RotateRootKey err: %v", err)
	}
}

func TestBackgroundRotation(t *testing.T) {
	ctx := context.Background()
	store, err := disk.New(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("disk.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d, _ := store.DomainByName(ctx, "default")

	startSeq, err := d.CurrentRootKey(ctx)
	if err != nil {
		t.Fatalf("CurrentRootKey: %v", err)
	}
	s, err := keyschedule.New(t.Context(), keyschedule.Config{
		Domain:               d,
		RootRotationInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close() // best effort

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		cur, err := d.CurrentRootKey(ctx)
		if err != nil {
			t.Fatalf("CurrentRootKey: %v", err)
		}
		if cur.SeqNum() > startSeq.SeqNum() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("background rotation did not advance the root key in 2s")
}

// TestBackgroundRotation_ErrorsLogged verifies that a persistently
// broken keystorage surfaces an ERROR-level slog record on each
// rotation tick. Without this, a misconfigured server would silently
// stop rotating and operators would be blind to it.
func TestBackgroundRotation_ErrorsLogged(t *testing.T) {
	// Capture slog.Default; restore on exit. This test cannot run in
	// parallel because it mutates the global default logger, and
	// slog.SetDefault is itself safe under concurrent readers.
	orig := slog.Default()
	t.Cleanup(func() { slog.SetDefault(orig) })

	var mu sync.Mutex
	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&safeWriter{mu: &mu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug})))

	d := &erroringDomain{err: errors.New("boom: keystorage is on fire")}
	s, err := keyschedule.New(t.Context(), keyschedule.Config{
		Domain:               d,
		RootRotationInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close() // best effort

	// Wait for the loop to tick at least twice and log at least one
	// error record.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.calls.Load() >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := d.calls.Load(); got < 2 {
		t.Fatalf("CurrentRootKey calls = %d, want >= 2 (loop did not tick)", got)
	}

	mu.Lock()
	logs := buf.String()
	mu.Unlock()

	if !strings.Contains(logs, `"level":"ERROR"`) {
		t.Fatalf("no ERROR log record; got: %s", logs)
	}
	if !strings.Contains(logs, "background root rotation failed") {
		t.Fatalf("expected rotation-failure message in logs; got: %s", logs)
	}
	if !strings.Contains(logs, "boom: keystorage is on fire") {
		t.Fatalf("expected underlying error text in logs; got: %s", logs)
	}
}

// safeWriter serialises writes to an underlying bytes.Buffer so the
// rotation goroutine and the main test goroutine can read/write the
// capture buffer without tripping -race.
type safeWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (s *safeWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// erroringDomain is a KeyStoreDomain whose CurrentRootKey always
// fails. Counts calls so a test can wait for the loop to tick.
type erroringDomain struct {
	stubDomain

	err   error
	calls atomic.Int64
}

func (d *erroringDomain) CurrentRootKey(context.Context) (keystorage.RootKey, error) {
	d.calls.Add(1)
	return nil, d.err
}

func TestClose_Idempotent(t *testing.T) {
	s, _ := newSchedule(t)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestClose_ConcurrentSafe(t *testing.T) {
	s, _ := newSchedule(t)
	const racers = 8
	var wg sync.WaitGroup
	wg.Add(racers)
	for range racers {
		go func() {
			defer wg.Done()
			_ = s.Close()
		}()
	}
	wg.Wait()
}

// --- helpers ---

type scheduleWithClock struct {
	s  *keyschedule.Schedule
	mu sync.Mutex
	t  time.Time
}

func (sc *scheduleWithClock) advance(d time.Duration) {
	sc.mu.Lock()
	sc.t = sc.t.Add(d)
	sc.mu.Unlock()
}

func (sc *scheduleWithClock) now() time.Time {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.t
}

func newScheduleWithClock(t *testing.T) (*scheduleWithClock, keystorage.KeyStoreDomain) {
	t.Helper()
	ctx := context.Background()
	store, err := disk.New(t.Context(), t.TempDir())
	if err != nil {
		t.Fatalf("disk.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d, _ := store.DomainByName(ctx, "default")
	sc := &scheduleWithClock{t: time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)}
	s, err := keyschedule.New(t.Context(), keyschedule.Config{
		Domain: d,
		Now:    sc.now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	sc.s = s
	return sc, d
}

// stubDomain exists only to satisfy the Config.Domain field for the
// validation-failure tests.
type stubDomain struct{}

func (stubDomain) ID() keystorage.DomainID { return "0" }
func (stubDomain) Name() string            { return "stub" }
func (stubDomain) CurrentRootKey(context.Context) (keystorage.RootKey, error) {
	return nil, errors.New("unused")
}
func (stubDomain) RootKeyByID(context.Context, keystorage.KeyID) (keystorage.RootKey, error) {
	return nil, errors.New("unused")
}
func (stubDomain) RootKeyBySeqNum(context.Context, uint64) (keystorage.RootKey, error) {
	return nil, errors.New("unused")
}
func (stubDomain) ListRootKeys(context.Context) iter.Seq2[keystorage.RootKey, error] {
	return nil
}
func (stubDomain) RotateRootKey(context.Context, keystorage.RootKey) (keystorage.RootKey, error) {
	return nil, errors.New("unused")
}
func (stubDomain) DeriveKey(context.Context, keystorage.RootKey, *keystorage.DerivationInfo) (*keystorage.DerivedKey, error) {
	return nil, errors.New("unused")
}
func (stubDomain) CurrentSubEpoch(context.Context, []byte) (uint64, error) {
	return 0, errors.New("unused")
}
func (stubDomain) AdvanceSubEpoch(context.Context, []byte) (uint64, error) {
	return 0, errors.New("unused")
}
