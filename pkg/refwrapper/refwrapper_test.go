package refwrapper_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/messier-42/cabe-go/attrset"
	"github.com/messier-42/khaled/pkg/keyschedule"
	"github.com/messier-42/khaled/pkg/plugin/keystorage/disk"
	"github.com/messier-42/khaled/pkg/refwrapper"
	"github.com/messier-42/khaled/pkg/wrapper/macwrapper"
)

func newCodec(t *testing.T) *refwrapper.Codec {
	t.Helper()
	ctx := t.Context()
	store, err := disk.New(ctx, t.TempDir())
	if err != nil {
		t.Fatalf("disk.New: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	d, err := store.DomainByName(ctx, "default")
	if err != nil {
		t.Fatalf("DomainByName: %v", err)
	}
	w, err := macwrapper.New(d)
	if err != nil {
		t.Fatalf("macwrapper.New: %v", err)
	}
	c, err := refwrapper.New(w)
	if err != nil {
		t.Fatalf("refwrapper.New: %v", err)
	}
	return c
}

func sampleInfo() keyschedule.LeaseRefInfo {
	return keyschedule.LeaseRefInfo{
		Time:       time.UnixMicro(time.Now().UnixMicro()).UTC(),
		RootSeqNum: 1,
		SubEpoch:   42,
	}
}

// sampleRepr returns a canonically-serialized attribute-set Repr. LKAT
// unwrap round-trips the inlined Repr through attrset.ReprFromBytes, so
// LKAT tests cannot use arbitrary bytes here — only a valid attrset.
func sampleRepr(t *testing.T) attrset.Repr {
	t.Helper()
	s, err := attrset.New(map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("attrset.New: %v", err)
	}
	return s.Repr()
}

func TestLeaseRef_RoundTrip_NonCaptive(t *testing.T) {
	c := newCodec(t)
	ctx := context.Background()
	info := sampleInfo()
	repr := attrset.Repr("aad-repr")

	wrapped, err := c.WrapLeaseRef(ctx, info, repr, false)
	if err != nil {
		t.Fatalf("WrapLeaseRef: %v", err)
	}
	got, captive, err := c.UnwrapLeaseRef(ctx, wrapped, repr)
	if err != nil {
		t.Fatalf("UnwrapLeaseRef: %v", err)
	}
	if captive {
		t.Fatal("non-captive ref returned captive=true")
	}
	if got != info {
		t.Fatalf("info mismatch: %+v vs %+v", got, info)
	}
}

func TestLeaseRef_RoundTrip_Captive(t *testing.T) {
	c := newCodec(t)
	ctx := context.Background()
	info := sampleInfo()
	repr := attrset.Repr("aad")

	wrapped, err := c.WrapLeaseRef(ctx, info, repr, true)
	if err != nil {
		t.Fatalf("WrapLeaseRef: %v", err)
	}
	_, captive, err := c.UnwrapLeaseRef(ctx, wrapped, repr)
	if err != nil {
		t.Fatalf("UnwrapLeaseRef: %v", err)
	}
	if !captive {
		t.Fatal("captive ref returned captive=false")
	}
}

func TestLeaseRef_WrongAAD(t *testing.T) {
	c := newCodec(t)
	ctx := context.Background()
	wrapped, err := c.WrapLeaseRef(ctx, sampleInfo(), attrset.Repr("a"), false)
	if err != nil {
		t.Fatalf("WrapLeaseRef: %v", err)
	}
	if _, _, err := c.UnwrapLeaseRef(ctx, wrapped, attrset.Repr("b")); !errors.Is(err, refwrapper.ErrInvalidRef) {
		t.Fatalf("want ErrInvalidRef, got %v", err)
	}
}

func TestLKAT_RoundTrip(t *testing.T) {
	c := newCodec(t)
	ctx := context.Background()
	info := sampleInfo()
	repr := sampleRepr(t)

	wrapped, err := c.WrapLKAT(ctx, info, repr)
	if err != nil {
		t.Fatalf("WrapLKAT: %v", err)
	}
	gotInfo, gotRepr, err := c.UnwrapLKAT(ctx, wrapped)
	if err != nil {
		t.Fatalf("UnwrapLKAT: %v", err)
	}
	if gotInfo != info {
		t.Fatalf("info mismatch: %+v vs %+v", gotInfo, info)
	}
	if gotRepr != repr {
		t.Fatalf("repr mismatch: %q vs %q", gotRepr, repr)
	}
}

func TestCrossKind_LKATAsLeaseRef(t *testing.T) {
	// A v=2 LKAT must not decode as a LeaseRef. Even though the
	// underlying MAC is valid, the version byte check rejects it.
	c := newCodec(t)
	ctx := context.Background()
	lkat, err := c.WrapLKAT(ctx, sampleInfo(), attrset.Repr("x"))
	if err != nil {
		t.Fatalf("WrapLKAT: %v", err)
	}
	// AAD for LKAT is nil; pass nil to bypass the MAC-layer rejection
	// and surface the version-byte rejection instead.
	if _, _, err := c.UnwrapLeaseRef(ctx, lkat, ""); !errors.Is(err, refwrapper.ErrInvalidRef) {
		t.Fatalf("want ErrInvalidRef, got %v", err)
	}
}

func TestCrossKind_LeaseRefAsLKAT(t *testing.T) {
	// A v=0 LeaseRef must not decode as an LKAT. It will fail MAC
	// verification (AAD mismatch) before the version byte is even
	// checked; either way the sentinel is ErrInvalidRef.
	c := newCodec(t)
	ctx := context.Background()
	ref, err := c.WrapLeaseRef(ctx, sampleInfo(), attrset.Repr("x"), false)
	if err != nil {
		t.Fatalf("WrapLeaseRef: %v", err)
	}
	if _, _, err := c.UnwrapLKAT(ctx, ref); !errors.Is(err, refwrapper.ErrInvalidRef) {
		t.Fatalf("want ErrInvalidRef, got %v", err)
	}
}

func TestLeaseRef_Tampered(t *testing.T) {
	c := newCodec(t)
	ctx := context.Background()
	wrapped, err := c.WrapLeaseRef(ctx, sampleInfo(), attrset.Repr("a"), false)
	if err != nil {
		t.Fatalf("WrapLeaseRef: %v", err)
	}
	tampered := bytes.Clone(wrapped)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, err := c.UnwrapLeaseRef(ctx, tampered, attrset.Repr("a")); !errors.Is(err, refwrapper.ErrInvalidRef) {
		t.Fatalf("want ErrInvalidRef, got %v", err)
	}
}

// An LKAT whose inlined tail is not a canonically-serialized attrset
// must be rejected with ErrInvalidRef. UnwrapLKAT validates the tail
// via attrset.ReprFromBytes rather than trusting whatever bytes the
// wrapper returns.
func TestLKAT_InvalidInlinedRepr(t *testing.T) {
	c := newCodec(t)
	ctx := context.Background()
	wrapped, err := c.WrapLKAT(ctx, sampleInfo(), attrset.Repr("not-a-valid-attrset"))
	if err != nil {
		t.Fatalf("WrapLKAT: %v", err)
	}
	if _, _, err := c.UnwrapLKAT(ctx, wrapped); !errors.Is(err, refwrapper.ErrInvalidRef) {
		t.Fatalf("want ErrInvalidRef, got %v", err)
	}
}

func TestNew_NilWrapper(t *testing.T) {
	if _, err := refwrapper.New(nil); err == nil {
		t.Fatal("nil wrapper accepted")
	}
}
