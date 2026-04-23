package inline_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/plugin/policysource"
	"github.com/messier-42/khaled/pkg/plugin/policysource/inline"
)

// stubEngine matches the file source's stub: minimal Engine that
// records its compiled-from text and exposes a Close-was-called flag.
type stubEngine struct {
	content string
	closed  atomic.Bool
}

func (e *stubEngine) DecideEncapsulate(_ context.Context, _ policyengine.EncapsulateRequest) (policyengine.Decision, error) {
	return policyengine.Decision{}, nil
}

func (e *stubEngine) DecideDecapsulate(_ context.Context, _ policyengine.DecapsulateRequest) (policyengine.Decision, error) {
	return policyengine.Decision{}, nil
}

func (e *stubEngine) Close() error {
	e.closed.Store(true)
	return nil
}

func stubCompile(_ context.Context, args policysource.CompileArgs) (policyengine.Engine, error) {
	if strings.HasPrefix(string(args.Source), "BAD") {
		return nil, errors.New("stub compile error")
	}
	return &stubEngine{content: string(args.Source)}, nil
}

func TestInline_New_Success(t *testing.T) {
	src, err := inline.New(t.Context(), []byte("permit-all"), stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	eng, err := src.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	got, ok := eng.(*stubEngine)
	if !ok {
		t.Fatalf("Current returned %T, want *stubEngine", eng)
	}
	if got.content != "permit-all" {
		t.Errorf("compiled content = %q, want %q", got.content, "permit-all")
	}
}

func TestInline_New_CompileFailure(t *testing.T) {
	src, err := inline.New(t.Context(), []byte("BAD policy"), stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	if _, err := src.Current(); err == nil {
		t.Fatalf("Current: expected compile error, got nil")
	}
}

func TestInline_New_RejectsNilCompile(t *testing.T) {
	if _, err := inline.New(t.Context(), []byte("anything"), nil); err == nil {
		t.Fatalf("New: expected error for nil CompileFunc")
	}
}

// TestInline_UpdateChanNeverFires confirms the documented contract:
// the inline source has no internal reload path; reloads happen
// through policyManager rebuilding the source. A consumer that
// blocks on UpdateChan must not see a stray value.
func TestInline_UpdateChanNeverFires(t *testing.T) {
	src, err := inline.New(t.Context(), []byte("policy"), stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = src.Close() })

	select {
	case v, ok := <-src.UpdateChan():
		if !ok {
			t.Fatalf("UpdateChan closed unexpectedly")
		}
		t.Fatalf("UpdateChan unexpectedly fired with %v", v)
	default:
		// expected: no value, channel still open
	}
}

func TestInline_Close_ClosesEngine(t *testing.T) {
	src, err := inline.New(t.Context(), []byte("policy"), stubCompile)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	eng, err := src.Current()
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	stub := eng.(*stubEngine)
	if err := src.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !stub.closed.Load() {
		t.Errorf("Close did not close the held engine")
	}
	// Idempotent.
	if err := src.Close(); err != nil {
		t.Errorf("second Close returned error: %v", err)
	}
}
