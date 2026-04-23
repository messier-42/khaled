package log

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func parseJSON(t *testing.T, line string) map[string]any {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimRight(line, "\n")), &rec); err != nil {
		t.Fatalf("parse JSON: %v; raw=%q", err, line)
	}
	return rec
}

func TestWithAttrRoundTrip(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(&buf, Config{Format: FormatJSON, Severity: slog.LevelDebug})

	ctx := WithAttr(context.Background(), slog.String("k", "v"))
	logger.DebugContext(ctx, "hello")

	rec := parseJSON(t, buf.String())
	if rec["k"] != "v" {
		t.Errorf("rec[k] = %v, want %q", rec["k"], "v")
	}
	if rec["msg"] != "hello" {
		t.Errorf("rec[msg] = %v, want %q", rec["msg"], "hello")
	}
}

func TestWithCorrelationIDAndRequestID(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(&buf, Config{Format: FormatJSON, Severity: slog.LevelDebug})

	ctx := context.Background()
	ctx = WithCorrelationID(ctx, "corr-1")
	ctx = WithRequestID(ctx, "req-1")
	logger.DebugContext(ctx, "x")

	rec := parseJSON(t, buf.String())
	if rec["correlationID"] != "corr-1" {
		t.Errorf("correlationID = %v, want corr-1", rec["correlationID"])
	}
	if rec["requestID"] != "req-1" {
		t.Errorf("requestID = %v, want req-1", rec["requestID"])
	}
}

func TestWithAttrParentSurvivesIntoChild(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(&buf, Config{Format: FormatJSON, Severity: slog.LevelDebug})

	parent := WithAttr(context.Background(), slog.String("a", "1"))
	child := WithAttr(parent, slog.String("b", "2"))

	logger.DebugContext(child, "both")
	rec := parseJSON(t, buf.String())
	if rec["a"] != "1" || rec["b"] != "2" {
		t.Errorf("child record missing parent attrs: %v", rec)
	}

	// Parent emitted separately must not see child's attrs.
	buf.Reset()
	logger.DebugContext(parent, "one")
	rec = parseJSON(t, buf.String())
	if _, ok := rec["b"]; ok {
		t.Errorf("parent record leaked child attr: %v", rec)
	}
	if rec["a"] != "1" {
		t.Errorf("parent record missing its own attr: %v", rec)
	}
}

func TestNoBagEmitsCleanRecord(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(&buf, Config{Format: FormatJSON, Severity: slog.LevelDebug})

	logger.DebugContext(context.Background(), "plain")
	rec := parseJSON(t, buf.String())

	// Nothing beyond the stdlib keys (time, level, msg) should appear.
	for k := range rec {
		switch k {
		case "time", "level", "msg":
			continue
		default:
			t.Errorf("unexpected key on plain record: %q", k)
		}
	}
}

func TestCorrelationIDLookup(t *testing.T) {
	t.Parallel()

	if _, ok := CorrelationID(context.Background()); ok {
		t.Fatal("expected no correlationID on empty ctx")
	}
	ctx := WithCorrelationID(context.Background(), "abc")
	got, ok := CorrelationID(ctx)
	if !ok || got != "abc" {
		t.Fatalf("CorrelationID = (%q, %v), want (abc, true)", got, ok)
	}

	// Later WithCorrelationID wins (last-attached semantics).
	ctx = WithCorrelationID(ctx, "xyz")
	got, _ = CorrelationID(ctx)
	if got != "xyz" {
		t.Fatalf("CorrelationID = %q, want xyz", got)
	}
}

func TestWithAttrsPreservesCtxHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	base := New(&buf, Config{Format: FormatJSON, Severity: slog.LevelDebug})

	// logger.With exercises ctxHandler.WithAttrs; the wrapper must be
	// preserved so ctx attrs still land on records.
	logger := base.With("pinned", "yes")
	ctx := WithAttr(context.Background(), slog.String("fromctx", "ok"))
	logger.DebugContext(ctx, "m")

	rec := parseJSON(t, buf.String())
	if rec["pinned"] != "yes" {
		t.Errorf("With-attr dropped: %v", rec)
	}
	if rec["fromctx"] != "ok" {
		t.Errorf("ctx attr dropped after With: %v", rec)
	}
}

func TestWithGroupPreservesCtxHandler(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	base := New(&buf, Config{Format: FormatJSON, Severity: slog.LevelDebug})

	logger := base.WithGroup("g")
	ctx := WithAttr(context.Background(), slog.String("k", "v"))
	logger.DebugContext(ctx, "m")

	rec := parseJSON(t, buf.String())
	// Context attrs land outside the group (they are added by the
	// wrapper which sits above the inner handler's group state). The
	// only behaviour we really care about is "nothing crashes and the
	// record carries the attr somewhere".
	if _, flat := rec["k"]; !flat {
		if g, ok := rec["g"].(map[string]any); !ok || g["k"] != "v" {
			t.Errorf("ctx attr missing after WithGroup: %v", rec)
		}
	}
}
