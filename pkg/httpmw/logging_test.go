package httpmw_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/messier-42/khaled/pkg/httpmw"
	klog "github.com/messier-42/khaled/pkg/log"
)

// newCapturingLogger builds a logger writing JSON to buf and returns
// a cleanup that restores slog's default.
func newCapturingLogger(t *testing.T, buf *bytes.Buffer, severity slog.Level) func() {
	t.Helper()
	prev := slog.Default()
	h := slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: severity})
	// Wrap via a logger built through pkg/log so the ctxHandler is in
	// place. We cheat here: construct a handler chain equivalent to
	// what pkg/log.New produces.
	logger := slog.New(klog.NewCtxHandler(h))
	slog.SetDefault(logger)
	return func() { slog.SetDefault(prev) }
}

func parseRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

func findRecord(t *testing.T, recs []map[string]any, msg string) map[string]any {
	t.Helper()
	for _, r := range recs {
		if r["msg"] == msg {
			return r
		}
	}
	t.Fatalf("no record with msg=%q in %v", msg, recs)
	return nil
}

func TestReceiveAndCompletionRecords(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/a/b?secret=xyz", nil)
	req.Header.Set("User-Agent", "ua/1.0")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	recs := parseRecords(t, &buf)
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d: %v", len(recs), recs)
	}

	got := findRecord(t, recs, "http request received")
	if got["method"] != "GET" {
		t.Errorf("method = %v", got["method"])
	}
	if got["path"] != "/a/b" {
		t.Errorf("path = %v (query should be stripped)", got["path"])
	}
	if got["proto"] != "HTTP/1.1" {
		t.Errorf("proto = %v", got["proto"])
	}
	if got["userAgent"] != "ua/1.0" {
		t.Errorf("userAgent = %v", got["userAgent"])
	}
	correlationID, _ := got["correlationID"].(string)
	if _, err := uuid.Parse(correlationID); err != nil {
		t.Errorf("correlationID not a UUID: %v", correlationID)
	}

	comp := findRecord(t, recs, "http request completed")
	if comp["status"] != float64(http.StatusOK) {
		t.Errorf("status = %v", comp["status"])
	}
	if comp["bytesWritten"] != float64(5) {
		t.Errorf("bytesWritten = %v", comp["bytesWritten"])
	}
	if dur, ok := comp["durationMs"].(float64); !ok || dur < 0 {
		t.Errorf("durationMs = %v (want positive float)", comp["durationMs"])
	}
	if comp["correlationID"] != correlationID {
		t.Errorf("completion correlationID %q != receive %q", comp["correlationID"], correlationID)
	}
}

func TestValidRequestIDHeaderAttached(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	extID := uuid.NewString()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", extID)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := findRecord(t, parseRecords(t, &buf), "http request received")
	if rec["requestID"] != extID {
		t.Errorf("requestID = %v, want %q", rec["requestID"], extID)
	}
}

func TestMalformedRequestIDHeaderIgnored(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "not-a-uuid")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := findRecord(t, parseRecords(t, &buf), "http request received")
	if _, ok := rec["requestID"]; ok {
		t.Errorf("requestID should be absent for malformed header; got %v", rec["requestID"])
	}
}

func TestUserAgentTruncation(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	longUA := strings.Repeat("a", 1024)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", longUA)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	rec := findRecord(t, parseRecords(t, &buf), "http request received")
	got, _ := rec["userAgent"].(string)
	if len(got) != 256 {
		t.Errorf("userAgent length = %d, want 256", len(got))
	}
}

func TestStatusShimDefaultsTo200(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Neither WriteHeader nor Write -> status defaults to 200.
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	rec := findRecord(t, parseRecords(t, &buf), "http request completed")
	if rec["status"] != float64(200) {
		t.Errorf("status = %v, want 200", rec["status"])
	}
}

func TestStatusShimExplicitStatus(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	rec := findRecord(t, parseRecords(t, &buf), "http request completed")
	if rec["status"] != float64(404) {
		t.Errorf("status = %v, want 404", rec["status"])
	}
	// http.NotFound writes a small body; ensure we counted bytes.
	if bw, _ := rec["bytesWritten"].(float64); bw <= 0 {
		t.Errorf("bytesWritten = %v, want > 0", rec["bytesWritten"])
	}
}

func TestBytesWrittenSumsMultipleWrites(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ab")
		_, _ = io.WriteString(w, "cde")
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	rec := findRecord(t, parseRecords(t, &buf), "http request completed")
	if rec["bytesWritten"] != float64(5) {
		t.Errorf("bytesWritten = %v, want 5", rec["bytesWritten"])
	}
}

func TestPanicRecoveredAndLogged(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	rr := httptest.NewRecorder()
	// Must not re-panic out to the caller.
	handler.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}

	recs := parseRecords(t, &buf)
	// No completion record should appear alongside a panic record.
	for _, r := range recs {
		if r["msg"] == "http request completed" {
			t.Errorf("unexpected completion record alongside panic: %v", r)
		}
	}

	rec := findRecord(t, recs, "http request panicked")
	if rec["panic"] != "boom" {
		t.Errorf("panic = %v, want boom", rec["panic"])
	}
	if stack, _ := rec["stack"].(string); stack == "" {
		t.Error("stack field missing")
	}
	if rec["level"] != "ERROR" {
		t.Errorf("level = %v, want ERROR", rec["level"])
	}
}

func TestPanicAfterHeadersKeepsStatus(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		panic("late")
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	// Because headers were already committed, we must not try to
	// overwrite them with 500.
	if rr.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rr.Code)
	}

	rec := findRecord(t, parseRecords(t, &buf), "http request panicked")
	if rec["panic"] != "late" {
		t.Errorf("panic = %v", rec["panic"])
	}
}

func TestPanicErrAbortHandlerIsRepanicked(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	rr := httptest.NewRecorder()
	defer func() {
		rec := recover()
		recErr, ok := rec.(error)
		if !ok || !errors.Is(recErr, http.ErrAbortHandler) {
			t.Fatalf("expected http.ErrAbortHandler to propagate, got %v", rec)
		}
	}()
	handler.ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	t.Fatal("handler.ServeHTTP returned; expected it to panic")
}

func TestCorrelationIDPropagatesToHandlerLog(t *testing.T) {
	var buf bytes.Buffer
	restore := newCapturingLogger(t, &buf, slog.LevelDebug)
	defer restore()

	handler := httpmw.Logging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.DebugContext(r.Context(), "inner")
	}))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))

	recs := parseRecords(t, &buf)
	recv := findRecord(t, recs, "http request received")
	inner := findRecord(t, recs, "inner")
	if recv["correlationID"] != inner["correlationID"] {
		t.Errorf("handler log correlationID %q != receive %q", inner["correlationID"], recv["correlationID"])
	}
}
