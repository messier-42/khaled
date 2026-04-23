package httpmw

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/google/uuid"

	klog "github.com/messier-42/khaled/pkg/log"
)

// maxUserAgentBytes caps the length of the User-Agent HTTP header
// for logging purposes, to ensure resilience against clients which
// maliciously specify a User-Agent header of unreasonable length.
const maxUserAgentBytes = 256

// maxStackBytes caps the stack dump emitted when logging panics.
const maxStackBytes = 8 * 1024 // 8 KiB

// Logging returns HTTP middleware that wraps the provided callback `next`
// with per-request correlation and Debug-level request logging.
//
// On each request the middleware:
//
//   - Generates a fresh UUIDv4 "correlationID" and attaches it to the
//     request context via [klog.WithCorrelationID]. Any subsequent
//     slog.*Context call in the handler chain will carry this ID.
//
//   - If the inbound request has a X-Request-ID header that parses as a
//     UUID, attaches it to the context as "requestID"; otherwise ignores
//     the header silently. This ties an optional external request ID to the
//     internal correlation ID.
//
//   - Wraps the ResponseWriter to capture the final status code and
//     the number of body bytes written.
//
//   - Emits one "http request received" record at Debug level before
//     invoking next().
//
//   - On request completion, either emits "http request completed" at
//     Debug level with status, durationMs and bytesWritten; or, on a
//     recovered panic, emits "http request panicked" at Error level with
//     the panic value and a stack dump, and (if the handler had not already
//     started writing a response) sends 500 Internal Server Error.
//     The panic is not re-thrown.
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		correlationID := uuid.NewString()
		ctx := klog.WithCorrelationID(r.Context(), correlationID)

		var requestID string
		if raw := r.Header.Get("X-Request-ID"); raw != "" {
			if parsed, err := uuid.Parse(raw); err == nil {
				requestID = parsed.String()
				ctx = klog.WithRequestID(ctx, requestID)
			}
		}

		r = r.WithContext(ctx)
		sw := &statusWriter{ResponseWriter: w}

		// correlationID and requestID (when set) ride along via the
		// context-aware slog handler, so we do not repeat them in the
		// explicit attr list here.
		slog.DebugContext(ctx, "http request received",
			"method", r.Method,
			"path", r.URL.Path,
			"remoteAddr", r.RemoteAddr,
			"proto", r.Proto,
			"userAgent", truncate(r.UserAgent(), maxUserAgentBytes),
		)

		defer func() {
			dur := time.Since(start)
			if rec := recover(); rec != nil {
				// http.ErrAbortHandler is a sentinel that instructs
				// net/http to abort the current request at the
				// connection level (e.g. close the HTTP/2 stream)
				// without emitting a response. Swallowing it here
				// would corrupt connection state, so re-panic and
				// let net/http handle it. We still log at Warn level
				// (not Error level) so the event is observable.
				if recErr, ok := rec.(error); ok && errors.Is(recErr, http.ErrAbortHandler) {
					slog.WarnContext(ctx, "http request aborted by handler",
						"durationMs", durationMs(dur),
					)
					panic(rec)
				}

				if !sw.wroteHeader {
					http.Error(sw, "Internal server error", http.StatusInternalServerError)
				}

				slog.ErrorContext(ctx, "http request panicked",
					"durationMs", durationMs(dur),
					"panic", fmt.Sprint(rec),
					"stack", truncate(string(debug.Stack()), maxStackBytes),
				)
				return
			}

			slog.DebugContext(ctx, "http request completed",
				"status", sw.status(),
				"durationMs", durationMs(dur),
				"bytesWritten", sw.bytesWritten,
			)
		}()

		next.ServeHTTP(sw, r)
	})
}

// statusWriter wraps an http.ResponseWriter so the middleware can
// observe the final status code and the number of body bytes
// written. If a handler never calls WriteHeader, status() returns 200
// (matching net/http's default).
type statusWriter struct {
	http.ResponseWriter

	statusCode   int
	wroteHeader  bool
	bytesWritten int64
}

func (s *statusWriter) WriteHeader(code int) {
	if s.wroteHeader {
		// Let the wrapped writer produce its usual "superfluous
		// WriteHeader" warning — we don't want to silently discard
		// the second call.
		s.ResponseWriter.WriteHeader(code)
		return
	}
	s.statusCode = code
	s.wroteHeader = true
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(p []byte) (int, error) {
	if !s.wroteHeader {
		s.statusCode = http.StatusOK
		s.wroteHeader = true
	}
	n, err := s.ResponseWriter.Write(p)
	s.bytesWritten += int64(n)
	return n, err
}

// Flush forwards to the wrapped writer when it supports http.Flusher.
// This is necessary to ensure the SSE implementation can stream its
// output properly.
func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Returns the HTTP status code which was sent.
func (s *statusWriter) status() int {
	if !s.wroteHeader {
		return http.StatusOK
	}
	return s.statusCode
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func durationMs(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1e6
}
