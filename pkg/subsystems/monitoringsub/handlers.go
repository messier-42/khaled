package monitoringsub

import (
	stdhttp "net/http"
	"strings"

	"github.com/messier-42/khaled/pkg/health"
)

// newMux builds the ServeMux for the monitoring listener: /livez,
// /readyz, a 405 for non-GET on those paths, and a 404 fallback.
func newMux(readyFunc ReadyFunc) *stdhttp.ServeMux {
	mux := stdhttp.NewServeMux()

	// Go 1.22+ method-and-path patterns: "GET /livez" matches only
	// GET; a bare "/livez" catches every other method so it can
	// answer 405 rather than falling through to the 404 handler.
	mux.HandleFunc("GET /livez", handleLivez)
	mux.HandleFunc("/livez", methodNotAllowed)

	mux.Handle("GET /readyz", &readyzHandler{readyFunc: readyFunc})
	mux.HandleFunc("/readyz", methodNotAllowed)

	mux.HandleFunc("/", stdhttp.NotFound)
	return mux
}

// handleLivez always reports the process as live. Liveness is pure
// process-aliveness; it never consults subsystem state.
func handleLivez(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(stdhttp.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// methodNotAllowed answers 405 for a recognised path reached with a
// method other than GET.
func methodNotAllowed(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
	stdhttp.Error(w, "method not allowed", stdhttp.StatusMethodNotAllowed)
}

// readyzHandler serves /readyz. It aggregates the readiness checks
// returned by readyFunc: 200 when all pass, 503 otherwise.
//
// With the "verbose" query parameter present (e.g. /readyz?verbose) the
// response carries a plaintext body, one "[+]"/"[-]" line per check
// followed by a summary line — mirroring kube-apiserver's
// /readyz?verbose so existing operator tooling and habits transfer.
type readyzHandler struct {
	readyFunc ReadyFunc
}

func (h *readyzHandler) ServeHTTP(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	results := h.readyFunc()
	ok := health.AllOK(results)

	status := stdhttp.StatusOK
	if !ok {
		status = stdhttp.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	if _, verbose := r.URL.Query()["verbose"]; verbose {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(verboseBody(results, ok)))
		return
	}

	w.WriteHeader(status)
	if ok {
		_, _ = w.Write([]byte("ok\n"))
	} else {
		_, _ = w.Write([]byte("not ready\n"))
	}
}

// verboseBody renders the per-check detail body for /readyz?verbose.
func verboseBody(results []health.CheckResult, ok bool) string {
	var b strings.Builder
	for _, res := range results {
		if res.OK {
			b.WriteString("[+] ")
			b.WriteString(res.Name)
			b.WriteString(" ok\n")
			continue
		}
		b.WriteString("[-] ")
		b.WriteString(res.Name)
		b.WriteString(" failed")
		if res.Detail != "" {
			b.WriteString(": ")
			b.WriteString(res.Detail)
		}
		b.WriteString("\n")
	}
	if ok {
		b.WriteString("readyz check passed\n")
	} else {
		b.WriteString("readyz check failed\n")
	}
	return b.String()
}
