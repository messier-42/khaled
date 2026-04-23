package httpmw

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckaphttp"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
)

// Authenticate returns HTTP middleware that uses a [clientauthn.Authenticator]
// on every request to ascertain a ClientIdentity and attach it to the request
// for subsequent processing using [WithClientIdentity].
//
// The [clientauthn.Authenticator] interface is provided via a delegate
// which is invoked at time-of-use so that live configuration reload
// can atomically swap the [clientauthn.Authenticator] in use without having
// to reconstruct the entire HTTP middleware stack.
//
// Authentication occurs as follows:
//
//   - Successful authentication: the inner handler is invoked with an
//     context augmented using [WithClientIdentity].
//
//   - Authenticator not available (nil from src): HTTP 500 with a CKAP
//     Error body carrying CodeInternal. This indicates an internal
//     failure and should be avoided.
//
//   - Authenticator returns an error: HTTP 401 with a CKAP
//     Error body carrying CodeUnauthorized.
//
// All error responses are CKAP Error responses written via [ckaphttp.WriteErrorHTTP].
func Authenticate(src func() clientauthn.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the current authenticator.
			auth := src()
			if auth == nil {
				slog.ErrorContext(r.Context(), "authenticator not available")
				ckaphttp.WriteErrorHTTP(r.Context(), ckap.Error{
					Code:    cabe.CodeInternal,
					Summary: "authentication unavailable",
				}, w, http.StatusInternalServerError)
				return
			}

			// Attempt authenticatoin of the request.
			id, err := auth.Authenticate(r)
			if err != nil {
				reason := "verification failed"
				switch {
				case errors.Is(err, clientauthn.ErrNotTLS):
					reason = "not tls"
				case errors.Is(err, clientauthn.ErrNoClientCertificate):
					reason = "no client certificate"
				}
				slog.InfoContext(r.Context(), "authentication failed",
					"reason", reason,
					"error", err.Error(),
				)
				ckaphttp.WriteErrorHTTP(r.Context(), ckap.Error{
					Code:    cabe.CodeUnauthorized,
					Summary: "unauthorized",
				}, w, http.StatusUnauthorized)
				return
			}

			slog.DebugContext(r.Context(), "authenticated",
				"uri", id.URI(),
			)

			next.ServeHTTP(w, r.WithContext(WithClientIdentity(r.Context(), id)))
		})
	}
}
