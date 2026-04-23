package httpmw

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
)

// MapClaims returns HTTP middleware that uses a [claimsmapping.ClaimsMapper]
// on every request to take a previously ascertained authenticated client
// identity, map it to a Principal comprising a set of claims, and attaches
// that information to the request using [WithPrincipal].
//
// The [clainsmapping.ClaimsMapper] interface is provided via a delegate
// which is invoked at time-of-use so that live configuration reload
// can atomically swap the [clientauthn.Authenticator] in use without having
// to reconstruct the entire HTTP middleware stack.
//
// The mapping process proceeds as follows:
//
//   - Success: the inner handler is invoked with a context augmented using
//     [WithPrincipal].
//
//   - ClientIdentity not available: HTTP 500. The middleware stack is
//     misconfigured or the client authenticator did not provide an identity.
//
//   - Mapper not available (nil from src): HTTP 500 with a CKAP
//     Error body carrying CodeInternal. This indicates an internal
//     failure and should be avoided.
//
//   - Mapper returns ErrPrincipalUnknown: HTTP 403. Normal "no principal matches"
//     denial.
//
//   - Mapper returns another error: HTTP 500 with a CKAP
//     Error body carrying CodeInternal. This indicates a configuration
//     or other issue.
func MapClaims(src func() claimsmapping.ClaimsMapper) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, ok := ClientIdentityFrom(r.Context())
			if !ok {
				slog.ErrorContext(r.Context(), "MapClaims called without Authenticate")
				http.Error(w, "authentication unavailable", http.StatusInternalServerError)
				return
			}

			mapper := src()
			if mapper == nil {
				slog.ErrorContext(r.Context(), "claims mapper not available")
				http.Error(w, "authorization unavailable", http.StatusInternalServerError)
				return
			}

			principal, err := mapper.Map(r.Context(), id)
			if err != nil {
				switch {
				case errors.Is(err, claimsmapping.ErrIdentityUnsupported):
					slog.ErrorContext(r.Context(), "claims mapper rejected identity type",
						"uri", id.URI(),
						"error", err.Error(),
					)
					http.Error(w, "authorization unavailable", http.StatusInternalServerError)
					return
				case errors.Is(err, claimsmapping.ErrPrincipalUnknown):
					slog.InfoContext(r.Context(), "claims mapping denied",
						"uri", id.URI(),
						"error", err.Error(),
					)
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				default:
					slog.ErrorContext(r.Context(), "claims mapping failed",
						"uri", id.URI(),
						"error", err.Error(),
					)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
			}

			slog.DebugContext(r.Context(), "claims mapped",
				"uri", principal.URI,
				"claimCount", len(principal.Claims),
			)

			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), principal)))
		})
	}
}
