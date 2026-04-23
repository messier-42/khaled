// Package httpmw provides HTTP middleware used by khaled.
//
// As used by khaled, the current HTTP middleware chain is:
//
//	Logging → Authenticate → MapClaims → mux
//
// The functions of each of these are as follows:
//
//   - Logging assigns each incoming request a correlation ID, logs
//     request receive and completion at Debug, and recovers from
//     and logs subsequent handler panics.
//
//   - Authenticate invokes the configured Client Authn
//     plugin on each request and stashes the resulting ClientIdentity
//     on the request context. Authentication failures produce HTTP 401
//     and prevent the inner handler from running.
//
//   - MapClaims invokes the configured Claims Mapping plugin on the
//     ClientIdentity attached by Authenticate and stashes the
//     resulting policyengine.Principal on the request context. Mapper
//     failures produce HTTP 403 (no principal matches) or HTTP 500
//     (mapper/authenticator compatibility mismatch, internal error).
//
// Handlers retrieve the attached values via ClientIdentityFrom and
// PrincipalFrom. All pieces rely on pkg/log to carry request-scoped
// attributes; downstream handlers that use slog.*Context automatically
// see the correlation ID on every record.
package httpmw
