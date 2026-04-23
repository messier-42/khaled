package http

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	stdhttp "net/http"

	"github.com/fxamacker/cbor/v2"

	"github.com/messier-42/cabe-go/cabe"
	"github.com/messier-42/cabe-go/ckap"
	"github.com/messier-42/cabe-go/ckaphttp"
	"github.com/messier-42/cabe-go/ckapraw"
	"github.com/messier-42/khaled/pkg/httpmw"
	"github.com/messier-42/khaled/pkg/keyserver"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
)

// maxCKAPReqLen sets the maximum size of an inbound CKAP request body.
const maxCKAPReqLen = 1 * 1024 * 1024 // 1 MiB

// strictCBORDec is the DecMode used for inbound CKAP request data.
var strictCBORDec = func() cbor.DecMode {
	m, err := cbor.DecOptions{
		MaxNestedLevels:  32,
		MaxArrayElements: 65536,
		MaxMapPairs:      65536,
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
	}.DecMode()
	if err != nil {
		panic(fmt.Sprintf("ckap: build strict cbor dec mode: %v", err))
	}
	return m
}()

func handleRequireMethod(mux *stdhttp.ServeMux, methodName, path string, handler stdhttp.Handler) {
	mux.Handle(methodName+" "+path, handler)
	mux.Handle(path, stdhttp.HandlerFunc(methodNotAllowedCKAP(methodName)))
}

// registerCKAPHandlers wires the CKAP operation endpoints to a ServeMux.
//
// getKeyServerFunc must be a function which returns the currently active
// key server instance; it is invoked per request to allow config changes
// at runtime.
func registerCKAPHandlers(mux *stdhttp.ServeMux, getKeyServerFunc func() *keyserver.Server) {
	for path, h := range map[string]stdhttp.Handler{
		"/ckap/GetSelf":             handle(getKeyServerFunc, handleGetSelf),
		"/ckap/Prograde":            handle(getKeyServerFunc, handlePrograde),
		"/ckap/Retrograde":          handle(getKeyServerFunc, handleRetrograde),
		"/ckap/AssistedEncapsulate": handle(getKeyServerFunc, handleAssistedEncapsulate),
		"/ckap/AssistedDecapsulate": handle(getKeyServerFunc, handleAssistedDecapsulate),
	} {
		handleRequireMethod(mux, stdhttp.MethodPost, path, h)
	}

	// TODO: Implement ARIN.
	handleRequireMethod(mux, stdhttp.MethodGet, "/ckap/ARINToken", stdhttp.HandlerFunc(arinUnsupported))
	handleRequireMethod(mux, stdhttp.MethodGet, "/ckap/ARIN", stdhttp.HandlerFunc(arinUnsupported))
}

// methodNotAllowedCKAP returns a handler that responds with a
// CBOR-shaped CKAP Error. It is mounted on the bare
// path so ServeMux's method-aware pattern matching routes
// requests with the wrong method here.
func methodNotAllowedCKAP(allowedMethod string) func(stdhttp.ResponseWriter, *stdhttp.Request) {
	return func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		w.Header().Set("Allow", allowedMethod)
		writeCKAPError(r.Context(), w, stdhttp.StatusMethodNotAllowed, cabe.CodeMalformedRequest, "method not allowed")
	}
}

func writeCKAPError(ctx context.Context, w stdhttp.ResponseWriter, status int, code cabe.Code, summary string) {
	ckaphttp.WriteErrorHTTP(ctx, ckap.Error{Code: code, Summary: summary}, w, status)
}

// ckapHandlerContext provides access to everything a CKAP operation handler
// needs.
type ckapHandlerContext struct {
	Request        *stdhttp.Request
	ResponseWriter stdhttp.ResponseWriter
	KeyServer      *keyserver.Server
	Principal      policyengine.Principal
}

// Context returns the request's context.Context.
func (hctx *ckapHandlerContext) Context() context.Context {
	return hctx.Request.Context()
}

// ckapHandlerFn is the signature of a typed CKAP operation handler.
// It returns the response value to CBOR-encode and an optional cleanup
// closure that the framework runs after the response has been
// serialised and written. Handlers may use the cleanup function to zero sensitive
// data (e.g. key material) that are serialized during encoding.
//
// This zeroization is best-effort and not assumed to be fully effective yet until
// Go 1.26's runtime/secret is integrated.
type ckapHandlerFn func(hctx *ckapHandlerContext) (resp any, cleanup func(), err error)

// handle wraps a typed CKAP operation handler with request verification,
// decoding, lookup, error translation and response encoding handling which
// is common to all CKAP operations.
//
// A handler-supplied cleanup closure runs after the CBOR response bytes
// have been written to the client, which can be used for zeroization.
func handle(getKeyServerFunc func() *keyserver.Server, fn ckapHandlerFn) stdhttp.Handler {
	return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		// Enforce request headers.
		if err := requireCKAPMediaType(r); err != nil {
			writeCKAPError(r.Context(), w, stdhttp.StatusUnsupportedMediaType, cabe.CodeMalformedRequest, err.Error())
			return
		}

		// Figure out the mapped principal.
		principal, ok := httpmw.PrincipalFrom(r.Context())
		if !ok {
			writeCKAPError(r.Context(), w, stdhttp.StatusUnauthorized, cabe.CodeUnauthorized, "no authenticated principal")
			return
		}

		// Obtain the current key server.
		ks := getKeyServerFunc()
		if ks == nil {
			writeCKAPError(r.Context(), w, stdhttp.StatusServiceUnavailable, cabe.CodeInternal, "keyserver not available")
			return
		}

		// Invoke the handler.
		hctx := &ckapHandlerContext{
			Request:        r,
			ResponseWriter: w,
			KeyServer:      ks,
			Principal:      principal,
		}

		resp, cleanup, err := fn(hctx)
		if cleanup != nil {
			defer cleanup()
		}

		// Write the error or non-error response.
		if err != nil {
			writeMappedError(w, r.Context(), err)
			return
		}

		writeCKAPResponse(w, r.Context(), stdhttp.StatusOK, resp)
	})
}

// requireCKAPMediaType enforces the correct Content-Type
// and Accept HTTP headers.
func requireCKAPMediaType(r *stdhttp.Request) error {
	if err := expectCKAPMediaType(r.Header.Get("Content-Type"), "Content-Type"); err != nil {
		return err
	}
	if err := expectCKAPMediaType(r.Header.Get("Accept"), "Accept"); err != nil {
		return err
	}
	return nil
}

func expectCKAPMediaType(headerValue, headerName string) error {
	if headerValue == "" {
		return fmt.Errorf("%s must be %q", headerName, ckap.MediaType)
	}
	mt, _, err := mime.ParseMediaType(headerValue)
	if err != nil {
		return fmt.Errorf("%s is not a valid media type", headerName)
	}
	if mt != ckap.MediaType {
		return fmt.Errorf("%s must be %q", headerName, ckap.MediaType)
	}
	return nil
}

// decodeRequest decodes the inbound CBOR body into a freshly-allocated
// value of type T and verifies its "kind" field matches the canonical
// kind string for T. It returns a *ckap.Error on any decode or kind
// mismatch.
//
// T is constrained through PT to be a ckapraw request struct whose
// *T implements ckapraw.Kinded.
func decodeRequest[T any, PT interface {
	*T
	ckapraw.Kinded
}](hctx *ckapHandlerContext) (T, error) {
	var req T
	if err := decodeCBOR(hctx.ResponseWriter, hctx.Request, PT(&req)); err != nil {
		return req, err
	}

	want := PT(&req).DefaultKind()
	if got := PT(&req).GetKind(); got != want {
		return req, &ckap.Error{
			Code:    cabe.CodeMalformedRequest,
			Summary: fmt.Sprintf("kind must be %q", want),
		}
	}

	return req, nil
}

func handleGetSelf(hctx *ckapHandlerContext) (any, func(), error) {
	_, err := decodeRequest[ckapraw.GetSelfRequest](hctx)
	if err != nil {
		return nil, nil, err
	}

	resp, err := hctx.KeyServer.GetSelf(hctx.Context(), keyserver.GetSelfRequest{Principal: hctx.Principal})
	if err != nil {
		return nil, nil, err
	}

	return ckapraw.GetSelfResponse{
		Kind: ckapraw.KindGetSelfResponse,
		Principal: ckapraw.Principal{
			URI:    resp.Principal.URI,
			Claims: resp.Principal.Claims,
		},
		ServerInfo: resp.ServerInfo,
	}, nil, nil
}

func handlePrograde(hctx *ckapHandlerContext) (any, func(), error) {
	req, err := decodeRequest[ckapraw.ProgradeRequest](hctx)
	if err != nil {
		return nil, nil, err
	}
	as, err := req.AttributeSet.Parse()
	if err != nil {
		return nil, nil, &ckap.Error{Code: cabe.CodeMalformedRequest, Summary: "invalid attributeSet", Err: err}
	}

	resp, err := hctx.KeyServer.Prograde(hctx.Context(), keyserver.ProgradeRequest{
		Principal: hctx.Principal, AttributeSet: as, ARINToken: req.ARINToken,
	})
	if err != nil {
		return nil, nil, err
	}

	leaseEnc, err := encodeLease(resp.Lease)
	if err != nil {
		return nil, nil, err
	}

	cleanup := zeroLKAICleanup(resp.Lease.LKAI)
	return ckapraw.ProgradeResponse{Kind: ckapraw.KindProgradeResponse, Lease: leaseEnc}, cleanup, nil
}

func handleRetrograde(hctx *ckapHandlerContext) (any, func(), error) {
	req, err := decodeRequest[ckapraw.RetrogradeRequest](hctx)
	if err != nil {
		return nil, nil, err
	}
	as, err := req.AttributeSet.Parse()
	if err != nil {
		return nil, nil, &ckap.Error{Code: cabe.CodeMalformedRequest, Summary: "invalid attributeSet", Err: err}
	}

	resp, err := hctx.KeyServer.Retrograde(hctx.Context(), keyserver.RetrogradeRequest{
		Principal: hctx.Principal, AttributeSet: as, LeaseRef: req.LeaseRef,
	})
	if err != nil {
		return nil, nil, err
	}

	lkaiEnc, err := encodeLKAI(resp.Lease.LKAI)
	if err != nil {
		return nil, nil, err
	}

	cleanup := zeroLKAICleanup(resp.Lease.LKAI)
	return ckapraw.RetrogradeResponse{
		Kind:         ckapraw.KindRetrogradeResponse,
		AttributeSet: ckapraw.FromSet(resp.Lease.AttributeSet),
		LKAI:         lkaiEnc,
	}, cleanup, nil
}

func handleAssistedEncapsulate(hctx *ckapHandlerContext) (any, func(), error) {
	req, err := decodeRequest[ckapraw.AssistedEncapsulateRequest](hctx)
	if err != nil {
		return nil, nil, err
	}

	resp, err := hctx.KeyServer.AssistedEncapsulate(hctx.Context(), keyserver.AssistedEncapsulateRequest{
		Principal: hctx.Principal, LKAT: req.LeaseKeyAccessToken, CEK: req.CEK,
	})
	if err != nil {
		return nil, nil, err
	}

	return ckapraw.AssistedEncapsulateResponse{Kind: ckapraw.KindAssistedEncapsulateResponse, WrappedCEK: resp.WrappedCEK}, nil, nil
}

func handleAssistedDecapsulate(hctx *ckapHandlerContext) (any, func(), error) {
	req, err := decodeRequest[ckapraw.AssistedDecapsulateRequest](hctx)
	if err != nil {
		return nil, nil, err
	}

	resp, err := hctx.KeyServer.AssistedDecapsulate(hctx.Context(), keyserver.AssistedDecapsulateRequest{
		Principal: hctx.Principal, LKAT: req.LeaseKeyAccessToken, WrappedCEK: req.WrappedCEK,
	})
	if err != nil {
		return nil, nil, err
	}

	return ckapraw.AssistedDecapsulateResponse{Kind: ckapraw.KindAssistedDecapsulateResponse, CEK: resp.CEK}, nil, nil
}

// zeroLKAICleanup returns a cleanup closure that zeroes the
// sensitive byte slices reachable from the LKAI, namely NonCaptive.LeaseKey.
//
// This is best effort and cannot guarantee stack data is erased. In future,
// Go's runtime/secret should be adopted to augment this approach.
func zeroLKAICleanup(k keyserver.LKAI) func() {
	if k.NonCaptive == nil || len(k.NonCaptive.LeaseKey) == 0 {
		return nil
	}
	buf := k.NonCaptive.LeaseKey
	return func() { clear(buf) }
}

func arinUnsupported(w stdhttp.ResponseWriter, r *stdhttp.Request) {
	writeCKAPError(r.Context(), w, stdhttp.StatusNotImplemented, cabe.CodeUnsupported, "ARIN not implemented")
}

func encodeLease(l keyserver.Lease) (ckapraw.Lease, error) {
	lkai, err := encodeLKAI(l.LKAI)
	if err != nil {
		return ckapraw.Lease{}, err
	}

	return ckapraw.Lease{
		LeaseID:      l.LeaseID,
		LeaseRef:     l.LeaseRef,
		AttributeSet: ckapraw.FromSet(l.AttributeSet),
		LKAI:         lkai,
		Expiry:       l.Expiry.Unix(),
	}, nil
}

func encodeLKAI(k keyserver.LKAI) (ckapraw.LKAI, error) {
	out := ckapraw.LKAI{}
	if k.NonCaptive != nil {
		coseKey, err := newCOSESymmetricKey(k.NonCaptive.LeaseKey)
		if err != nil {
			return ckapraw.LKAI{}, err
		}

		out.NonCaptive = &ckapraw.LKAINonCaptive{
			LeaseKey: coseKey,
		}
	}
	if k.Captive != nil {
		out.Captive = &ckapraw.LKAIActive{LeaseKeyAccessToken: k.Captive.LKAT}
	}
	return out, nil
}

// decodeCBOR reads the bounded request body and decodes it into v
// using strict decoding. A maximum request body size is enforced and
// surfaced as cabe.CodeRequestTooLarge (HTTP 413).
func decodeCBOR(w stdhttp.ResponseWriter, r *stdhttp.Request, v any) error {
	r.Body = stdhttp.MaxBytesReader(w, r.Body, maxCKAPReqLen)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mberr *stdhttp.MaxBytesError
		if errors.As(err, &mberr) {
			return &ckap.Error{
				Code:    cabe.CodeRequestTooLarge,
				Summary: "request body too large",
				Err:     err,
			}
		}

		return &ckap.Error{
			Code:    cabe.CodeMalformedRequest,
			Summary: "malformed request body",
			Err:     err,
		}
	}

	if err := strictCBORDec.Unmarshal(data, v); err != nil {
		return &ckap.Error{
			Code:    cabe.CodeMalformedRequest,
			Summary: "malformed request body",
			Err:     err,
		}
	}

	return nil
}

// writeCKAPResponse encodes v as CBOR and writes it with the given
// status code.
func writeCKAPResponse(w stdhttp.ResponseWriter, ctx context.Context, status int, v any) {
	var buf bytes.Buffer
	if err := cbor.NewEncoder(&buf).Encode(v); err != nil {
		slog.ErrorContext(ctx, "ckap: response encode failed", "error", err)
		writeCKAPError(ctx, w, stdhttp.StatusInternalServerError, cabe.CodeInternal, "internal error")
		return
	}

	w.Header().Set("Content-Type", ckap.MediaType)
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// httpStatusForCode returns the HTTP status code a CKAP error with
// the given cabe.Code should be surfaced with.
func httpStatusForCode(c cabe.Code) int {
	switch c {
	case cabe.CodeMalformedRequest, cabe.CodeInvalidRef, cabe.CodeInvalidAttributeSet:
		return stdhttp.StatusBadRequest
	case cabe.CodeUnauthorized:
		return stdhttp.StatusUnauthorized
	case cabe.CodePolicyDenied:
		return stdhttp.StatusForbidden
	case cabe.CodeRequestTooLarge:
		return stdhttp.StatusRequestEntityTooLarge
	case cabe.CodeUnsupported:
		return stdhttp.StatusNotImplemented
	case cabe.CodeInternal:
		return stdhttp.StatusInternalServerError
	default:
		return stdhttp.StatusInternalServerError
	}
}

// writeMappedError maps err to a CKAP error response and sends it.
//
// If err is, or wraps, a *ckap.Error, its data is encoded verbatim
// and an HTTP status is derived automatically based on the CKAP Code
// field.
//
// Failing that, certain sentinel errors are translated into a fresh
// *ckap.Error. Anything else is treated as an internal error.
func writeMappedError(w stdhttp.ResponseWriter, ctx context.Context, err error) {
	var ce *ckap.Error
	if errors.As(err, &ce) {
		slog.InfoContext(ctx, "ckap: handler rejected request",
			"code", ce.Code,
			"op", ce.Op,
			"summary", ce.Summary,
			"error", err)
		ckaphttp.WriteErrorHTTP(ctx, *ce, w, httpStatusForCode(ce.Code))
		return
	}

	switch {
	case errors.Is(err, keyserver.ErrDenied):
		slog.InfoContext(ctx, "ckap: policy denied", "error", err)
		writeCKAPError(ctx, w, stdhttp.StatusForbidden, cabe.CodePolicyDenied, "access denied")
	case errors.Is(err, keyserver.ErrInvalidRef):
		slog.InfoContext(ctx, "ckap: invalid lease ref", "error", err)
		writeCKAPError(ctx, w, stdhttp.StatusBadRequest, cabe.CodeInvalidRef, "invalid lease reference")
	default:
		slog.ErrorContext(ctx, "ckap: internal error", "error", err)
		writeCKAPError(ctx, w, stdhttp.StatusInternalServerError, cabe.CodeInternal, "internal error")
	}
}
