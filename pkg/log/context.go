package log

import (
	"context"
	"log/slog"
	"slices"
)

// ctxKey is the internal type used as a key to store log attributes
// on a [context.Context].
type ctxKey struct{}

// Get the attributes set on a context (or nil).
func getAttrs(ctx context.Context) []slog.Attr {
	attrs, _ := ctx.Value(ctxKey{}).([]slog.Attr)
	return attrs
}

// Set attributes on a context and return the resultant derived context.
func setAttrs(ctx context.Context, attrs []slog.Attr) context.Context {
	return context.WithValue(ctx, ctxKey{}, attrs)
}

const (
	kCorrelationID = "correlationID"
	kRequestID     = "requestID"
)

// WithAttr returns a context derived from ctx which appends the given attrs
// to every log record emitted using slog calls made using the returned context.
//
// Any existing attributes attached to the input ctx are preserved.
// Conflict resolution is handler-dependent; for log/slog's text and JSON
// logging handlers, a last-attribute-wins approach is used.
func WithAttr(ctx context.Context, a slog.Attr) context.Context {
	parentAttrs := getAttrs(ctx)
	childAttrs := make([]slog.Attr, len(parentAttrs), len(parentAttrs)+1)
	copy(childAttrs, parentAttrs)
	return setAttrs(ctx, append(childAttrs, a))
}

// WithCorrelationID attaches a correlation ID to a context as the
// `correlationID` attribute and returns the resultant derived context. It
// is intended for use to carry a server-generated unique request correlator
// through the entire lifecycle of a request.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return WithAttr(ctx, slog.String(kCorrelationID, id))
}

// WithRequestID attaches a request ID to a context as the `requestID` attribute and returns
// the resultant derived context. It is intended for use to carry an externally
// provided request ID (such as that which be provided by a client in an HTTP header)
// through the entire lifecycle of a request.
//
// Unlike the correlation ID which is intended to be locally generated and trusted,
// a request ID is external in origin, may not be present, might not be unique,
// and may be malicious in nature.
func WithRequestID(ctx context.Context, id string) context.Context {
	return WithAttr(ctx, slog.String(kRequestID, id))
}

// CorrelationID returns the correlation ID previously attached to a context, if any.
// The most recently set value is returned. Returns ("", false) if not present.
func CorrelationID(ctx context.Context) (string, bool) {
	return getStrAttr(ctx, kCorrelationID)
}

// RequestID returns the request ID previously attached to a context, if any.
// The most recently set value is returned. Returns ("", false) if not present.
func RequestID(ctx context.Context) (string, bool) {
	return getStrAttr(ctx, kRequestID)
}

func getStrAttr(ctx context.Context, attrName string) (string, bool) {
	attrs := getAttrs(ctx)
	for _, attr := range slices.Backward(attrs) {
		if attr.Key == attrName {
			if s, ok := attr.Value.Any().(string); ok {
				return s, true
			}
			return attr.Value.String(), true
		}
	}
	return "", false
}

// ctxHandler wraps a slog.Handler. On Handle, it appends the slog attributes
// set on the ctx provided to the slog call to the produced slog record.
type ctxHandler struct {
	inner slog.Handler
}

func (h ctxHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h ctxHandler) Handle(ctx context.Context, r slog.Record) error {
	if attrs := getAttrs(ctx); len(attrs) > 0 {
		r.AddAttrs(attrs...)
	}
	return h.inner.Handle(ctx, r)
}

func (h ctxHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return ctxHandler{inner: h.inner.WithAttrs(attrs)}
}

func (h ctxHandler) WithGroup(name string) slog.Handler {
	return ctxHandler{inner: h.inner.WithGroup(name)}
}

// NewCtxHandler wraps an arbitrary slog.Handler. The resultant Handler
// appends any slog attributes set using the above functions on the
// [context.Context] passed to slog to the produced slog record.
func NewCtxHandler(h slog.Handler) slog.Handler {
	return ctxHandler{inner: h}
}
