// Package log provides utilities for khaled's usage of log/slog.
package log

import (
	"fmt"
	"io"
	"log/slog"
)

// Format selects the slog output format used.
type Format string

const (
	FormatJSON Format = "json"
	FormatText Format = "text"
)

// ParseFormat parses an output format name.
func ParseFormat(s string) (Format, error) {
	switch s {
	case string(FormatJSON):
		return FormatJSON, nil
	case string(FormatText):
		return FormatText, nil
	default:
		return "", fmt.Errorf("invalid log format %q: must be 'text' or 'json'", s)
	}
}

// Config is the resolved logging configuration.
type Config struct {
	Format   Format
	Severity slog.Level
}

// New constructs a *slog.Logger from cfg, writing output to the given
// [io.Writer].
//
// The returned logger's handler is wrapped in a ctxHandler so that
// attributes attached to a context via WithAttr (or the typed
// helpers) appear on every record emitted via the slog.*Context
// methods.
func New(w io.Writer, cfg Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.Severity}

	var handler slog.Handler
	switch cfg.Format {
	case FormatJSON:
		handler = slog.NewJSONHandler(w, opts)
	case FormatText:
		handler = slog.NewTextHandler(w, opts)
	default:
		handler = slog.NewTextHandler(w, opts)
	}

	return slog.New(ctxHandler{inner: handler})
}
