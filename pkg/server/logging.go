package server

import (
	"fmt"
	"log/slog"

	"github.com/messier-42/khaled/pkg/config"
	klog "github.com/messier-42/khaled/pkg/log"
)

// parseLogSeverity accepts a log level and returns slog.Level. It is
// case sensitive and accepts only lowercase input.
func parseLogSeverity(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log severity %q: must be %q, %q, %q, or %q", s, "debug", "info", "warn", "error")
	}
}

// resolveLoggingConfig produces the final logging configuration by
// merging log configuration from three different sources:
//
//  1. Config source values (logging.*), preferred if present;
//  2. Failing that, the CLI flag/environment variable value provided in Options;
//  3. Failing that, a built-in default.
//
// The returned error is non-nil if the config contains logging
// configuration which is invalid.
func resolveLoggingConfig(snap config.Snapshot, opts Options) (klog.Config, error) {
	format := DefaultLogFormat
	if opts.LogFormat != "" {
		parsed, err := klog.ParseFormat(opts.LogFormat)
		if err != nil {
			return klog.Config{}, err
		}
		format = parsed
	}

	severity := DefaultLogSeverity
	if opts.LogSeverity != "" {
		parsed, err := parseLogSeverity(opts.LogSeverity)
		if err != nil {
			return klog.Config{}, err
		}
		severity = parsed
	}

	if logging, ok := snap.Root.GetMap("logging"); ok {
		if raw, ok := logging.GetString("format"); ok {
			parsed, err := klog.ParseFormat(raw)
			if err != nil {
				return klog.Config{}, fmt.Errorf("logging.format: %w", err)
			}
			format = parsed
		}
		if raw, ok := logging.GetString("severity"); ok {
			parsed, err := parseLogSeverity(raw)
			if err != nil {
				return klog.Config{}, fmt.Errorf("logging.severity: %w", err)
			}
			severity = parsed
		}
	}

	return klog.Config{Format: format, Severity: severity}, nil
}
