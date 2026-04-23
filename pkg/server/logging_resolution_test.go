package server

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/config"
	klog "github.com/messier-42/khaled/pkg/log"
)

// These tests pin the precedence rules between built-in defaults,
// CLI/env Options, and the snapshot's logging block. They exercise
// resolveLoggingConfig directly (the same function Run and
// runReloadLoop both call) so they don't need a full server boot.

func TestResolveLoggingConfig_BuiltinDefaultsWhenNothingSet(t *testing.T) {
	cfg, err := resolveLoggingConfig(config.Snapshot{Root: config.Map{}}, Options{})
	if err != nil {
		t.Fatalf("resolveLoggingConfig: %v", err)
	}
	if cfg.Format != DefaultLogFormat {
		t.Errorf("format = %q, want %q", cfg.Format, DefaultLogFormat)
	}
	if cfg.Severity != DefaultLogSeverity {
		t.Errorf("severity = %v, want %v", cfg.Severity, DefaultLogSeverity)
	}
}

func TestResolveLoggingConfig_OptionsFillEmptyConfig(t *testing.T) {
	cfg, err := resolveLoggingConfig(config.Snapshot{Root: config.Map{}}, Options{
		LogFormat:   "text",
		LogSeverity: "info",
	})
	if err != nil {
		t.Fatalf("resolveLoggingConfig: %v", err)
	}
	if cfg.Format != klog.FormatText {
		t.Errorf("format = %q, want %q", cfg.Format, klog.FormatText)
	}
	if cfg.Severity != slog.LevelInfo {
		t.Errorf("severity = %v, want %v", cfg.Severity, slog.LevelInfo)
	}
}

func TestResolveLoggingConfig_ConfigFileWinsOverOptions(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"logging": config.Map{
			"format":   "json",
			"severity": "warn",
		},
	}}
	cfg, err := resolveLoggingConfig(snap, Options{
		LogFormat:   "text",
		LogSeverity: "debug",
	})
	if err != nil {
		t.Fatalf("resolveLoggingConfig: %v", err)
	}
	if cfg.Format != klog.FormatJSON {
		t.Errorf("format = %q, want json (config wins)", cfg.Format)
	}
	if cfg.Severity != slog.LevelWarn {
		t.Errorf("severity = %v, want warn (config wins)", cfg.Severity)
	}
}

func TestResolveLoggingConfig_PartialConfigBlocksOptionsField(t *testing.T) {
	// Config sets severity only; CLI sets format only. Each wins
	// its own field — the unset fields fall back independently.
	snap := config.Snapshot{Root: config.Map{
		"logging": config.Map{"severity": "debug"},
	}}
	cfg, err := resolveLoggingConfig(snap, Options{LogFormat: "text"})
	if err != nil {
		t.Fatalf("resolveLoggingConfig: %v", err)
	}
	if cfg.Format != klog.FormatText {
		t.Errorf("format = %q, want text (Options, config silent)", cfg.Format)
	}
	if cfg.Severity != slog.LevelDebug {
		t.Errorf("severity = %v, want debug (config, Options silent)", cfg.Severity)
	}
}

// TestRunReapliesLoggerOnSuccessfulReload pins that runReloadLoop
// re-resolves the logging config and fires the observer a second
// time when a reload arrives.
func TestRunReapliesLoggerOnSuccessfulReload(t *testing.T) {
	initial := config.Snapshot{Root: config.Map{
		"logging": config.Map{
			"format":   "json",
			"severity": "error",
		},
	}}
	reloaded := config.Snapshot{Root: config.Map{
		"logging": config.Map{
			"format":   "text",
			"severity": "debug",
		},
	}}

	source := &fakeConfigSource{currentSnap: initial, updates: make(chan error, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var observed []klog.Config
	prevObserver := finalLoggingConfigObserver
	finalLoggingConfigObserver = func(cfg klog.Config) {
		observed = append(observed, cfg)
		if len(observed) == 1 {
			// runReloadLoop fires the observer for the *reloaded*
			// snapshot, not the initial one. Drive the reload now.
			source.currentSnap = reloaded
			source.updates <- nil
		} else {
			cancel()
		}
	}
	defer func() { finalLoggingConfigObserver = prevObserver }()

	// Prime by sending an initial nil update so the loop fires for
	// the first time. This stands in for the call Run makes during
	// startup.
	source.updates <- nil

	if err := runReloadLoop(ctx, source, defaultOptions()); err != nil {
		t.Fatalf("runReloadLoop: %v", err)
	}

	if len(observed) != 2 {
		t.Fatalf("observer fired %d times, want 2", len(observed))
	}
	if observed[0].Severity != slog.LevelError || observed[0].Format != klog.FormatJSON {
		t.Errorf("initial observed = %v/%v, want json/error", observed[0].Format, observed[0].Severity)
	}
	if observed[1].Severity != slog.LevelDebug || observed[1].Format != klog.FormatText {
		t.Errorf("reloaded observed = %v/%v, want text/debug", observed[1].Format, observed[1].Severity)
	}
}

// TestRunKeepsLoggerOnFailedReload pins that a failed reload does
// NOT fire the observer a second time — the previous logger is
// retained.
func TestRunKeepsLoggerOnFailedReload(t *testing.T) {
	initial := config.Snapshot{Root: config.Map{
		"logging": config.Map{
			"format":   "json",
			"severity": "warn",
		},
	}}
	source := &fakeConfigSource{currentSnap: initial, updates: make(chan error, 1)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	observed := 0
	prevObserver := finalLoggingConfigObserver
	finalLoggingConfigObserver = func(klog.Config) {
		observed++
		if observed == 1 {
			source.updates <- errors.New("reload boom")
			// Give the loop time to log and continue, then cancel.
			time.AfterFunc(50*time.Millisecond, cancel)
		}
	}
	defer func() { finalLoggingConfigObserver = prevObserver }()

	source.updates <- nil

	if err := runReloadLoop(ctx, source, defaultOptions()); err != nil {
		t.Fatalf("runReloadLoop: %v", err)
	}

	if observed != 1 {
		t.Fatalf("observer fired %d times, want 1 (no re-application on failed reload)", observed)
	}
}
