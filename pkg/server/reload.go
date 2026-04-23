package server

import (
	"context"
	"log/slog"
	"os"

	"github.com/messier-42/khaled/pkg/config"
	klog "github.com/messier-42/khaled/pkg/log"
	"github.com/messier-42/khaled/pkg/plugin/configsource"
)

// reloadHandler is invoked by runReloadLoop after each successful
// config reload. It receives the freshly loaded config snapshot.
// Returned errors are logged but do not stop the loop.
type reloadHandler func(ctx context.Context, snap config.Snapshot) error

// runReloadLoop blocks until ctx is cancelled, consuming reload
// notifications from source. On a successful reload it re-resolves the
// logging configuration (applying the same precedence rules as at
// startup), replaces slog's default logger, and invokes each supplied
// handler in order. Handler errors are logged and the loop continues.
// On a failed reload it logs the failure and continues to use the
// previous config.
//
// The function returns nil on graceful shutdown, such as in the case of
// context cancellation.
func runReloadLoop(ctx context.Context, source configsource.Source, opts Options, handlers ...reloadHandler) error {
	updates := source.UpdateChan()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err, ok := <-updates:
			if !ok {
				// The source closed its update channel; nothing more to do.
				// Wait for shutdown.
				<-ctx.Done()
				return nil
			}
			if err != nil {
				slog.Error("config reload failed", "error", err)
				continue
			}
			snap, cerr := source.Current()
			if cerr != nil {
				slog.Error("post-reload Current() failed", "error", cerr)
				continue
			}
			finalCfg, rerr := resolveLoggingConfig(snap, opts)
			if rerr != nil {
				slog.Error("post-reload logging config invalid", "error", rerr)
				continue
			}
			if finalLoggingConfigObserver != nil {
				finalLoggingConfigObserver(finalCfg)
			}
			slog.SetDefault(klog.New(os.Stderr, finalCfg))
			slog.Info("config reloaded", "logFormat", string(finalCfg.Format), "logSeverity", finalCfg.Severity.String())

			for _, h := range handlers {
				// Check cancellation between handlers so SIGTERM
				// during a reload does not force us to wait for
				// every Reconcile in the chain. Each handler is
				// also expected to honour ctx internally.
				select {
				case <-ctx.Done():
					return nil
				default:
				}

				if err := h(ctx, snap); err != nil {
					slog.Error("reload handler failed", "error", err)
				}
			}
		}
	}
}
