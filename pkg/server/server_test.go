package server

import (
	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin/configsource"
)

// defaultOptions returns the zero-valued Options that runReloadLoop
// and resolveLoggingConfig accept when the caller does not want to
// influence logger resolution. Convenience helper for tests that
// drive these functions directly.
func defaultOptions() Options { return Options{} }

// fakeConfigSource is a minimal in-memory configsource.Source for
// driving runReloadLoop in tests. UpdateChan returns a channel the
// test can send on to trigger a reload (nil for success, non-nil
// for failure). Current returns the most recently-set snapshot.
type fakeConfigSource struct {
	currentSnap config.Snapshot
	currentErr  error
	closed      bool
	updates     chan error
}

var _ configsource.Source = (*fakeConfigSource)(nil)

func (f *fakeConfigSource) Current() (config.Snapshot, error) {
	return f.currentSnap, f.currentErr
}

func (f *fakeConfigSource) UpdateChan() <-chan error {
	return f.updates
}

func (f *fakeConfigSource) Close() error {
	f.closed = true
	return nil
}
