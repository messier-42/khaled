// Package configsource defines the Config Source plugin interface.
//
// A Config Source delivers configuration snapshots and provides
// notifications when updates occur.
//
// A Source that has ever successfully loaded a configuration MUST
// continue to serve it even if a subsequent reload attempt fails.
// Failed reloads are communicated via UpdateChan as an error value;
// callers may log such an event but are generally expected to continue
// operating using the previous good configuration.
package configsource

import (
	"context"
	"io"

	"github.com/messier-42/khaled/pkg/config"
)

// ValidateFunc is invoked each time a Source attempts to adopt a freshly
// loaded configuration. It runs synchronously inside the reload path, so
// returning an error aborts the reload, meaning that the Source continues to
// serve the previous configuration (or, on initial load, records the error as
// the startup error).
//
// On the initial load oldConfig is nil. On a subsequent reload oldConfig
// points to the configuration that is currently being served.
type ValidateFunc func(ctx context.Context, oldConfig *config.Snapshot, newConfig config.Snapshot) error

// Source provides access to the current configuration and provides notification
// when the current configuration changes.
type Source interface {
	io.Closer

	// Current returns the current configuration snapshot. It always returns either
	// a valid config.Snapshot or an error. When Current is called for the first time,
	// it returns the initial configuration which was loaded, or an error if the config
	// could not be loaded at initial load time.
	//
	// Once a configuration is successfully loaded, it is returned by this method.
	// If a subsequent change to a configuration occurs, it is detected
	// automatically, nil is sent on UpdateChan() and the return value of this
	// method changes. Note that a configuration change results in creation of a
	// completely new config.Snapshot; no previously returned data is modified.
	//
	// If a configuration is modified and reloaded and the new configuration cannot
	// be loaded due to an error, the old configuration continues to be returned.
	// This means that it is guaranteed that once this method has returned a valid
	// config and nil error once, all future calls will succeed for the remaining
	// lifetime of the Source.
	//
	// Callers should detect startup configuration errors by calling this method at
	// launch and ensuring it succeeds. Callers can detect failed reloads using
	// UpdateChan(). Callers should continue using the old last-known-good
	// configuration in this case.
	Current() (config.Snapshot, error)

	// UpdateChan returns a channel which is sent on whenever a configuration is
	// reloaded. The initial configuration load does not result in a value being
	// sent on this channel. If the reload attempt was successful, nil is sent. If
	// the reload attempt was unsuccessful, an error is sent. Callers should report
	// the failed reload via a logging mechanism and continue using the current
	// configuration. An implementation is permitted to coalesce multiple updates
	// into a single send on this channel, and to delay reporting to facilitate
	// such coalescing if desired.
	UpdateChan() <-chan error
}
