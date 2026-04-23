package x509source

import "time"

// SetFileReloadRetryDelay overrides the retry delay used by
// file-backed sources when a reload fails. Tests call this to
// shorten the delay so they can exercise the retry path without
// waiting a full second per iteration. Returns a restore function.
func SetFileReloadRetryDelay(d time.Duration) func() {
	prev := fileReloadRetryDelay
	fileReloadRetryDelay = d
	return func() { fileReloadRetryDelay = prev }
}
