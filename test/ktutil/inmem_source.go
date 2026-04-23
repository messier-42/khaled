package khaledtest

import (
	"sync"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin/configsource"
)

// inMemorySource is a configsource.Source backed by an in-memory
// snapshot. Tests that drive the harness's RunReloadLoop call
// reload(snap) to atomically swap the served snapshot and notify
// any watcher.
//
// The single-buffered updateCh matches the channel discipline used
// by the disk and k8s configsource plugins: a notification is
// dropped if a previous one is still pending so a stuck reader
// cannot wedge writers. Tests calling reload synchronously after
// a previous reload should give the reload loop a chance to drain
// before sending the next update — typically by waiting on the
// observable side-effect of the previous reload before issuing
// the next one.
type inMemorySource struct {
	updateCh chan error

	mu      sync.RWMutex
	snap    config.Snapshot
	closed  bool
	closeCh chan struct{}
}

var _ configsource.Source = (*inMemorySource)(nil)

func newInMemorySource(snap config.Snapshot) *inMemorySource {
	return &inMemorySource{
		snap:     snap,
		updateCh: make(chan error, 1),
		closeCh:  make(chan struct{}),
	}
}

// Current returns the most recently installed snapshot.
func (s *inMemorySource) Current() (config.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap, nil
}

// UpdateChan returns the channel the reload loop reads from.
func (s *inMemorySource) UpdateChan() <-chan error { return s.updateCh }

// Close marks the source closed. Subsequent reload calls become
// no-ops; the reload loop sees a closed UpdateChan and shuts down.
func (s *inMemorySource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.closeCh)
	close(s.updateCh)
	return nil
}

// reload installs snap as the new served snapshot and sends a nil
// update on UpdateChan so the reload loop picks it up. If a prior
// update is still pending the new notification is dropped (matching
// the buffered-1 channel discipline of the production sources); the
// installed snapshot is what Current() returns once the loop drains.
//
// Returns false if the source has been closed.
func (s *inMemorySource) reload(snap config.Snapshot) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.snap = snap
	s.mu.Unlock()
	select {
	case s.updateCh <- nil:
	default:
	}
	return true
}
