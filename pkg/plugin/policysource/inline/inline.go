// Package inline provides a policysource.Source whose policy text is
// supplied directly inline inside the server config rather than read
// from a separate file or remote store.
package inline

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/plugin/policysource"
)

// Source is a [policysource.Source] whose Engine is constructed once
// from inline text. UpdateChan never fires, as reloads occur through
// the policy manager rebuilding the source.
type Source struct {
	updateCh chan error

	mu      sync.RWMutex
	current policyengine.Engine
	loadErr error
	closed  bool
}

var _ policysource.Source = &Source{}

// New constructs an inline Source.
func New(ctx context.Context, text []byte, compile policysource.CompileFunc) (*Source, error) {
	if compile == nil {
		return nil, errors.New("policysource/inline: compile is required")
	}

	s := &Source{updateCh: make(chan error)}

	eng, err := compile(ctx, policysource.CompileArgs{Source: text})
	if err != nil {
		s.loadErr = fmt.Errorf("compile inline policy: %w", err)
	} else {
		s.current = eng
	}

	return s, nil
}

// Current returns the precompiled Engine, or the construction error.
func (s *Source) Current() (policyengine.Engine, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.loadErr != nil {
		return nil, s.loadErr
	}

	return s.current, nil
}

// UpdateChan returns a channel that never fires.
func (s *Source) UpdateChan() <-chan error {
	return s.updateCh
}

// Close releases the held Engine. Idempotent.
func (s *Source) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	engine := s.current
	s.current = nil
	s.mu.Unlock()

	if engine != nil {
		return engine.Close()
	}

	return nil
}
