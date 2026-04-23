// Package file provides a file-based policy source with watcher-powered
// auto-reloading.
//
// The file at a given path is read, compiled via an injected CompileFunc,
// and served as the current Engine. Changes to the file trigger a reload;
// failed reloads leave the previous Engine in place.
//
// This source is engine-agnostic: the CompileFunc is supplied at
// construction and can target any concrete policy engine. The caller
// (typically pkg/plugin.NewPolicySource) chooses the CompileFunc based
// on the configured engine.
package file

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"

	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/plugin/policysource"
)

// Source is a policysource.Source backed by a single watched file.
type Source struct {
	path    string
	compile policysource.CompileFunc
	watcher *fsnotify.Watcher

	updateCh chan error
	doneCh   chan struct{}
	// watchWG tracks the background watch goroutine so Close can
	// wait for it to exit. Without this, a caller that cleans up
	// shared state (e.g. deletes the watched directory) immediately
	// after Close returns would race against a final reload().
	watchWG sync.WaitGroup

	mu      sync.RWMutex
	current policyengine.Engine
	loadErr error
	closed  bool
}

var _ policysource.Source = &Source{}

// New constructs a file-backed, auto-reloading Source. The initial load runs
// synchronously and the result (whether success or failure) is stored.
// If the initial load was successful, Current() returns the constructed
// Engine; if the initial load failed, Current() will return the error.
//
// New itself returns an error only if the filesystem watcher cannot be created.
// ctx scopes the initial synchronous reload's compile call; after construction,
// reloads use a context tied to the Source's lifecycle (cancelled by Close).
func New(ctx context.Context, path string, compile policysource.CompileFunc) (*Source, error) {
	if compile == nil {
		return nil, errors.New("policysource/file: compile is required")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create filesystem watcher: %w", err)
	}

	s := &Source{
		path:     filepath.Clean(path),
		compile:  compile,
		watcher:  watcher,
		updateCh: make(chan error, 1),
		doneCh:   make(chan struct{}),
	}

	s.reload(ctx, false)

	dir := filepath.Dir(s.path)
	if err := s.watcher.Add(dir); err != nil {
		_ = s.watcher.Close()
		return nil, fmt.Errorf("watch policy directory %q: %w", dir, err)
	}

	s.watchWG.Add(1)
	go s.watch(ctx)
	return s, nil
}

// Current returns the current Engine or the error that occurred during the
// initial load attempt. Once a (re)load has succeeded at least once, the
// last good Engine is retained and Current returns it.
func (s *Source) Current() (policyengine.Engine, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.current != nil {
		return s.current, nil
	}

	if s.loadErr == nil {
		// New performs the initial reload before returning, so one of
		// current or loadErr must always be set for a constructed Source.
		panic("policysource/file: invariant violated: current and loadErr are both nil")
	}

	return nil, s.loadErr
}

// UpdateChan returns the reload notification channel. See [policysource.Source].
func (s *Source) UpdateChan() <-chan error {
	return s.updateCh
}

// Close stops the filesystem watcher and releases resources. Idempotent.
// Blocks until teardown is complete.
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

	// Close doneCh first so any in-flight reload can observe
	// cancellation via the compile context and return. Then close
	// the watcher to wake and terminate the goroutine.
	close(s.doneCh)
	werr := s.watcher.Close()
	s.watchWG.Wait()

	var cerr error
	if engine != nil {
		cerr = engine.Close()
	}

	switch {
	case werr != nil:
		return werr
	default:
		return cerr
	}
}

func (s *Source) watch(ctx context.Context) {
	defer s.watchWG.Done()
	for {
		select {
		case <-s.doneCh:
			return
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if s.isRelevantEvent(event) {
				s.reload(ctx, true)
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("file policysource: filesystem watcher error",
				"path", s.path,
				"error", err,
			)
		}
	}
}

func (s *Source) isRelevantEvent(event fsnotify.Event) bool {
	if event.Name != s.path {
		return false
	}
	return event.Has(fsnotify.Create) ||
		event.Has(fsnotify.Write) ||
		event.Has(fsnotify.Rename) ||
		event.Has(fsnotify.Remove)
}

// reload reads the file, compiles it, and installs the resulting Engine.
// On failure, the previous Engine is retained.
func (s *Source) reload(ctx context.Context, notify bool) {
	engine, err := s.buildEngine(ctx)

	s.mu.Lock()
	old := s.current
	if err != nil {
		if s.current == nil {
			s.loadErr = err
		}
		s.mu.Unlock()
		if notify {
			s.sendUpdate(err)
		}
		return
	}

	s.loadErr = nil
	s.current = engine
	s.mu.Unlock()

	// Close the superseded Engine outside the lock so a slow Close()
	// does not block concurrent Current() callers.
	if old != nil {
		old.Close() // best effort
	}

	if notify {
		s.sendUpdate(nil)
	}
}

func (s *Source) buildEngine(parent context.Context) (policyengine.Engine, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("read policy file %q: %w", s.path, err)
	}

	// Pass a context tied both to the caller and to the Source's
	// lifecycle so a slow CompileFunc unblocks on either cancellation.
	ctx, cancel := s.newLifecycleContext(parent)
	defer cancel()

	engine, err := s.compile(ctx, policysource.CompileArgs{Source: data})
	if err != nil {
		return nil, fmt.Errorf("compile policy file %q: %w", s.path, err)
	}

	return engine, nil
}

// newLifecycleContext returns a context that is cancelled when the
// Source is closed or when the parent context is cancelled. The
// caller must invoke the returned cancel to release the watcher
// goroutine.
func (s *Source) newLifecycleContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-s.doneCh:
			cancel()
		case <-stopped:
		}
	}()
	return ctx, func() {
		close(stopped)
		cancel()
	}
}

func (s *Source) sendUpdate(err error) {
	select {
	case s.updateCh <- err:
	default:
	}
}
