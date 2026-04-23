// Package disk implements the configsource.Source interface by
// reading a YAML or CBOR config file from the local filesystem and
// reloading it on change via fsnotify.
package disk

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/fsnotify/fsnotify"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin/configsource"
)

// Source loads configuration from a watched local file encoded as YAML or CBOR.
type Source struct {
	path     string
	validate configsource.ValidateFunc
	watcher  *fsnotify.Watcher
	updateCh chan error
	doneCh   chan struct{}

	mu      sync.RWMutex
	current *config.Snapshot
	loadErr error
}

var _ configsource.Source = &Source{}

// New creates a disk-backed config source and starts watching the specified
// file. The validate callback, if non-nil, is invoked for every successful
// parse; see configsource.ValidateFunc for semantics.
func New(path string, validate configsource.ValidateFunc) (*Source, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create filesystem watcher: %w", err)
	}

	source := &Source{
		path:     filepath.Clean(path),
		validate: validate,
		watcher:  watcher,
		updateCh: make(chan error, 1),
		doneCh:   make(chan struct{}),
	}

	source.reload(false)

	dir := filepath.Dir(source.path)
	if err := source.watcher.Add(dir); err != nil {
		_ = source.watcher.Close()
		return nil, fmt.Errorf("watch config directory %q: %w", dir, err)
	}

	go source.watch()
	return source, nil
}

func (s *Source) Current() (config.Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.current != nil {
		return *s.current, nil
	}

	if s.loadErr == nil {
		// New performs the initial reload before returning, so one of current or
		// loadErr must always be set for a constructed Source.
		panic("disk.Source invariant violated: current and loadErr are both nil")
	}

	return config.Snapshot{}, s.loadErr
}

func (s *Source) UpdateChan() <-chan error {
	return s.updateCh
}

func (s *Source) Close() error {
	close(s.doneCh)
	return s.watcher.Close()
}

func (s *Source) watch() {
	for {
		select {
		case <-s.doneCh:
			return
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if s.isRelevantEvent(event) {
				s.reload(true)
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("disk configsource: filesystem watcher error",
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

// Tries to (re)load the configuration. If successful, the configuration
// becomes the new current configuration.
func (s *Source) reload(notify bool) {
	snapshot, err := loadFile(s.path)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err == nil && s.validate != nil {
		if verr := s.validate(context.Background(), s.current, snapshot); verr != nil {
			err = fmt.Errorf("validate config file %q: %w", s.path, verr)
		}
	}

	if err != nil {
		if s.current == nil {
			s.loadErr = err
		}
		if notify {
			s.sendUpdate(err)
		}
		return
	}

	s.loadErr = nil
	s.current = &snapshot

	if notify {
		s.sendUpdate(nil)
	}
}

// Sends a notification on the update channel.
func (s *Source) sendUpdate(err error) {
	select {
	case s.updateCh <- err:
	default:
	}
}

// maxConfigFileSize caps how large the config may be. This value of 1 MiB
// was chosen to match the Kubernetes ConfigMap limit.
const maxConfigFileSize = 1 << 20

func loadFile(path string) (config.Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return config.Snapshot{}, fmt.Errorf("cannot open config file %q: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxConfigFileSize+1))
	if err != nil {
		return config.Snapshot{}, fmt.Errorf("cannot read config file %q: %w", path, err)
	}
	if len(data) > maxConfigFileSize {
		return config.Snapshot{}, fmt.Errorf("config file %q exceeds max size of %d bytes", path, maxConfigFileSize)
	}

	if looksLikeCBOR(data) {
		snapshot, err := configsource.DecodeCBOR(data)
		if err != nil {
			return config.Snapshot{}, fmt.Errorf("cannot decode config file %q as CBOR: %w", path, err)
		}
		return snapshot, nil
	}

	snapshot, err := configsource.DecodeYAML(data)
	if err != nil {
		return config.Snapshot{}, fmt.Errorf("cannot decode config file %q as YAML: %w", path, err)
	}
	return snapshot, nil
}

// looksLikeCBOR decides whether data should be routed to the CBOR
// decoder rather than the YAML one. A CBOR config must be a map at
// the top level.
func looksLikeCBOR(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// CBOR Map
	if data[0]>>5 == 0b101 {
		return true
	}

	// Tagged CBOR
	if len(data) >= 3 && data[0] == 0xD9 && data[1] == 0xD9 && data[2] == 0xF7 {
		return true
	}

	return false
}
