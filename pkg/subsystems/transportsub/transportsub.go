// Package transportsub provides the listener/transport subsystem.
//
// New instantiates one Transport per listeners[] entry in the
// config snapshot, runs each in its own goroutine, and returns a
// Running handle that tracks them. Stop cancels the run context,
// closes every transport, waits for goroutines to exit, and returns
// the combined errors.
//
// Currently, Listener changes require a service restart.
package transportsub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/transport"
)

// BoundAddrer is the optional accessor a Transport implementation can
// satisfy to expose its bound listener address. The HTTP transport
// implements it; tests need this to discover the port chosen when
// address is "127.0.0.1:0".
type BoundAddrer interface {
	BoundAddr() net.Addr
}

// New instantiates and runs one Transport per listeners[] entry in
// snap. Each transport runs in its own goroutine. Returns a handle
// whose Stop method shuts every transport down and reports the first
// error encountered.
//
// If any transport fails to construct, all already-constructed
// transports are closed before returning.
func New(ctx context.Context, snap config.Snapshot, deps plugin.TransportDeps) (*Running, error) {
	listeners, _ := snap.Root.GetArray("listeners")

	var built []transport.Transport
	for i, entry := range listeners {
		obj, ok := entry.(config.Map)
		if !ok {
			closeAll(built)
			return nil, fmt.Errorf("listeners[%d]: not an object", i)
		}
		tr, err := plugin.NewTransport(ctx, obj, snap.Root, deps)
		if err != nil {
			closeAll(built)
			return nil, fmt.Errorf("listeners[%d]: %w", i, err)
		}
		built = append(built, tr)
	}

	runCtx, cancel := context.WithCancel(ctx)
	rt := &Running{
		cancel:     cancel,
		transports: built,
	}

	rt.wg.Add(len(built))
	for _, tr := range built {
		go func(tr transport.Transport) {
			defer rt.wg.Done()
			if err := tr.Run(runCtx); err != nil {
				slog.Error("transport stopped with error", "error", err)
				rt.recordErr(err)
			}
		}(tr)
	}

	return rt, nil
}

// NewEmpty returns a Running with no transports. Used for testing.
func NewEmpty() *Running {
	return &Running{cancel: func() {}}
}

// Running tracks the set of live transports started by New.
type Running struct {
	cancel     context.CancelFunc
	transports []transport.Transport
	wg         sync.WaitGroup

	mu      sync.Mutex
	runErrs []error
}

// Stop cancels the run context of each transport, closes every transport,
// waits for each transport's goroutines to exit, and returns the combined
// run-time and close-time errors.
func (r *Running) Stop() error {
	if r == nil {
		return nil
	}
	r.cancel()
	var closeErrs []error
	for _, tr := range r.transports {
		if err := tr.Close(); err != nil {
			closeErrs = append(closeErrs, err)
		}
	}
	r.wg.Wait()

	r.mu.Lock()
	defer r.mu.Unlock()
	all := append([]error(nil), r.runErrs...)
	all = append(all, closeErrs...)
	return errors.Join(all...)
}

func (r *Running) recordErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runErrs = append(r.runErrs, err)
}

// Addresses returns the bound listener address of each running
// transport that implements BoundAddrer, in the order the listeners
// were started. Transports that do not expose an address are skipped.
// The returned slice is empty if Stop has already run or no
// transports were started.
func (r *Running) Addresses() []net.Addr {
	if r == nil {
		return nil
	}
	addrs := make([]net.Addr, 0, len(r.transports))
	for _, t := range r.transports {
		ba, ok := t.(BoundAddrer)
		if !ok {
			continue
		}
		if a := ba.BoundAddr(); a != nil {
			addrs = append(addrs, a)
		}
	}
	return addrs
}

func closeAll(ts []transport.Transport) {
	for _, t := range ts {
		_ = t.Close()
	}
}
