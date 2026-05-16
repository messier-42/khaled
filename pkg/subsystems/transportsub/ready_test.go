package transportsub

import (
	"context"
	"net"
	"testing"

	"github.com/messier-42/khaled/pkg/plugin/transport"
)

// fakeTransport is a no-op transport.Transport that does not implement
// BoundAddrer.
type fakeTransport struct {
	addr net.Addr
}

func (f *fakeTransport) Close() error                { return nil }
func (f *fakeTransport) Run(_ context.Context) error { return nil }

// boundFakeTransport additionally implements BoundAddrer.
type boundFakeTransport struct {
	fakeTransport
}

func (b *boundFakeTransport) BoundAddr() net.Addr { return b.addr }

func TestRunningReadyNil(t *testing.T) {
	var r *Running
	if !r.Ready() {
		t.Errorf("nil Running should be ready")
	}
}

func TestRunningReadyEmpty(t *testing.T) {
	if !NewEmpty().Ready() {
		t.Errorf("Running with no transports should be ready")
	}
}

func TestRunningReadyAllBound(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	r := &Running{
		cancel: func() {},
		transports: []transport.Transport{
			&boundFakeTransport{fakeTransport{addr: addr}},
		},
	}
	if !r.Ready() {
		t.Errorf("Running with a bound transport should be ready")
	}
}

func TestRunningReadyUnboundTransport(t *testing.T) {
	r := &Running{
		cancel: func() {},
		transports: []transport.Transport{
			&boundFakeTransport{fakeTransport{addr: nil}},
		},
	}
	if r.Ready() {
		t.Errorf("Running with an unbound (nil BoundAddr) transport should not be ready")
	}
}

func TestRunningReadyNonBoundAddrerAssumedReady(t *testing.T) {
	// A transport that does not implement BoundAddrer cannot be
	// inspected and is assumed ready.
	r := &Running{
		cancel:     func() {},
		transports: []transport.Transport{&fakeTransport{}},
	}
	if !r.Ready() {
		t.Errorf("transport without BoundAddrer should be assumed ready")
	}
}
