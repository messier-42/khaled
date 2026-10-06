package server

import (
	"context"
	"io"
	stdhttp "net/http"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/subsystems/keyserversub"
	"github.com/messier-42/khaled/pkg/subsystems/monitoringsub"
	"github.com/messier-42/khaled/pkg/subsystems/spiffesub"
	"github.com/messier-42/khaled/pkg/subsystems/transportsub"
)

// newTestServerWithMonitoring builds a Server with empty subsystem
// handles and a real monitoring listener bound to a kernel-assigned
// port with the given shutdown-warning time.
func newTestServerWithMonitoring(t *testing.T, swt time.Duration) *Server {
	t.Helper()
	s := &Server{}
	s.spiffeSrc.Store(spiffesub.NewEmpty())
	s.transports.Store(transportsub.NewEmpty())
	s.keyserverMgr.Store(keyserversub.NewEmpty())

	mon, err := monitoringsub.New(context.Background(),
		monitoringsub.Config{Address: "127.0.0.1:0", ShutdownWarningTime: swt},
		s.readyFunc)
	if err != nil {
		t.Fatalf("monitoringsub.New: %v", err)
	}
	s.monitoring = mon
	return s
}

func readyzStatus(t *testing.T, base string) int {
	t.Helper()
	req, err := stdhttp.NewRequestWithContext(t.Context(), stdhttp.MethodGet, base+"/readyz", nil)
	if err != nil {
		t.Fatalf("create GET /readyz: %v", err)
	}
	resp, err := stdhttp.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close /readyz response: %v", err)
		}
	}()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestStopFlipsReadyzBeforeWarningSleep verifies the shutdown ordering:
// /readyz reports 503 during the Shutdown Warning Time while the
// monitoring listener is still serving, and only afterwards is the
// listener torn down.
func TestStopFlipsReadyzBeforeWarningSleep(t *testing.T) {
	const swt = 400 * time.Millisecond
	s := newTestServerWithMonitoring(t, swt)
	base := "http://" + s.monitoring.BoundAddr().String()

	// Empty subsystems => not ready, but not 503-by-shutdown.
	if got := readyzStatus(t, base); got != stdhttp.StatusServiceUnavailable {
		t.Fatalf("pre-stop /readyz = %d, want 503 (empty subsystems)", got)
	}

	stopped := make(chan struct{})
	go func() {
		_ = s.Stop()
		close(stopped)
	}()

	// During the warning window the listener must still answer, and
	// shuttingDown must already be set.
	time.Sleep(swt / 2)
	select {
	case <-stopped:
		t.Fatal("Stop returned before the shutdown warning time elapsed")
	default:
	}
	if !s.shuttingDown.Load() {
		t.Error("shuttingDown should be set during the warning window")
	}
	if got := readyzStatus(t, base); got != stdhttp.StatusServiceUnavailable {
		t.Errorf("/readyz during warning window = %d, want 503", got)
	}

	<-stopped

	// After Stop, the listener is closed.
	req, err := stdhttp.NewRequestWithContext(t.Context(), stdhttp.MethodGet, base+"/readyz", nil)
	if err != nil {
		t.Fatalf("create GET /readyz: %v", err)
	}
	if resp, err := stdhttp.DefaultClient.Do(req); err == nil {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close /readyz response: %v", err)
		}
		t.Error("monitoring listener should be closed after Stop")
	}
}

// TestStopSkipsWarningWhenNoMonitoring verifies that with no monitoring
// listener the Shutdown Warning Time is not waited out.
func TestStopSkipsWarningWhenNoMonitoring(t *testing.T) {
	s := &Server{}
	s.spiffeSrc.Store(spiffesub.NewEmpty())
	s.transports.Store(transportsub.NewEmpty())
	s.keyserverMgr.Store(keyserversub.NewEmpty())
	// monitoring left as a disabled handle.
	mon, err := monitoringsub.New(context.Background(), monitoringsub.Config{}, nil)
	if err != nil {
		t.Fatalf("monitoringsub.New: %v", err)
	}
	s.monitoring = mon

	start := time.Now()
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("Stop took %v; warning period should be skipped with no listener", elapsed)
	}
}
