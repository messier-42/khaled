package monitoringsub_test

import (
	"context"
	"io"
	stdhttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/health"
	"github.com/messier-42/khaled/pkg/subsystems/monitoringsub"
)

// startTest brings up a monitoring listener on a kernel-assigned port
// and returns its base URL. The listener is stopped via t.Cleanup.
func startTest(t *testing.T, readyFunc monitoringsub.ReadyFunc) string {
	t.Helper()
	r, err := monitoringsub.New(context.Background(),
		monitoringsub.Config{Address: "127.0.0.1:0"}, readyFunc)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = r.Stop() })

	addr := r.BoundAddr()
	if addr == nil {
		t.Fatal("BoundAddr returned nil for an enabled listener")
	}
	return "http://" + addr.String()
}

// get performs a GET and returns status code and body.
func get(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := stdhttp.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func allOK() []health.CheckResult {
	return []health.CheckResult{{Name: "keyserver", OK: true}}
}

func TestDisabledWhenAddressEmpty(t *testing.T) {
	r, err := monitoringsub.New(context.Background(), monitoringsub.Config{}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = r.Stop() }()

	if r.Active() {
		t.Errorf("empty address should yield an inactive listener")
	}
	if r.BoundAddr() != nil {
		t.Errorf("disabled listener should have no bound address")
	}
}

func TestEnabledRequiresReadyFunc(t *testing.T) {
	if _, err := monitoringsub.New(context.Background(),
		monitoringsub.Config{Address: "127.0.0.1:0"}, nil); err == nil {
		t.Fatalf("expected error: enabled listener without readyFunc")
	}
}

func TestLivezAlwaysOK(t *testing.T) {
	base := startTest(t, func() []health.CheckResult {
		// Even with a failing readiness check, /livez stays 200.
		return []health.CheckResult{{Name: "x", OK: false}}
	})
	status, body := get(t, base+"/livez")
	if status != stdhttp.StatusOK {
		t.Errorf("/livez status = %d, want 200", status)
	}
	if body != "ok\n" {
		t.Errorf("/livez body = %q", body)
	}
}

func TestReadyzPasses(t *testing.T) {
	base := startTest(t, allOK)
	status, body := get(t, base+"/readyz")
	if status != stdhttp.StatusOK {
		t.Errorf("/readyz status = %d, want 200", status)
	}
	if body != "ok\n" {
		t.Errorf("/readyz body = %q", body)
	}
}

func TestReadyzFails503(t *testing.T) {
	base := startTest(t, func() []health.CheckResult {
		return []health.CheckResult{
			{Name: "keyserver", OK: true},
			{Name: "tls-cert", OK: false, Detail: "no certificate yet"},
		}
	})
	status, body := get(t, base+"/readyz")
	if status != stdhttp.StatusServiceUnavailable {
		t.Errorf("/readyz status = %d, want 503", status)
	}
	if body != "not ready\n" {
		t.Errorf("/readyz body = %q", body)
	}
}

func TestReadyzVerbose(t *testing.T) {
	base := startTest(t, func() []health.CheckResult {
		return []health.CheckResult{
			{Name: "keyserver", OK: true},
			{Name: "tls-cert", OK: false, Detail: "no certificate yet"},
		}
	})
	status, body := get(t, base+"/readyz?verbose")
	if status != stdhttp.StatusServiceUnavailable {
		t.Errorf("/readyz?verbose status = %d, want 503", status)
	}
	for _, want := range []string{
		"[+] keyserver ok\n",
		"[-] tls-cert failed: no certificate yet\n",
		"readyz check failed\n",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/readyz?verbose body missing %q\ngot:\n%s", want, body)
		}
	}
}

func TestNonGetIs405(t *testing.T) {
	base := startTest(t, allOK)
	for _, path := range []string{"/livez", "/readyz"} {
		resp, err := stdhttp.Post(base+path, "text/plain", strings.NewReader(""))
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != stdhttp.StatusMethodNotAllowed {
			t.Errorf("POST %s status = %d, want 405", path, resp.StatusCode)
		}
	}
}

func TestUnknownPathIs404(t *testing.T) {
	base := startTest(t, allOK)
	status, _ := get(t, base+"/nope")
	if status != stdhttp.StatusNotFound {
		t.Errorf("/nope status = %d, want 404", status)
	}
}

func TestStopIdempotent(t *testing.T) {
	r, err := monitoringsub.New(context.Background(),
		monitoringsub.Config{Address: "127.0.0.1:0"}, allOK)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Errorf("first Stop: %v", err)
	}
	if err := r.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

func TestConfigFromSnapshot(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"monitoring": config.Map{
			"address":             "0.0.0.0:8081",
			"shutdownWarningTime": "5s",
		},
	}}
	cfg, err := monitoringsub.ConfigFromSnapshot(snap)
	if err != nil {
		t.Fatalf("ConfigFromSnapshot: %v", err)
	}
	if cfg.Address != "0.0.0.0:8081" {
		t.Errorf("Address = %q", cfg.Address)
	}
	if cfg.ShutdownWarningTime != 5*time.Second {
		t.Errorf("ShutdownWarningTime = %v, want 5s", cfg.ShutdownWarningTime)
	}
}

func TestConfigFromSnapshotEmptyBlock(t *testing.T) {
	// An absent or empty monitoring block disables the listener and
	// is not an error.
	cfg, err := monitoringsub.ConfigFromSnapshot(config.Snapshot{Root: config.Map{}})
	if err != nil {
		t.Fatalf("ConfigFromSnapshot: %v", err)
	}
	if cfg.Address != "" {
		t.Errorf("Address = %q, want empty", cfg.Address)
	}
}

func TestConfigFromSnapshotRejectsBadDuration(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"monitoring": config.Map{"shutdownWarningTime": "five-seconds"},
	}}
	if _, err := monitoringsub.ConfigFromSnapshot(snap); err == nil {
		t.Fatalf("expected bad shutdownWarningTime to fail")
	}
}
