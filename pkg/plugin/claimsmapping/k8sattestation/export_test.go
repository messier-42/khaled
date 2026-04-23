package k8sattestation

import (
	"time"

	"k8s.io/client-go/kubernetes"
)

// NewWithClock is a test-only constructor that injects a shared clock
// into both the Mapper and its internal TTL cache. Production code
// goes through NewWithClient, which pins the clock to time.Now.
func NewWithClock(client kubernetes.Interface, cfg Config, clock func() time.Time) *Mapper {
	cfg = cfg.withDefaults()
	return newWithClock(client, cfg, clock)
}
