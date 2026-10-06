package federation

import (
	"testing"

	"github.com/messier-42/khaled/pkg/config"
)

func TestConfigDefaultsAndInvalid(t *testing.T) {
	c, err := ConfigFromSnapshot(config.Snapshot{Root: config.Map{"federation": config.Map{domainIDField: "origin"}}})
	if err != nil || c == nil || c.DomainID != "origin" || c.CacheBytes != 8<<20 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	for _, block := range []config.Map{{}, {domainIDField: "o", "curve": "X25519"}, {domainIDField: "o", "cacheBytes": int64(-1)}, {domainIDField: "o", cacheTTLField: "-1s"}, {domainIDField: "o", "unknown": true}, {domainIDField: "o", "peers": config.Array{config.Map{domainIDField: "p", "identity": "invalid"}}}} {
		if _, err := ConfigFromSnapshot(config.Snapshot{Root: config.Map{"federation": block}}); err == nil {
			t.Fatalf("accepted %+v", block)
		}
	}
}
