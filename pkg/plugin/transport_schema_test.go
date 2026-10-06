package plugin

import (
	"context"
	"strings"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
)

const (
	pluginSelector    = "use"
	httpTransportName = "http"
	addressKey        = "address"
	testListenAddress = ":5000"
	listenersKey      = "listeners"
)

func TestValidateListenersImmutableOnReload_AllowsInitialLoad(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		listenersKey: config.Array{
			config.Map{pluginSelector: httpTransportName, addressKey: testListenAddress},
		},
	}}
	// oldConfig = nil on initial load: must not error.
	if err := validateListenersImmutableOnReload(context.Background(), nil, snap); err != nil {
		t.Errorf("initial load rejected: %v", err)
	}
}

func TestValidateListenersImmutableOnReload_AllowsUnchangedReload(t *testing.T) {
	listeners := config.Array{config.Map{pluginSelector: httpTransportName, addressKey: testListenAddress}}
	old := config.Snapshot{Root: config.Map{listenersKey: listeners}}
	// A fresh-but-equal slice should be accepted by DeepEqual.
	newL := config.Array{config.Map{pluginSelector: httpTransportName, addressKey: testListenAddress}}
	snap := config.Snapshot{Root: config.Map{listenersKey: newL}}
	if err := validateListenersImmutableOnReload(context.Background(), &old, snap); err != nil {
		t.Errorf("unchanged reload rejected: %v", err)
	}
}

func TestValidateListenersImmutableOnReload_RejectsAddressChange(t *testing.T) {
	old := config.Snapshot{Root: config.Map{
		listenersKey: config.Array{config.Map{pluginSelector: httpTransportName, addressKey: testListenAddress}},
	}}
	snap := config.Snapshot{Root: config.Map{
		listenersKey: config.Array{config.Map{pluginSelector: httpTransportName, addressKey: ":6000"}},
	}}
	err := validateListenersImmutableOnReload(context.Background(), &old, snap)
	if err == nil {
		t.Fatal("expected listener address change to be rejected on reload")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Errorf("error does not mention immutability: %v", err)
	}
}

func TestValidateListenersImmutableOnReload_RejectsAddedListener(t *testing.T) {
	old := config.Snapshot{Root: config.Map{
		listenersKey: config.Array{config.Map{pluginSelector: httpTransportName, addressKey: testListenAddress}},
	}}
	snap := config.Snapshot{Root: config.Map{
		listenersKey: config.Array{
			config.Map{pluginSelector: httpTransportName, addressKey: testListenAddress},
			config.Map{pluginSelector: httpTransportName, addressKey: ":5001"},
		},
	}}
	if err := validateListenersImmutableOnReload(context.Background(), &old, snap); err == nil {
		t.Fatal("expected added listener to be rejected on reload")
	}
}
