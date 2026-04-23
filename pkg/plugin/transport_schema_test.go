package plugin

import (
	"context"
	"strings"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
)

func TestValidateListenersImmutableOnReload_AllowsInitialLoad(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"listeners": config.Array{
			config.Map{"use": "http", "address": ":5000"},
		},
	}}
	// oldConfig = nil on initial load: must not error.
	if err := validateListenersImmutableOnReload(context.Background(), nil, snap); err != nil {
		t.Errorf("initial load rejected: %v", err)
	}
}

func TestValidateListenersImmutableOnReload_AllowsUnchangedReload(t *testing.T) {
	listeners := config.Array{config.Map{"use": "http", "address": ":5000"}}
	old := config.Snapshot{Root: config.Map{"listeners": listeners}}
	// A fresh-but-equal slice should be accepted by DeepEqual.
	newL := config.Array{config.Map{"use": "http", "address": ":5000"}}
	snap := config.Snapshot{Root: config.Map{"listeners": newL}}
	if err := validateListenersImmutableOnReload(context.Background(), &old, snap); err != nil {
		t.Errorf("unchanged reload rejected: %v", err)
	}
}

func TestValidateListenersImmutableOnReload_RejectsAddressChange(t *testing.T) {
	old := config.Snapshot{Root: config.Map{
		"listeners": config.Array{config.Map{"use": "http", "address": ":5000"}},
	}}
	snap := config.Snapshot{Root: config.Map{
		"listeners": config.Array{config.Map{"use": "http", "address": ":6000"}},
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
		"listeners": config.Array{config.Map{"use": "http", "address": ":5000"}},
	}}
	snap := config.Snapshot{Root: config.Map{
		"listeners": config.Array{
			config.Map{"use": "http", "address": ":5000"},
			config.Map{"use": "http", "address": ":5001"},
		},
	}}
	if err := validateListenersImmutableOnReload(context.Background(), &old, snap); err == nil {
		t.Fatal("expected added listener to be rejected on reload")
	}
}
