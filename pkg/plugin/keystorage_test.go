package plugin_test

import (
	"context"
	"testing"

	"github.com/messier-42/khaled/pkg/plugin"
)

func TestNewKeyStorage_UnknownPlugin(t *testing.T) {
	if _, err := plugin.NewKeyStorage(t.Context(), plugin.KeyStorageArgs{PluginName: "bogus"}); err == nil {
		t.Fatalf("expected error for unknown plugin")
	}
}

func TestNewKeyStorage_Disk(t *testing.T) {
	args := plugin.KeyStorageArgs{PluginName: "disk"}
	args.Disk.Path = t.TempDir()

	store, err := plugin.NewKeyStorage(t.Context(), args)
	if err != nil {
		t.Fatalf("NewKeyStorage: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if _, err := store.DomainByName(context.Background(), "default"); err != nil {
		t.Fatalf("Domain(default): %v", err)
	}
}

func TestNewKeyStorage_DiskBadPath(t *testing.T) {
	args := plugin.KeyStorageArgs{PluginName: "disk"}
	args.Disk.Path = "/nonexistent/khaled-keystorage-test"
	if _, err := plugin.NewKeyStorage(t.Context(), args); err == nil {
		t.Fatalf("expected error for nonexistent path")
	}
}
