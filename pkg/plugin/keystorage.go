package plugin

import (
	"context"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config/schema"
	"github.com/messier-42/khaled/pkg/plugin/keystorage"
	"github.com/messier-42/khaled/pkg/plugin/keystorage/disk"
)

// KeyStorageArgs provides information used to instantiate a key
// storage plugin.
type KeyStorageArgs struct {
	// The name of the key storage plugin to use.
	PluginName string

	// Key storage arguments specific to the disk plugin.
	Disk struct {
		// Path to a directory holding the SQLite database. The
		// directory must exist and be writable; the database file is
		// created on first use.
		Path string
	}
}

// NewKeyStorage instantiates a key storage plugin given the specified
// arguments.
func NewKeyStorage(ctx context.Context, args KeyStorageArgs) (keystorage.KeyStore, error) {
	switch args.PluginName {
	case "disk":
		return disk.New(ctx, args.Disk.Path)
	default:
		return nil, fmt.Errorf("unsupported key storage plugin %q", args.PluginName)
	}
}

// RegisterKeyStorageSchemas contributes every key storage plugin's schema
// plus the common runtime settings that apply regardless of which
// plugin is selected via `use`.
func RegisterKeyStorageSchemas(r *schema.Registry) error {
	minOne := 1
	commons := []struct {
		name   string
		schema *jsonschema.Schema
	}{
		{"domainName", &jsonschema.Schema{Type: "string", MinLength: &minOne}},
		{"rootRotationInterval", &jsonschema.Schema{Type: "string", MinLength: &minOne}},
		{"leaseDuration", &jsonschema.Schema{Type: "string", MinLength: &minOne}},
	}
	for _, c := range commons {
		if err := r.RegisterPluginKindCommon("keyStorage", c.name, c.schema); err != nil {
			return err
		}
	}
	return disk.RegisterSchema(r)
}
