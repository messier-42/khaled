package plugin

import (
	"fmt"

	"github.com/messier-42/khaled/pkg/plugin/configsource"
	"github.com/messier-42/khaled/pkg/plugin/configsource/disk"
	"github.com/messier-42/khaled/pkg/plugin/configsource/k8s"
)

// ConfigSourceArgs provides information used to instantiate a config source plugin.
type ConfigSourceArgs struct {
	// The name of the config source plugin to use.
	PluginName string

	// Validate is invoked for every freshly loaded configuration snapshot. It
	// may be nil, in which case no validation is performed.
	Validate configsource.ValidateFunc

	// Config source arguments specific to the disk plugin.
	Disk struct {
		// Path to a YAML or CBOR config file.
		Path string
	}

	// Config source arguments specific to the k8s plugin.
	K8s struct {
		// ConfigMap name or configmap/<NAME> selector.
		Config string

		// Kubernetes namespace containing the ConfigMap.
		Namespace string
	}
}

// NewConfigSource instantiates a config source given the specified arguments.
func NewConfigSource(args ConfigSourceArgs) (configsource.Source, error) {
	switch args.PluginName {
	case "disk":
		return disk.New(args.Disk.Path, args.Validate)
	case "k8s":
		return k8s.New(args.K8s.Config, args.K8s.Namespace, args.Validate)
	default:
		return nil, fmt.Errorf("unsupported config source plugin %q", args.PluginName)
	}
}
