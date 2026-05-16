package server

import (
	"github.com/messier-42/khaled/pkg/config/schema"
	klog "github.com/messier-42/khaled/pkg/log"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/subsystems/monitoringsub"
	"github.com/messier-42/khaled/pkg/subsystems/spiffesub"
)

// BuildRegistry constructs the khaled configuration schema registry,
// populates it by dispatching to each plugin kind's and each top-level
// block owner's RegisterSchema(s) function, and freezes the registry via
// Build. Schema fragments, common properties, and custom validators
// all live alongside the code they describe, and are aggregated
// into one here.
func BuildRegistry() (*schema.Registry, error) {
	r := schema.New()

	contributors := []func(*schema.Registry) error{
		plugin.RegisterKeyStorageSchemas,
		plugin.RegisterPolicyEngineSchemas,
		plugin.RegisterPolicySourceSchemas,
		plugin.RegisterClientAuthnSchemas,
		plugin.RegisterClaimsMappingSchemas,
		plugin.RegisterTransportSchemas,
		spiffesub.RegisterSchema,
		monitoringsub.RegisterSchema,
		klog.RegisterSchema,
	}
	for _, fn := range contributors {
		if err := fn(r); err != nil {
			return nil, err
		}
	}

	if _, err := r.Build(); err != nil {
		return nil, err
	}
	return r, nil
}
