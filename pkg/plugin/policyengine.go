package plugin

import (
	"fmt"

	"github.com/messier-42/khaled/pkg/config/schema"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/plugin/policyengine/cedar"
)

// PolicyEngineArgs provides information used to instantiate a policy engine
// plugin.
type PolicyEngineArgs struct {
	// The name of the policy engine plugin to use.
	PluginName string

	// Policy engine arguments specific to the cedar plugin.
	Cedar struct {
		// Cedar policy source text (UTF-8).
		PolicyText []byte
	}
}

// NewPolicyEngine instantiates a policy engine given the specified arguments.
func NewPolicyEngine(args PolicyEngineArgs) (policyengine.Engine, error) {
	switch args.PluginName {
	case "cedar":
		return cedar.New(cedar.Config{
			PolicyText: args.Cedar.PolicyText,
		})
	default:
		return nil, fmt.Errorf("unsupported policy engine plugin %q", args.PluginName)
	}
}

// RegisterPolicyEngineSchemas contributes every policy engine plugin's schema.
func RegisterPolicyEngineSchemas(r *schema.Registry) error {
	return cedar.RegisterSchema(r)
}
