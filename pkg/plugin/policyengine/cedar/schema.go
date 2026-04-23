package cedar

import "github.com/messier-42/khaled/pkg/config/schema"

// RegisterSchema contributes this plugin's configuration schema to r.
// It is called once during registry construction.
//
// The cedar engine currently has no subblock schema; policy source text
// is supplied through a separate policySource plugin.
func RegisterSchema(r *schema.Registry) error {
	return r.RegisterPluginKind("policyEngine", "cedar", nil)
}
