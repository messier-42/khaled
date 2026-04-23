package tlsspiffe

import "github.com/messier-42/khaled/pkg/config/schema"

// RegisterSchema contributes this plugin's configuration schema to r.
// It is called once during registry construction.
//
// The tls-spiffe plugin has no subblock schema: the trust bundle is
// obtained from the shared SPIFFE Workload API source configured under
// the top-level `spiffe` block.
func RegisterSchema(r *schema.Registry) error {
	return r.RegisterPluginKind("clientAuthn", "tls-spiffe", nil)
}
