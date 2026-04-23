package tlsca

import (
	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config/schema"
)

// RegisterSchema contributes this plugin's configuration schema to r.
// It is called once during registry construction.
func RegisterSchema(r *schema.Registry) error {
	minOne := 1
	return r.RegisterPluginKind("clientAuthn", "tls-ca", &jsonschema.Schema{
		Type:     "object",
		Required: []string{"caBundlePath"},
		Properties: map[string]*jsonschema.Schema{
			"caBundlePath": {Type: "string", MinLength: &minOne},
		},
	})
}
