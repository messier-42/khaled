package static

import (
	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config/schema"
)

// RegisterSchema contributes this plugin's configuration schema to r.
// It is called once during registry construction.
func RegisterSchema(r *schema.Registry) error {
	minOne := 1
	return r.RegisterPluginKind("claimsMapping", "static", &jsonschema.Schema{
		Type:     "object",
		Required: []string{"principals"},
		Properties: map[string]*jsonschema.Schema{
			"principals": {
				Type: "array",
				Items: &jsonschema.Schema{
					Type:     "object",
					Required: []string{"uri", "claims"},
					Properties: map[string]*jsonschema.Schema{
						"uri": {Type: "string", MinLength: &minOne},
						"claims": {
							Type: "object",
							AdditionalProperties: &jsonschema.Schema{
								Type: "string",
							},
						},
					},
				},
			},
		},
	})
}
