package spiffesub

import (
	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config/schema"
)

// RegisterSchema contributes the top-level `spiffe` block schema to r.
// Called once during registry construction.
func RegisterSchema(r *schema.Registry) error {
	return r.RegisterPath("spiffe", &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"workloadSocketPath": {Type: "string"},
		},
	})
}
