package monitoringsub

import (
	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config/schema"
)

// RegisterSchema contributes the top-level `monitoring` block schema to
// r. Called once during registry construction.
//
// Both fields are optional. The monitoring listener is enabled by a
// non-empty `address`; an empty (or omitted) address disables it
// entirely. shutdownWarningTime is a Go duration string;
// time.ParseDuration does the real validation when the block is read.
func RegisterSchema(r *schema.Registry) error {
	return r.RegisterPath("monitoring", &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"address":             {Type: "string"},
			"shutdownWarningTime": {Type: "string"},
		},
	})
}
