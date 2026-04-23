package log

import (
	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config/schema"
)

// RegisterSchema contributes the top-level `logging` block schema to r.
// Called once during registry construction.
//
// Both fields are optional; values are strict lowercase — uppercase
// variants, synonyms like "warning", and any other spelling are rejected
// by the enum. cmd/khaled supplies built-in defaults when the config
// omits these fields.
func RegisterSchema(r *schema.Registry) error {
	return r.RegisterPath("logging", &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"format": {
				Type: "string",
				Enum: []any{"json", "text"},
			},
			"severity": {
				Type: "string",
				Enum: []any{"debug", "info", "warn", "error"},
			},
		},
	})
}
