package log

import (
	"encoding/json"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config/schema"
)

const (
	schemaTypeString  = "string"
	schemaTypeBoolean = "boolean"
)

// RegisterSchema contributes the top-level `logging` block schema to r.
// Called once during registry construction.
//
// All fields are optional. Format and severity are strict lowercase — uppercase
// variants, synonyms like "warning", and any other spelling are rejected
// by the enum. cmd/khaled supplies built-in defaults when the config
// omits these fields.
func RegisterSchema(r *schema.Registry) error {
	return r.RegisterPath("logging", &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"audit": {
				Type:                 "object",
				AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}},
				Properties: map[string]*jsonschema.Schema{
					auditPrincipalClaims: {Type: "array", Default: json.RawMessage("[]"), Items: &jsonschema.Schema{Type: schemaTypeString, MinLength: new(1)}},
					"clientIP":           {Type: schemaTypeBoolean, Default: json.RawMessage("false")},
					"fullAttributeSet":   {Type: schemaTypeBoolean, Default: json.RawMessage("false")},
					"policyHashes":       {Type: schemaTypeBoolean, Default: json.RawMessage("false")},
					"diagnostics":        {Type: schemaTypeBoolean, Default: json.RawMessage("false")},
				},
			},
			"format": {
				Type: schemaTypeString,
				Enum: []any{"json", "text"},
			},
			"severity": {
				Type: schemaTypeString,
				Enum: []any{"debug", "info", "warn", "error"},
			},
		},
	})
}
