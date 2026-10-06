package http

import (
	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/x509source"
)

const (
	schemaTypeObject = "object"
	schemaTypeString = "string"
)

// ListenerEntrySchema returns the JSON Schema fragment describing a
// single `listeners[]` entry with `use: "http"`. The transport kind
// does not use the `use:` discriminator at the top-level kind slot —
// each listener entry carries its own `use:` — so schemas are surfaced
// per-entry and composed by the transport kind package into a OneOf.
func ListenerEntrySchema() *jsonschema.Schema {
	minOne := 1
	httpUse := any("http")

	tlsBlock := &jsonschema.Schema{
		Type: schemaTypeObject,
		Properties: map[string]*jsonschema.Schema{
			"keylog":            {Type: schemaTypeString},
			"serverCertificate": x509source.Schema(),
		},
	}

	return &jsonschema.Schema{
		Type:     schemaTypeObject,
		Required: []string{"use", "address"},
		Properties: map[string]*jsonschema.Schema{
			"use":     {Const: &httpUse},
			"address": {Type: schemaTypeString, MinLength: &minOne},
			"http": {
				Type: schemaTypeObject,
				Properties: map[string]*jsonschema.Schema{
					"tls": tlsBlock,
					// Graceful-shutdown grace period: how long srv.Shutdown
					// waits for in-flight requests to drain. A Go duration
					// string; time.ParseDuration does the real validation.
					"shutdownGraceTime": {Type: schemaTypeString, MinLength: &minOne},
				},
			},
		},
	}
}
