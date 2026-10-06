package x509source

import "github.com/google/jsonschema-go/jsonschema"

const (
	sourceProperty   = "source"
	schemaTypeString = "string"
)

// Schema returns the JSON Schema fragment describing the
// standard serverCertificate block. Callers merge this into
// their own schema at whatever path embeds the block (e.g.
// listeners[].http.tls.serverCertificate).
//
// When source=file, certificateFilePath and keyFilePath are
// required. This is enforced at schema level via an if/then clause
// rather than only at runtime inside newFileSource, so a
// misconfigured deployment is rejected at config load time before
// any listener starts.
func Schema() *jsonschema.Schema {
	fileSrcConst := any(string(KindFile))
	return &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			sourceProperty: {
				Type: schemaTypeString,
				Enum: []any{string(KindFile), string(KindSPIFFE)},
			},
			"certificateFilePath":    {Type: schemaTypeString},
			"keyFilePath":            {Type: schemaTypeString},
			"clientTrustAnchorsPath": {Type: schemaTypeString},
		},
		AllOf: []*jsonschema.Schema{
			{
				If: &jsonschema.Schema{
					Properties: map[string]*jsonschema.Schema{
						sourceProperty: {Const: &fileSrcConst},
					},
					Required: []string{sourceProperty},
				},
				Then: &jsonschema.Schema{
					Required: []string{"certificateFilePath", "keyFilePath"},
				},
			},
		},
	}
}
