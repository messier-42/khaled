package k8sattestation

import (
	"context"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/config/schema"
)

// RegisterSchema contributes this plugin's configuration schema and
// cross-block semantic validator to r. Called once during registry
// construction.
//
// The k8s-attestation plugin has no required subblock — every cache knob
// has a built-in default. When present, cache fields are validated
// structurally here; semantic validation (e.g. parseable duration strings)
// happens in the plugin constructor.
func RegisterSchema(r *schema.Registry) error {
	minOne := 1
	zero := 0.0
	if err := r.RegisterPluginKind("claimsMapping", "k8s-attestation", &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"cache": {
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"ttl":         {Type: "string", MinLength: &minOne},
					"negativeTTL": {Type: "string", MinLength: &minOne},
					"maxEntries":  {Type: "integer", Minimum: &zero},
				},
			},
		},
	}); err != nil {
		return err
	}
	return r.RegisterValidator(validateRequiresTLSSpiffe)
}

// validateRequiresTLSSpiffe catches the "mapper needs a SPIFFEIdentity
// but authenticator does not produce one" case at config-load time.
// Without this, the mismatch would only surface per-request as an
// HTTP 500 once requests start flowing.
//
// The schema cannot express this cross-block constraint directly.
func validateRequiresTLSSpiffe(_ context.Context, _ *config.Snapshot, snap config.Snapshot) error {
	cm, ok := snap.Root.GetMap("claimsMapping")
	if !ok {
		return nil
	}
	use, _ := cm.GetString("use")
	if use != "k8s-attestation" {
		return nil
	}
	ca, _ := snap.Root.GetMap("clientAuthn")
	authUse, _ := ca.GetString("use")
	if authUse != "tls-spiffe" {
		return fmt.Errorf("claimsMapping.use=k8s-attestation requires clientAuthn.use=tls-spiffe (got %q)", authUse)
	}
	return nil
}
