package inline

import (
	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config/schema"
)

// RegisterSchema contributes this plugin's configuration schema to r.
// It is called once during registry construction.
//
// Policy text is embedded in the config snapshot itself — no separate
// file or remote store. Reload happens whenever the configsource reports
// a snapshot change (the policyManager sees the new Inline.Text and
// rebuilds the runtime), so reload latency is whatever the active
// configsource provides — for the k8s configsource that's ~1 second;
// for the file configsource it's the inotify event delay.
func RegisterSchema(r *schema.Registry) error {
	minOne := 1
	return r.RegisterPluginKind("policySource", "inline", &jsonschema.Schema{
		Type:     "object",
		Required: []string{"text"},
		Properties: map[string]*jsonschema.Schema{
			"text": {Type: "string", MinLength: &minOne},
		},
	})
}
