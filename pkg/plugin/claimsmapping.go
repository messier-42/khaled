package plugin

import (
	"context"

	"github.com/messier-42/khaled/pkg/config/schema"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping/k8sattestation"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping/static"
)

// ClaimsMapperArgs provides the inputs used to instantiate a Claims
// Mapping plugin.
type ClaimsMapperArgs struct {
	// PluginName is the name of the plugin to use ("static" or
	// "k8s-attestation" today).
	PluginName string

	// Static holds the static mapper's configuration.
	Static struct {
		Principals []static.PrincipalConfig
	}

	// K8sAttestation holds the k8s-attestation mapper's cache
	// configuration. Zero-valued fields take built-in defaults.
	K8sAttestation k8sattestation.Config
}

var claimsMappingFactory = func() *Factory[ClaimsMapperArgs, claimsmapping.ClaimsMapper] {
	f := NewFactory[ClaimsMapperArgs, claimsmapping.ClaimsMapper]("claims mapping")
	f.Register("static",
		func(_ context.Context, a ClaimsMapperArgs) (claimsmapping.ClaimsMapper, error) {
			return static.New(a.Static.Principals)
		},
		static.RegisterSchema)
	f.Register("k8s-attestation",
		func(_ context.Context, a ClaimsMapperArgs) (claimsmapping.ClaimsMapper, error) {
			return k8sattestation.New(a.K8sAttestation)
		},
		k8sattestation.RegisterSchema)
	return f
}()

// NewClaimsMapper instantiates a ClaimsMapper given the specified
// arguments.
func NewClaimsMapper(ctx context.Context, args ClaimsMapperArgs) (claimsmapping.ClaimsMapper, error) {
	return claimsMappingFactory.Build(ctx, args.PluginName, args)
}

// RegisterClaimsMappingSchemas contributes every claims mapping plugin's
// schema.
func RegisterClaimsMappingSchemas(r *schema.Registry) error {
	return claimsMappingFactory.RegisterSchemas(r)
}
