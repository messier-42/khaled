package plugin

import (
	"context"
	"errors"
	"fmt"

	"github.com/messier-42/khaled/pkg/config/schema"
	"github.com/messier-42/khaled/pkg/plugin/policyengine"
	"github.com/messier-42/khaled/pkg/plugin/policyengine/cedar"
	"github.com/messier-42/khaled/pkg/plugin/policysource"
	"github.com/messier-42/khaled/pkg/plugin/policysource/file"
	"github.com/messier-42/khaled/pkg/plugin/policysource/inline"
)

// PolicySourceArgs provides information used to instantiate a policy source
// plugin. The caller must supply both PluginName (the source type to
// construct) and EngineName (the policy engine whose CompileFunc this
// source will feed) because the source is responsible for constructing
// policy engines.
type PolicySourceArgs struct {
	// The name of the policy source plugin to use.
	PluginName string

	// The name of the policy engine plugin the source must use to compile
	// policies. Must match the policyEngine block of the configuration.
	EngineName string

	// Policy source arguments specific to the file plugin.
	File struct {
		// Path to the policy file on disk. The file is watched and
		// reloaded on change.
		Path string
	}

	// Policy source arguments specific to the inline plugin.
	Inline struct {
		// Text is the raw policy bytes embedded in the configsource
		// snapshot. The inline source compiles this once at
		// construction; reloads happen by way of the snapshot
		// changing (which the policyManager observes and rebuilds
		// the source for).
		//
		// Stored as a string (rather than []byte) so PolicySourceArgs
		// remains comparable with ==, as the policyManager currently relies
		// on this for change detection.
		Text string
	}
}

// policySourceCtx is PolicySourceArgs plus the resolved CompileFunc;
// the per-variant constructors under the Factory read from this so
// each variant's code-path is (ctx, args) → Source.
type policySourceCtx struct {
	args    PolicySourceArgs
	compile policysource.CompileFunc
}

var policySourceFactory = func() *Factory[policySourceCtx, policysource.Source] {
	f := NewFactory[policySourceCtx, policysource.Source]("policy source")
	f.Register("file",
		func(ctx context.Context, a policySourceCtx) (policysource.Source, error) {
			return file.New(ctx, a.args.File.Path, a.compile)
		},
		file.RegisterSchema)
	f.Register("inline",
		func(ctx context.Context, a policySourceCtx) (policysource.Source, error) {
			return inline.New(ctx, []byte(a.args.Inline.Text), a.compile)
		},
		inline.RegisterSchema)
	return f
}()

// NewPolicySource instantiates a policy source given the specified
// arguments. In particular, the (source, engine) pairing must be supported.
func NewPolicySource(ctx context.Context, args PolicySourceArgs) (policysource.Source, error) {
	compile, err := compileFuncForEngine(args.EngineName)
	if err != nil {
		return nil, err
	}
	return policySourceFactory.Build(ctx, args.PluginName, policySourceCtx{args: args, compile: compile})
}

func compileFuncForEngine(name string) (policysource.CompileFunc, error) {
	switch name {
	case "":
		return nil, errors.New("policy engine name is required")
	case "cedar":
		return cedarCompile, nil
	default:
		return nil, fmt.Errorf("unsupported policy engine plugin %q", name)
	}
}

// RegisterPolicySourceSchemas contributes every policy source plugin's
// schema.
func RegisterPolicySourceSchemas(r *schema.Registry) error {
	return policySourceFactory.RegisterSchemas(r)
}

// cedarCompile compiles policy source bytes for the Cedar engine.
func cedarCompile(_ context.Context, args policysource.CompileArgs) (policyengine.Engine, error) {
	switch args.Type {
	case "", "text/cedar":
		// ok: Cedar text form.
	default:
		return nil, fmt.Errorf("cedar: unsupported content type %q", args.Type)
	}
	return cedar.New(cedar.Config{PolicyText: args.Source})
}
