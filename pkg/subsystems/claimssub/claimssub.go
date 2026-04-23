// Package claimssub provides the claims mapper subsystem.
//
// A Manager owns the current ClaimsMapper and reconciles it against
// config reloads. The per-request ClaimsMapper method value is stable
// across reloads so that HTTP middleware can retain it indefinitely.
package claimssub

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/lifecycle"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping/k8sattestation"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping/static"
)

// Manager owns the lifecycle of the current ClaimsMapper and
// reconciles it in the event of config reloads. It is a lifecycle.Manager
// configured with the claimssub-specific Apply; the currently-installed
// mapper is obtained via Current().
type Manager = lifecycle.Manager[claimsmapping.ClaimsMapper]

// argsData captures the inputs that built the current mapper, used for
// detecting no-op reconciles.
type argsData struct {
	PluginName string

	// StaticPrincipals is the ordered list of static mapper entries
	// in raw form.
	StaticPrincipals []static.PrincipalConfig

	// K8sCache is the k8s-attestation configuration, if used.
	K8sCache k8sattestation.Config
}

func (a argsData) equals(b argsData) bool {
	if a.PluginName != b.PluginName {
		return false
	}
	if a.K8sCache != b.K8sCache {
		return false
	}
	return reflect.DeepEqual(a.StaticPrincipals, b.StaticPrincipals)
}

// New builds the initial ClaimsMapper from snap and returns a
// Manager that manages the lifecycle.
func New(snap config.Snapshot) (*Manager, error) {
	return lifecycle.New(context.Background(), snap, spec())
}

// NewEmpty returns a Manager with no current mapper. Used for testing.
func NewEmpty() *Manager {
	return lifecycle.NewEmpty(spec())
}

func spec() lifecycle.Spec[claimsmapping.ClaimsMapper] {
	return lifecycle.Spec[claimsmapping.ClaimsMapper]{
		Name: "claimsmapper",
		Apply: func(_ context.Context, old claimsmapping.ClaimsMapper, oldSnap, newSnap config.Snapshot) (claimsmapping.ClaimsMapper, error) {
			newArgs, err := argsFromSnapshot(newSnap)
			if err != nil {
				return nil, err
			}
			if newArgs.PluginName == "" {
				return nil, nil
			}
			if old != nil {
				oldArgs, err := argsFromSnapshot(oldSnap)
				if err == nil && oldArgs.equals(newArgs) {
					return old, nil
				}
			}
			return buildClaimsMapper(newArgs)
		},
		Close: func(m claimsmapping.ClaimsMapper) error { return m.Close() },
	}
}

// argsFromSnapshot parses the claimsMapping block from snap into a
// argsData struct.
func argsFromSnapshot(snap config.Snapshot) (argsData, error) {
	cm, ok := snap.Root.GetMap("claimsMapping")
	if !ok {
		return argsData{}, nil
	}
	use, _ := cm.GetString("use")
	args := argsData{PluginName: use}

	switch use {
	case "":
		return args, nil

	case "static":
		staticBlock, ok := cm.GetMap("static")
		if !ok {
			return args, errors.New("claimsMapping.static block is required when use=static")
		}
		rawPrincipals, ok := staticBlock.GetArray("principals")
		if !ok || len(rawPrincipals) == 0 {
			return args, errors.New("claimsMapping.static.principals must be non-empty")
		}
		principals := make([]static.PrincipalConfig, 0, len(rawPrincipals))
		for i, raw := range rawPrincipals {
			obj, ok := raw.(config.Map)
			if !ok {
				return args, fmt.Errorf("claimsMapping.static.principals[%d] is not an object", i)
			}
			uri, ok := obj.GetString("uri")
			if !ok || uri == "" {
				return args, fmt.Errorf("claimsMapping.static.principals[%d].uri is required", i)
			}
			claimsObj, _ := obj.GetMap("claims")
			claims := make(map[string]string, len(claimsObj))
			for k, v := range claimsObj {
				s, ok := v.(string)
				if !ok {
					return args, fmt.Errorf("claimsMapping.static.principals[%d].claims[%q]: value must be a string", i, k)
				}
				claims[k] = s
			}
			principals = append(principals, static.PrincipalConfig{URI: uri, Claims: claims})
		}
		args.StaticPrincipals = principals

	case "k8s-attestation":
		k8sBlock, _ := cm.GetMap("k8s-attestation")
		cacheBlock, _ := k8sBlock.GetMap("cache")
		if raw, ok := cacheBlock.GetString("ttl"); ok {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return args, fmt.Errorf("claimsMapping.k8s-attestation.cache.ttl: %w", err)
			}
			args.K8sCache.TTL = d
		}
		if raw, ok := cacheBlock.GetString("negativeTTL"); ok {
			d, err := time.ParseDuration(raw)
			if err != nil {
				return args, fmt.Errorf("claimsMapping.k8s-attestation.cache.negativeTTL: %w", err)
			}
			args.K8sCache.NegativeTTL = d
		}
		if raw, ok := cacheBlock.Get("maxEntries"); ok {
			n, ok := asInt(raw)
			if !ok {
				return args, fmt.Errorf("claimsMapping.k8s-attestation.cache.maxEntries: not an integer in range [%d,%d]", math.MinInt, math.MaxInt)
			}
			args.K8sCache.MaxEntries = n
		}
	}

	return args, nil
}

func buildClaimsMapper(args argsData) (claimsmapping.ClaimsMapper, error) {
	pluginArgs := plugin.ClaimsMapperArgs{PluginName: args.PluginName}
	pluginArgs.Static.Principals = args.StaticPrincipals
	pluginArgs.K8sAttestation = args.K8sCache
	return plugin.NewClaimsMapper(pluginArgs)
}

// asInt coerces an already-Normalize'd config value into an int.
func asInt(v config.Value) (int, bool) {
	switch n := v.(type) {
	case int64:
		if n > math.MaxInt || n < math.MinInt {
			return 0, false
		}
		return int(n), true
	case uint64:
		if n > math.MaxInt {
			return 0, false
		}
		return int(n), true
	}
	return 0, false
}
