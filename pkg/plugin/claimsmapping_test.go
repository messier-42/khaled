package plugin_test

import (
	"context"
	"testing"

	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping/static"
)

func TestNewClaimsMapperRejectsUnknown(t *testing.T) {
	_, err := plugin.NewClaimsMapper(context.Background(), plugin.ClaimsMapperArgs{PluginName: "bogus"})
	if err == nil {
		t.Fatalf("expected unknown plugin name to fail")
	}
}

func TestNewClaimsMapperBuildsStatic(t *testing.T) {
	args := plugin.ClaimsMapperArgs{PluginName: "static"}
	args.Static.Principals = []static.PrincipalConfig{{
		URI:    ".*",
		Claims: map[string]string{"c": "v"},
	}}
	m, err := plugin.NewClaimsMapper(context.Background(), args)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestNewClaimsMapperStaticRequiresPrincipals(t *testing.T) {
	_, err := plugin.NewClaimsMapper(context.Background(), plugin.ClaimsMapperArgs{PluginName: "static"})
	if err == nil {
		t.Fatalf("expected empty principals to fail")
	}
}
