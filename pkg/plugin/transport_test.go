package plugin_test

import (
	"strings"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/plugin"
)

func TestNewTransportRejectsMissingUse(t *testing.T) {
	_, err := plugin.NewTransport(t.Context(), config.Map{}, config.Map{}, plugin.TransportDeps{})
	if err == nil {
		t.Fatalf("expected missing use to fail")
	}
	if !strings.Contains(err.Error(), "use is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewTransportRejectsUnsupportedPlugin(t *testing.T) {
	_, err := plugin.NewTransport(t.Context(), config.Map{"use": "ftp"}, config.Map{}, plugin.TransportDeps{})
	if err == nil {
		t.Fatalf("expected unsupported plugin to fail")
	}
	if !strings.Contains(err.Error(), "unsupported transport") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewTransportHTTPRequiresCertificates(t *testing.T) {
	// Use the http plugin but omit certificate material; the http
	// plugin should refuse to construct. This verifies that the
	// factory correctly dispatches to the http plugin's own
	// validation.
	entry := config.Map{
		"use":     "http",
		"address": ":0",
	}
	_, err := plugin.NewTransport(t.Context(), entry, config.Map{}, plugin.TransportDeps{})
	if err == nil {
		t.Fatalf("expected missing certificate to fail")
	}
}
