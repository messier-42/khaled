package k8sattestation

import (
	"context"
	"strings"
	"testing"

	"github.com/messier-42/khaled/pkg/config"
)

func TestValidateRequiresTLSSpiffe_AllowsMatch(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"clientAuthn":   config.Map{"use": "tls-spiffe"},
		"claimsMapping": config.Map{"use": "k8s-attestation"},
	}}
	if err := validateRequiresTLSSpiffe(context.Background(), nil, snap); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateRequiresTLSSpiffe_RejectsMismatch(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"clientAuthn":   config.Map{"use": "oauth"},
		"claimsMapping": config.Map{"use": "k8s-attestation"},
	}}
	err := validateRequiresTLSSpiffe(context.Background(), nil, snap)
	if err == nil {
		t.Fatalf("expected mismatch to fail")
	}
	if !strings.Contains(err.Error(), "tls-spiffe") {
		t.Errorf("error does not mention tls-spiffe: %v", err)
	}
}

func TestValidateRequiresTLSSpiffe_SilentOnOtherMappers(t *testing.T) {
	snap := config.Snapshot{Root: config.Map{
		"clientAuthn":   config.Map{"use": "oauth"},
		"claimsMapping": config.Map{"use": "static"},
	}}
	if err := validateRequiresTLSSpiffe(context.Background(), nil, snap); err != nil {
		t.Errorf("unexpected error for static mapper: %v", err)
	}
}
