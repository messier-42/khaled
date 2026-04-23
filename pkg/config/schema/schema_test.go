package schema_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/config/schema"
)

func mustSnapshot(t *testing.T, raw any) config.Snapshot {
	t.Helper()
	snap, err := config.NewSnapshot(raw)
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	return snap
}

func TestBuildProducesObjectSchemaWithPluginKindVariants(t *testing.T) {
	r := schema.New()
	err := r.RegisterPluginKind("keyStorage", "disk", &jsonschema.Schema{
		Type:     "object",
		Required: []string{"path"},
		Properties: map[string]*jsonschema.Schema{
			"path": {Type: "string", MinLength: new(1)},
		},
	})
	if err != nil {
		t.Fatalf("register disk: %v", err)
	}
	if err := r.RegisterPluginKind("keyStorage", "memory", nil); err != nil {
		t.Fatalf("register memory: %v", err)
	}

	built, err := r.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if built.Schema().Type != "object" {
		t.Fatalf("expected object root, got %q", built.Schema().Type)
	}

	ks := built.Schema().Properties["keyStorage"]
	if ks == nil {
		t.Fatalf("expected keyStorage property")
	}
	if ks.Properties["use"] == nil {
		t.Fatalf("expected keyStorage.use property")
	}
}

func TestValidateAcceptsWellFormedConfig(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", &jsonschema.Schema{
		Type:     "object",
		Required: []string{"path"},
		Properties: map[string]*jsonschema.Schema{
			"path": {Type: "string", MinLength: new(1)},
		},
	})

	snap := mustSnapshot(t, map[string]any{
		"keyStorage": map[string]any{
			"use":  "disk",
			"disk": map[string]any{"path": "/var/lib/khaled"},
		},
	})

	if err := r.Validate(context.Background(), nil, snap); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

// TestValidateLargeIntegerPreservesPrecision guards against the
// earlier float64 round-trip on the instance side that silently
// coerced integers above 2^53 to the nearest representable float.
// The schema has an enum of one large int; the float64 coercion
// would have turned a mismatching instance into a matching one.
func TestValidateLargeIntegerPreservesPrecision(t *testing.T) {
	r := schema.New()
	allowed := any(int64(math.MaxInt64))
	if err := r.RegisterPath("bigNum", &jsonschema.Schema{
		Enum: []any{allowed},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Exact match: allowed.
	good := mustSnapshot(t, map[string]any{"bigNum": int64(math.MaxInt64)})
	if err := r.Validate(context.Background(), nil, good); err != nil {
		t.Fatalf("expected MaxInt64 to satisfy enum=[MaxInt64], got %v", err)
	}

	// One less: must be rejected. With a float64 round-trip both
	// sides would collapse to the same double and the mismatch
	// would be lost. (MaxInt64-1 and MaxInt64 both round to the
	// same double.)
	bad := mustSnapshot(t, map[string]any{"bigNum": int64(math.MaxInt64 - 1)})
	if err := r.Validate(context.Background(), nil, bad); err == nil {
		t.Fatalf("expected MaxInt64-1 to violate enum=[MaxInt64]")
	}
}

func TestValidateRejectsUnknownUseValue(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", nil)

	snap := mustSnapshot(t, map[string]any{
		"keyStorage": map[string]any{"use": "bogus"},
	})

	err := r.Validate(context.Background(), nil, snap)
	if err == nil {
		t.Fatalf("expected validation error for unknown use")
	}
}

func TestValidateRejectsMissingSubBlock(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", &jsonschema.Schema{
		Type:     "object",
		Required: []string{"path"},
	})

	snap := mustSnapshot(t, map[string]any{
		"keyStorage": map[string]any{"use": "disk"},
	})

	err := r.Validate(context.Background(), nil, snap)
	if err == nil {
		t.Fatalf("expected validation error when sub-block is missing")
	}
}

func TestRegisterPathMergesAtDottedPath(t *testing.T) {
	r := schema.New()
	if err := r.RegisterPath("metrics", &jsonschema.Schema{
		Type:     "object",
		Required: []string{"addr"},
		Properties: map[string]*jsonschema.Schema{
			"addr": {Type: "string"},
		},
	}); err != nil {
		t.Fatalf("register metrics: %v", err)
	}

	snap := mustSnapshot(t, map[string]any{
		"metrics": map[string]any{"addr": ":9090"},
	})
	if err := r.Validate(context.Background(), nil, snap); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bad := mustSnapshot(t, map[string]any{
		"metrics": map[string]any{"addr": 1234},
	})
	if err := r.Validate(context.Background(), nil, bad); err == nil {
		t.Fatalf("expected error for wrong type")
	}
}

func TestRegisterPathRejectsCollisionWithPluginKind(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", nil)

	err := r.RegisterPath("keyStorage.extra", &jsonschema.Schema{})
	if err == nil {
		t.Fatalf("expected conflict error")
	}
}

func TestRegisterPluginKindRejectsCollisionWithPath(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPath("metrics", &jsonschema.Schema{Type: "object"})

	err := r.RegisterPluginKind("metrics", "prom", nil)
	if err == nil {
		t.Fatalf("expected conflict error")
	}
}

func TestRegisterDuplicatePluginKindVariantRejected(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", nil)
	if err := r.RegisterPluginKind("keyStorage", "disk", nil); err == nil {
		t.Fatalf("expected duplicate registration error")
	}
}

func TestRegisterDuplicatePathRejected(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPath("metrics", &jsonschema.Schema{Type: "object"})
	if err := r.RegisterPath("metrics", &jsonschema.Schema{Type: "object"}); err == nil {
		t.Fatalf("expected duplicate path error")
	}
}

func TestRegisterAfterBuildFrozen(t *testing.T) {
	r := schema.New()
	if _, err := r.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}

	if err := r.RegisterPluginKind("x", "y", nil); err == nil {
		t.Fatalf("expected frozen error")
	}
	if err := r.RegisterPath("metrics", &jsonschema.Schema{}); err == nil {
		t.Fatalf("expected frozen error")
	}
	noop := func(_ context.Context, _ *config.Snapshot, _ config.Snapshot) error { return nil }
	if err := r.RegisterValidator(noop); err == nil {
		t.Fatalf("expected frozen error from RegisterValidator")
	}
}

// TestBuildSchemaDeterministic pins the stability of schema output
// across registry builds. Map iteration order is randomised by the
// Go runtime, so a naive build is non-deterministic; this test
// registers the same variants in two independent registries and
// compares the marshalled schemas byte-for-byte.
func TestBuildSchemaDeterministic(t *testing.T) {
	buildOnce := func() []byte {
		t.Helper()
		r := schema.New()
		// Register variants in an order that would otherwise
		// surface map-iteration nondeterminism: alphabetically
		// reversed, and with a common-prop alongside.
		if err := r.RegisterPluginKind("keyStorage", "zebra", &jsonschema.Schema{
			Type:     "object",
			Required: []string{"path"},
		}); err != nil {
			t.Fatalf("register zebra: %v", err)
		}
		if err := r.RegisterPluginKind("keyStorage", "yak", nil); err != nil {
			t.Fatalf("register yak: %v", err)
		}
		if err := r.RegisterPluginKind("keyStorage", "aardvark", nil); err != nil {
			t.Fatalf("register aardvark: %v", err)
		}
		if err := r.RegisterPluginKindCommon("keyStorage", "leaseDuration", &jsonschema.Schema{Type: "string"}); err != nil {
			t.Fatalf("register common: %v", err)
		}
		built, err := r.Build()
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		out, err := json.Marshal(built.Schema())
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return out
	}

	first := buildOnce()
	for i := range 5 {
		got := buildOnce()
		if !bytes.Equal(first, got) {
			t.Fatalf("schema output not deterministic across builds:\niter 0: %s\niter %d: %s", first, i+1, got)
		}
	}
}

func TestBuildIdempotent(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", nil)
	first, err := r.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	second, err := r.Build()
	if err != nil {
		t.Fatalf("build again: %v", err)
	}
	if first != second {
		t.Fatalf("expected identical schema pointer on second build")
	}
}

func TestRegisterValidatorRunsAfterSchemaPasses(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", nil)

	called := false
	_ = r.RegisterValidator(func(_ context.Context, _ *config.Snapshot, snap config.Snapshot) error {
		called = true
		return errors.New("semantic failure")
	})

	snap := mustSnapshot(t, map[string]any{
		"keyStorage": map[string]any{"use": "disk"},
	})

	err := r.Validate(context.Background(), nil, snap)
	if err == nil {
		t.Fatalf("expected semantic validation error")
	}
	if !called {
		t.Fatalf("expected validator to run")
	}
	if !strings.Contains(err.Error(), "semantic failure") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatorsNotRunIfSchemaFails(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", nil)

	called := false
	_ = r.RegisterValidator(func(_ context.Context, _ *config.Snapshot, _ config.Snapshot) error {
		called = true
		return nil
	})

	// Schema violation: keyStorage.use must be a string.
	snap := mustSnapshot(t, map[string]any{
		"keyStorage": map[string]any{"use": 42},
	})

	err := r.Validate(context.Background(), nil, snap)
	if err == nil {
		t.Fatalf("expected schema error")
	}
	if called {
		t.Fatalf("validator should not run if schema fails")
	}
}

func TestMultipleValidatorsErrorsAggregated(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", nil)

	_ = r.RegisterValidator(func(_ context.Context, _ *config.Snapshot, _ config.Snapshot) error {
		return errors.New("first fail")
	})
	_ = r.RegisterValidator(func(_ context.Context, _ *config.Snapshot, _ config.Snapshot) error {
		return errors.New("second fail")
	})

	snap := mustSnapshot(t, map[string]any{
		"keyStorage": map[string]any{"use": "disk"},
	})

	err := r.Validate(context.Background(), nil, snap)
	if err == nil {
		t.Fatalf("expected aggregated error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "first fail") || !strings.Contains(msg, "second fail") {
		t.Fatalf("expected both messages, got %q", msg)
	}
}

func TestRegisterPluginKindCommon(t *testing.T) {
	r := schema.New()
	if err := r.RegisterPluginKind("keyStorage", "disk", &jsonschema.Schema{
		Type:     "object",
		Required: []string{"path"},
		Properties: map[string]*jsonschema.Schema{
			"path": {Type: "string", MinLength: new(1)},
		},
	}); err != nil {
		t.Fatalf("register disk: %v", err)
	}
	if err := r.RegisterPluginKindCommon("keyStorage", "leaseDuration", &jsonschema.Schema{
		Type: "string", MinLength: new(1),
	}); err != nil {
		t.Fatalf("register common: %v", err)
	}

	good := mustSnapshot(t, map[string]any{
		"keyStorage": map[string]any{
			"use":           "disk",
			"disk":          map[string]any{"path": "/tmp/x"},
			"leaseDuration": "5m",
		},
	})
	if err := r.Validate(context.Background(), nil, good); err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	bad := mustSnapshot(t, map[string]any{
		"keyStorage": map[string]any{
			"use":           "disk",
			"disk":          map[string]any{"path": "/tmp/x"},
			"leaseDuration": 42,
		},
	})
	if err := r.Validate(context.Background(), nil, bad); err == nil {
		t.Fatalf("expected schema error for non-string leaseDuration")
	}
}

func TestRegisterPluginKindCommonRejectsUseCollision(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", nil)
	if err := r.RegisterPluginKindCommon("keyStorage", "use", &jsonschema.Schema{Type: "string"}); err == nil {
		t.Fatal("expected error for use collision")
	}
}

func TestRegisterPluginKindCommonRejectsVariantCollision(t *testing.T) {
	r := schema.New()
	_ = r.RegisterPluginKind("keyStorage", "disk", nil)
	if err := r.RegisterPluginKindCommon("keyStorage", "disk", &jsonschema.Schema{Type: "string"}); err == nil {
		t.Fatal("expected error for variant collision")
	}
}
