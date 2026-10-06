// Package schema manages dynamic introspection, validation and export of schema
// descriptions based on per-plugin contributions to an overall configuration
// schema.
//
// The underlying premise of this architecture is that configuration objects
// are arbitrary CBOR maps which are required to align with a JSON Schema.
// That schema is the product of schema fragments contributed from the plugins
// loaded into khaled.
//
// Plugins contribute schema fragments by registering *jsonschema.Schema objects
// via one of two entry points:
//
//   - [RegisterPluginKind] is used for straightforward cases; a top-level key
//     (e.g. "keyStorage") holds a "use: <name>" discriminator plus an
//     optional subblock bearing that name. Each registration adds a (kind: name)
//     variant, and the combined schema enforces that if keyStorage.use == "disk",
//     then keyStorage.disk must match the registered `disk` schema.
//
//   - [RegisterPath] merges a schema fragment at an arbitrary dotted path, for
//     cases that don't fit the `use“ pattern above. This can be used for example
//     to register global top-level configuration.
//
// [RegisterPluginKindCommon] is used to register schema fragments common to the
// configuration schema for all plugins of a given kind.
//
// Semantic rules that JSON Schema cannot express (for example, cross-field,
// cross-snapshot, or registry-dependent rules) are contributed via RegisterValidator
// as Go callbacks.
//
// The combined schema is assembled lazily by [Build]; once [Build] is called, the
// registry is frozen and further registrations return an error. [Validate]
// verifies against the combined schema and then invokes the registered validators,
// aggregating their errors.
package schema

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config"
)

const (
	schemaTypeObject = "object"
	pluginSelector   = "use"
)

// ValidateFunc is a custom validator invoked after structural JSON Schema
// validation has passed. oldConfig is nil if a configuration is the first
// configuration being loaded; it is otherwise passed as a non-nil value
// so that a plugin can implement restrictions on what configuration can
// be changed after initial startup.
type ValidateFunc func(ctx context.Context, oldConfig *config.Snapshot, newConfig config.Snapshot) error

// Registry accumulates schema fragments and custom validators contributed
// by plugins, and assembles the combined JSON Schema for validation.
//
// Use [New] to create a Registry.
type Registry struct {
	mu sync.Mutex // protects all of the following fields

	pluginKinds map[string]*pluginKind
	paths       map[string]*jsonschema.Schema

	// Custom validation functions which have been registered.
	validators []ValidateFunc

	// After Build() is called, frozen becomes true and these
	// values are non-nil.
	built    *jsonschema.Schema
	resolved *jsonschema.Resolved
	frozen   bool
}

type pluginKind struct {
	variants map[string]*jsonschema.Schema
	// commonProps are properties that apply to the kind slot
	// regardless of which plugin is selected via `use`. They are
	// merged alongside the variant subblock and the `use`
	// discriminator in the built schema. Typical usage: runtime
	// knobs shared across all plugins of the kind.
	commonProps map[string]*jsonschema.Schema
}

// New returns a new [Registry].
func New() *Registry {
	return &Registry{
		pluginKinds: make(map[string]*pluginKind),
		paths:       make(map[string]*jsonschema.Schema),
	}
}

// Must hold mutex.
func (r *Registry) ensureKind(kind string) *pluginKind {
	entry, ok := r.pluginKinds[kind]
	if !ok {
		// First plugin being registered of the given kind - create the entry.
		entry = &pluginKind{
			variants:    make(map[string]*jsonschema.Schema),
			commonProps: make(map[string]*jsonschema.Schema),
		}
		r.pluginKinds[kind] = entry
	}

	return entry
}

// RegisterPluginKind declares a plugin of a given kind, with configuration
// keyed by the kind and the plugin name. The kind describes a category of plugin
// (e.g. "keyStorage") and the plugin name is unique within that category.
// The plugin's sub-block schema is registered to the plugin. The same (kind, name)
// cannot be registered twice.
//
// The resulting combined schema enforces that the kind slot is an object with
// a `use` string discriminator whose value must be one of the registered
// names, and that when `use` equals a given plugin name the corresponding sub-block
// (if present) matches the registered schema for that plugin.
func (r *Registry) RegisterPluginKind(kind, name string, subSchema *jsonschema.Schema) error {
	if kind == "" {
		return errors.New("plugin kind must be non-empty")
	}
	if name == "" {
		return errors.New("plugin name must be non-empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.frozen {
		return fmt.Errorf("registry is frozen: cannot register plugin kind %q/%q after Build", kind, name)
	}

	// Use of a kind name is mutually exclusive with use of the same name with RegisterPath.
	if _, ok := r.paths[kind]; ok {
		return fmt.Errorf("plugin kind %q conflicts with path registration", kind)
	}

	for path := range r.paths {
		if strings.HasPrefix(path, kind+".") {
			return fmt.Errorf("plugin kind %q conflicts with path %q", kind, path)
		}
	}

	entry := r.ensureKind(kind)

	// Prevent duplicate registrations.
	if _, ok := entry.variants[name]; ok {
		return fmt.Errorf("plugin kind %q already has a variant named %q", kind, name)
	}
	if _, ok := entry.commonProps[name]; ok {
		return fmt.Errorf("plugin kind %q variant %q collides with a common property", kind, name)
	}

	// Register the plugin-specific schema.
	entry.variants[name] = subSchema
	return nil
}

// RegisterPluginKindCommon registers schema for given plugin kind
// that is applicable regardless of what plugin of that kind is selected.
func (r *Registry) RegisterPluginKindCommon(kind, propName string, schema *jsonschema.Schema) error {
	if kind == "" {
		return errors.New("plugin kind must be non-empty")
	}
	if propName == "" {
		return errors.New("common property name must be non-empty")
	}
	if propName == pluginSelector {
		return fmt.Errorf("cannot override reserved property %q", propName)
	}
	if schema == nil {
		return errors.New("schema must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return fmt.Errorf("registry is frozen: cannot register common prop %q for %q after Build", propName, kind)
	}

	entry := r.ensureKind(kind)

	// Prevent duplicate registrations.
	if _, ok := entry.variants[propName]; ok {
		return fmt.Errorf("common property %q collides with plugin variant name", propName)
	}
	if _, ok := entry.commonProps[propName]; ok {
		return fmt.Errorf("common property %q already registered for kind %q", propName, kind)
	}

	// Register the common schema.
	entry.commonProps[propName] = schema
	return nil
}

// RegisterPath merges subSchema into the combined schema at a global mounting
// point expressed by a dotted path (e.g. "metrics" or "spiffe.advanced"). The
// path must not collide with any [RegisterPluginKind] registration or a previous
// [RegisterPath] registration.
func (r *Registry) RegisterPath(path string, subSchema *jsonschema.Schema) error {
	if path == "" {
		return errors.New("path must be non-empty")
	}
	if subSchema == nil {
		return errors.New("subSchema must not be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.frozen {
		return fmt.Errorf("registry is frozen: cannot register path %q after Build", path)
	}
	if _, ok := r.paths[path]; ok {
		return fmt.Errorf("path %q already registered", path)
	}

	top, _, _ := strings.Cut(path, ".")
	if _, ok := r.pluginKinds[top]; ok {
		return fmt.Errorf("path %q conflicts with plugin kind %q", path, top)
	}

	for existing := range r.paths {
		if existing == path ||
			strings.HasPrefix(existing, path+".") ||
			strings.HasPrefix(path, existing+".") {
			return fmt.Errorf("path %q conflicts with existing path %q", path, existing)
		}
	}

	r.paths[path] = subSchema
	return nil
}

// RegisterValidator registers a custom validator. Custom validators run in
// registration order after structural validation succeeds. Their errors are
// aggregated with [errors.Join]. Returns an error if the registry has already
// been frozen by a successful Build call. A nil fn is silently ignored.
func (r *Registry) RegisterValidator(fn ValidateFunc) error {
	if fn == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return errors.New("registry is frozen: cannot register validator after Build")
	}

	r.validators = append(r.validators, fn)
	return nil
}

// Build assembles and constructs the combined schema and returns *jsonschema.Resolved,
// caching the result and freezing the Registry so that it cannot be further modified.
// This method is idempotent, and further calls return the same cached value. The registry
// becomes frozen after the first successful call. The underlying schema can be obtained
// by calling (*jsonschema.Resolved).Schema().
func (r *Registry) Build() (*jsonschema.Resolved, error) {
	rr, _, err := r.buildAndGetValidators()
	return rr, err
}

func (r *Registry) buildAndGetValidators() (*jsonschema.Resolved, []ValidateFunc, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.resolved != nil {
		validators := append([]ValidateFunc(nil), r.validators...)
		return r.resolved, validators, nil
	}

	combined := &jsonschema.Schema{
		Type:       schemaTypeObject,
		Properties: map[string]*jsonschema.Schema{},
	}

	for kind, entry := range r.pluginKinds {
		combined.Properties[kind] = buildPluginKindSchema(entry)
	}

	for path, sub := range r.paths {
		if err := mergePath(combined, path, sub); err != nil {
			return nil, nil, fmt.Errorf("merge path %q: %w", path, err)
		}
	}

	resolved, err := combined.Resolve(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve combined schema: %w", err)
	}

	r.built = combined
	r.resolved = resolved
	r.frozen = true
	validators := append([]ValidateFunc(nil), r.validators...)
	return resolved, validators, nil
}

// Validate uses the constructed JSON Schema to validate newConfig. If structural
// validation passes, it then verifies against any registered custom validators,
// aggregating any errors via [errors.Join].
func (r *Registry) Validate(ctx context.Context, oldConfig *config.Snapshot, newConfig config.Snapshot) error {
	resolved, validators, err := r.buildAndGetValidators()
	if err != nil {
		return err
	}

	instance := snapshotToInstance(newConfig)
	if err := resolved.Validate(instance); err != nil {
		return err
	}

	var errs []error
	for _, fn := range validators {
		if err := fn(ctx, oldConfig, newConfig); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}

	return nil
}

// buildPluginKindSchema produces the discriminated-union schema for a plugin
// kind with variants { "use": string-enum, <name>: <variant schema> }.
//
// Iteration order over entry.variants is made deterministic (sorted by
// plugin name) so the generated JSON Schema is byte-stable between
// runs. This ensures that running `khaled config-schema` does not
// produce different output from run to run.
func buildPluginKindSchema(entry *pluginKind) *jsonschema.Schema {
	variantNames := sortedKeys(entry.variants)
	commonNames := sortedKeys(entry.commonProps)

	enum := make([]any, 0, len(variantNames))
	for _, name := range variantNames {
		enum = append(enum, name)
	}

	properties := map[string]*jsonschema.Schema{
		pluginSelector: {Type: "string", Enum: enum},
	}
	for _, name := range variantNames {
		if sub := entry.variants[name]; sub != nil {
			properties[name] = sub
		}
	}
	for _, name := range commonNames {
		properties[name] = entry.commonProps[name]
	}

	kindSchema := &jsonschema.Schema{
		Type:       schemaTypeObject,
		Properties: properties,
		Required:   []string{pluginSelector},
	}

	for _, name := range variantNames {
		sub := entry.variants[name]
		if sub == nil {
			continue
		}

		// A variant sub-block is required on the kind slot only if
		// the sub-block itself has required fields. A sub-block with
		// every field optional (e.g. a pure knob bag with defaults)
		// does not need to be present.
		if len(sub.Required) == 0 {
			continue
		}

		useConst := any(name)
		kindSchema.AllOf = append(kindSchema.AllOf, &jsonschema.Schema{
			If: &jsonschema.Schema{
				Properties: map[string]*jsonschema.Schema{
					pluginSelector: {Const: &useConst},
				},
				Required: []string{pluginSelector},
			},
			Then: &jsonschema.Schema{
				Required: []string{name},
			},
		})
	}

	return kindSchema
}

// sortedKeys returns the keys of m in ascending order.
func sortedKeys[V any](m map[string]V) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// mergePath installs sub at dotted path within root, creating intermediate
// object schemas as needed. Fails if the path is already occupied.
func mergePath(root *jsonschema.Schema, path string, sub *jsonschema.Schema) error {
	parts := strings.Split(path, ".")
	cur := root
	for i, part := range parts {
		if cur.Properties == nil {
			cur.Properties = map[string]*jsonschema.Schema{}
		}
		if i == len(parts)-1 {
			if _, exists := cur.Properties[part]; exists {
				return fmt.Errorf("property %q already defined", part)
			}
			cur.Properties[part] = sub
			return nil
		}
		child, ok := cur.Properties[part]
		if !ok {
			child = &jsonschema.Schema{Type: schemaTypeObject, Properties: map[string]*jsonschema.Schema{}}
			cur.Properties[part] = child
		}
		cur = child
	}
	return nil
}

// snapshotToInstance converts a config.Snapshot into the
// representation that jsonschema.Resolved.Validate expects.
func snapshotToInstance(snap config.Snapshot) any {
	return valueToInstance(snap.Root)
}

func valueToInstance(v config.Value) any {
	switch typed := v.(type) {
	case config.Map:
		out := make(map[string]any, len(typed))
		for key, child := range typed {
			out[key] = valueToInstance(child)
		}
		return out
	case config.Array:
		out := make([]any, len(typed))
		for i, child := range typed {
			out[i] = valueToInstance(child)
		}
		return out
	case int64, uint64:
		// Pass native integer types straight through. An earlier
		// implementation converted both to float64 "to keep
		// enum/const comparisons uniform"; that silently rounded
		// any integer above 2^53 (e.g. a user-supplied nanosecond
		// timestamp), which could let an out-of-range value slip
		// past a range validator after becoming representable as a
		// float. jsonschema-go accepts int64/uint64 as native
		// integer instances and compares them exactly, so we get
		// both precision and uniformity for free.
		return typed
	default:
		return typed
	}
}

// MarshalJSON returns the combined schema as pretty-printed JSON. Useful for
// the `khaled config-schema` subcommand.
func (r *Registry) MarshalJSON() ([]byte, error) {
	resolved, err := r.Build()
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(resolved.Schema(), "", "  ")
}
