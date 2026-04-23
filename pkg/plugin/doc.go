// Package plugin provides plugin factory functions that the server
// uses to instantiate the per-plugin-type implementations selected by the
// loaded configuration.
//
// Each plugin type has an *Args struct describing the inputs needed to
// construct a plugin, plus a constructor that dispatches to the named
// implementation under the corresponding pkg/plugin/<type>/ subpackage.
package plugin
