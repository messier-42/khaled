// Command khaled implements a CABE Key Server.
//
// khaled is assembled from plugins that are wired together at startup
// and updated on configuration reload. cmd/khaled is the
// command-line entrypoint: it parses flags and environment,
// installs a bootstrap logger, builds the configuration source,
// and then hands off to the pkg/server package which owns every
// subsystem manager, the reload loop, and teardown handling.
//
// All the per-subsystem manager code, the reload loop, and the
// schema assembly live in pkg/server.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/messier-42/khaled/pkg/config/schema"
	klog "github.com/messier-42/khaled/pkg/log"
	"github.com/messier-42/khaled/pkg/plugin"
	"github.com/messier-42/khaled/pkg/plugin/configsource"
	"github.com/messier-42/khaled/pkg/server"
)

const (
	// Default configuration source if nothing else is specified.
	defaultConfigSource = "disk"
	defaultConfigPath   = "/etc/khaled/khaled.yaml"

	// Environment variables.
	envConfigSource = "KHALED_CONFIG_SOURCE"
	envConfigPath   = "KHALED_CONFIG"
	envK8sConfig    = "KHALED_K8S_CONFIG"
	envK8sNamespace = "KHALED_K8S_NAMESPACE"
	envLogFormat    = "KHALED_LOG_FORMAT"
	envLogSeverity  = "KHALED_LOG_SEVERITY"
)

type options struct {
	configSource string
	configPath   string
	k8sConfig    string
	k8sNamespace string

	// logFormat and logSeverity are empty if the user does not supply
	// a CLI flag or environment variable. An empty value means "fall
	// through to built-ins"; a non-empty value configures both the bootstrap
	// logger and supplies a default for the final config-driven logger if the
	// config file does not specify one.
	logFormat   string
	logSeverity string
}

var (
	configSourceFactory = newConfigSource
	registryFactory     = server.BuildRegistry

	// runContext returns the context used for the post-initial-load
	// run loop that consumes reload notifications. Replaceable in tests.
	runContext = defaultRunContext

	// starterSet, when non-nil, is passed to server.New as
	// Options.StarterSet so that unit tests in this package can drive
	// the cobra entrypoint without standing up real plugins.
	// Production leaves this nil.
	starterSet *server.StarterSet
)

// defaultRunContext returns a context that is cancelled on SIGINT or
// SIGTERM, along with the stop function that releases signal handlers.
//
// A second signal force-exits via os.Exit(1) so that the process can
// be forcibly torn down by pressing Ctrl-C twice (e.g. if the shutdown
// teardown process itself hangs).
func defaultRunContext() (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	go func() {
		// Wait for the first shutdown interrupt.
		<-ctx.Done()

		forceCh := make(chan os.Signal, 1)
		signal.Notify(forceCh, os.Interrupt, syscall.SIGTERM)
		<-forceCh

		slog.Error("second signal received; forcing exit")
		os.Exit(1)
	}()

	return ctx, cancel
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		slog.Error("khaled startup failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer, stderr io.Writer) error {
	opts := defaultOptions()
	cmd := newRootCmd(&opts, stdout, stderr)
	cmd.SetArgs(args)
	return cmd.Execute()
}

// installBootstrapLogger parses the bootstrap logging options in opts and
// replaces slog's default logger with a bootstrap logger. This runs
// before config loads, so the logger reflects only CLI flags, environment
// variables and built-in defaults. This ensures that some form of logging
// is available prior to first config load.
//
// Parse failures are returned as errors; the caller is responsible for
// surfacing them. No logger exists until this function returns.
func installBootstrapLogger(opts options) error {
	format := server.DefaultLogFormat
	if opts.logFormat != "" {
		parsed, err := klog.ParseFormat(opts.logFormat)
		if err != nil {
			return err
		}
		format = parsed
	}

	severity := server.DefaultLogSeverity
	if opts.logSeverity != "" {
		parsed, err := parseLogSeverity(opts.logSeverity)
		if err != nil {
			return err
		}
		severity = parsed
	}

	slog.SetDefault(klog.New(os.Stderr, klog.Config{Format: format, Severity: severity}))
	return nil
}

// parseLogSeverity parses a severity in a case-sensitive manner.
func parseLogSeverity(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log severity %q: must be debug, info, warn or error", s)
	}
}

// Returns the cobra setup for all CLI subcommands.
func newRootCmd(opts *options, stdout io.Writer, stderr io.Writer) *cobra.Command {
	if opts == nil {
		defaults := defaultOptions()
		opts = &defaults
	}

	cmd := &cobra.Command{
		Use:   "khaled --config-source=<name> <config-source-specific-flags>",
		Short: "CABE key server daemon",
		Long:  "khaled is a CABE key server implementation. For more information,\nsee <https://cabespec.org/> and <https://github.com/messier-42/khaled>.",

		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := installBootstrapLogger(*opts); err != nil {
				return err
			}

			registry, err := registryFactory()
			if err != nil {
				return fmt.Errorf("build config schema: %w", err)
			}

			source, err := configSourceFactory(*opts, registry)
			if err != nil {
				return err
			}
			defer source.Close() // best effort

			snap, err := source.Current()
			if err != nil {
				return err
			}

			ctx, stop := runContext()
			defer stop()

			srvOpts := server.Options{
				LogFormat:   opts.logFormat,
				LogSeverity: opts.logSeverity,
				StarterSet:  starterSet,
			}
			srv, err := server.New(ctx, snap, srvOpts)
			if err != nil {
				return err
			}
			defer func() {
				if stopErr := srv.Stop(); stopErr != nil {
					slog.Error("server shutdown error", "error", stopErr)
				}
			}()

			return srv.Run(ctx, source)
		},
	}

	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	flags := cmd.Flags()
	flags.StringVar(&opts.configSource, "config-source", opts.configSource, "Use the named config source plugin.")
	flags.StringVar(&opts.configPath, "config", opts.configPath, "Path to a YAML or CBOR config file for the disk config source.")
	flags.StringVar(&opts.k8sConfig, "k8s-config", opts.k8sConfig, "Kubernetes config source spec in the form configmap/<NAME>.")
	flags.StringVar(&opts.k8sNamespace, "k8s-namespace", opts.k8sNamespace, "Kubernetes namespace for the k8s config source.")
	flags.StringVar(&opts.logFormat, "log-format", opts.logFormat, `Bootstrap log output format: "json" or "text". Also used as the default logging format if config source does not set it.`)
	flags.StringVar(&opts.logSeverity, "log-severity", opts.logSeverity, `Bootstrap minimum log severity: "debug", "info", "warn", or "error". Also used as the default logging severity if config source does not set it.`)

	// Subcommands
	cmd.AddCommand(newConfigSchemaCmd())

	return cmd
}

func newConfigSchemaCmd() *cobra.Command {
	return &cobra.Command{
		Use:          "config-schema",
		Short:        "Emit the khaled configuration JSON Schema",
		Long:         "config-schema prints the JSON Schema for khaled configuration,\nassembled from all registered plugin contributions.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			registry, err := registryFactory()
			if err != nil {
				return fmt.Errorf("build config schema: %w", err)
			}
			data, err := registry.MarshalJSON()
			if err != nil {
				return fmt.Errorf("marshal config schema: %w", err)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), string(data)); err != nil {
				return err
			}
			return nil
		},
	}
}

func defaultOptions() options {
	return options{
		configSource: envOrDefault(envConfigSource, defaultConfigSource),
		configPath:   envOrDefault(envConfigPath, defaultConfigPath),
		k8sConfig:    envOrDefault(envK8sConfig, ""),
		k8sNamespace: envOrDefault(envK8sNamespace, ""),
		logFormat:    envOrDefault(envLogFormat, ""),
		logSeverity:  envOrDefault(envLogSeverity, ""),
	}
}

// envOrDefault returns the environment variable $name or the contents of `fallback`
// if it is empty.
func envOrDefault(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func newConfigSource(opts options, registry *schema.Registry) (configsource.Source, error) {
	args := plugin.ConfigSourceArgs{
		PluginName: opts.configSource,
		Validate:   registry.Validate,
	}
	args.Disk.Path = opts.configPath
	args.K8s.Config = opts.k8sConfig
	args.K8s.Namespace = opts.k8sNamespace
	return plugin.NewConfigSource(args)
}
