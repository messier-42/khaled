package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/config/schema"
	"github.com/messier-42/khaled/pkg/keyserver"
	"github.com/messier-42/khaled/pkg/plugin/claimsmapping"
	"github.com/messier-42/khaled/pkg/plugin/clientauthn"
	"github.com/messier-42/khaled/pkg/plugin/transport"
	httpt "github.com/messier-42/khaled/pkg/plugin/transport/http"
	"github.com/messier-42/khaled/pkg/x509source"
)

// TransportDeps provides runtime dependencies that transports
// may require to operate.
type TransportDeps struct {
	// SharedSPIFFE is the shared SPIFFE-backed x509source.Source
	// built from the configuration's global top-level `spiffe` block.
	// This avoids the need for a listener to manage its own workload
	// API connection if it uses SPIFFE.
	SharedSPIFFE x509source.Source

	// Authn and Claims, if non-nil, return the current Client
	// Authentication and Claims Mapping middleware on every request.
	// Delegates (rather than direct plugin references) are used here
	// to support atomic plugin swap on config reload. The middleware
	// invokes these functions per request.
	Authn  func() clientauthn.Authenticator
	Claims func() claimsmapping.ClaimsMapper

	// Keyserver returns the current key server implementation that backs
	// the CKAP operation endpoints. A delegate is used to support atomic
	// keyserver swap on config reload. The transport invokes it per request.
	Keyserver func() *keyserver.Server
}

// NewTransport instantiates a Transport plugin for a single
// listeners entry in the khaled config. The plugin name is read from the
// entry's `use` field. root is the full configuration snapshot root. Access
// to the full config is provided as some transports read global top-level fields.
// deps provides runtime dependencies to be injected.
//
// All structural validation is expected to have been done already by
// the config schema.
//
// The returned Transport owns any per-listener resources constructed
// here (e.g. a file-backed x509 source for the listener that is not
// covered by deps.SharedSPIFFE). Those resources are released when
// Transport.Close is called.
func NewTransport(ctx context.Context, entry config.Map, root config.Map, deps TransportDeps) (transport.Transport, error) {
	use, ok := entry.GetString("use")
	if !ok || use == "" {
		return nil, errors.New("listeners[]: use is required")
	}

	switch use {
	case "http":
		return newHTTPTransport(ctx, entry, root, deps)
	default:
		return nil, fmt.Errorf("unsupported transport %q", use)
	}
}

// newHTTPTransport builds the http transport, materialising its
// certificate source and (optional) keylog writer from the snapshot
// and wrapping the result so those per-listener resources are
// released alongside the transport.
func newHTTPTransport(ctx context.Context, entry config.Map, root config.Map, deps TransportDeps) (transport.Transport, error) {
	cfg, err := httpt.ConfigFromSnapshot(entry, root)
	if err != nil {
		return nil, err
	}

	certCfg := httpt.CertConfigFromSnapshot(entry, root)
	certSrc, ownsCert, err := acquireCertSource(ctx, certCfg, deps.SharedSPIFFE)
	if err != nil {
		return nil, err
	}

	var keyLog io.WriteCloser
	if path := httpt.KeyLogPathFromSnapshot(entry); path != "" {
		fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			if ownsCert {
				_ = certSrc.Close()
			}
			return nil, fmt.Errorf("http transport: open keylog file: %w", err)
		}
		keyLog = fh
	}

	cfg.CertSource = certSrc
	cfg.KeyLog = keyLog
	cfg.GetAuthnFunc = deps.Authn
	cfg.GetClaimsMapperFunc = deps.Claims
	cfg.GetKeyServerFunc = deps.Keyserver

	inner, err := httpt.New(ctx, cfg)
	if err != nil {
		// httpt.New has already closed keyLog if it observed it.
		if ownsCert {
			_ = certSrc.Close()
		}
		return nil, err
	}
	if !ownsCert {
		return inner, nil
	}
	return &httpTransport{Transport: inner, ownedCert: certSrc}, nil
}

// acquireCertSource returns the x509source.Source the listener should
// use. If the listener's serverCertificate selects SPIFFE and a shared
// SPIFFE source is available, that shared source is returned and
// ownsCert is false (the caller must not close it). Otherwise a new
// source is built and ownsCert is true.
func acquireCertSource(ctx context.Context, cfg x509source.Config, sharedSPIFFE x509source.Source) (src x509source.Source, ownsCert bool, err error) {
	if cfg.Kind == x509source.KindSPIFFE && sharedSPIFFE != nil {
		return sharedSPIFFE, false, nil
	}
	s, err := x509source.New(ctx, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("http transport: %w", err)
	}
	return s, true, nil
}

// httpTransport wraps an *httpt.Transport so that a per-listener
// x509source.Source — built in this package when no shared source can
// serve the listener — is released when the transport is closed. The
// http transport itself does not close its CertSource.
type httpTransport struct {
	*httpt.Transport

	ownedCert x509source.Source
}

func (t *httpTransport) Close() error {
	err := t.Transport.Close()
	if cerr := t.ownedCert.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return err
}

// RegisterTransportSchemas contributes the `listeners[]` top-level
// schema plus listener-level custom validators. Each listener entry
// is itself a discriminated "use:" union.
func RegisterTransportSchemas(r *schema.Registry) error {
	entries := []*jsonschema.Schema{
		httpt.ListenerEntrySchema(),
	}

	if err := r.RegisterPath("listeners", &jsonschema.Schema{
		Type:  "array",
		Items: &jsonschema.Schema{OneOf: entries},
	}); err != nil {
		return err
	}
	if err := r.RegisterValidator(validateListenersNonEmpty); err != nil {
		return err
	}
	return r.RegisterValidator(validateListenersImmutableOnReload)
}

// validateListenersNonEmpty enforces that at least one listener is
// configured.
func validateListenersNonEmpty(_ context.Context, _ *config.Snapshot, snap config.Snapshot) error {
	listeners, ok := snap.Root.GetArray("listeners")
	if !ok || len(listeners) == 0 {
		return errors.New("listeners: at least one listener must be configured")
	}
	return nil
}

// validateListenersImmutableOnReload rejects any change to the
// top-level listeners block on a reload; listeners are started
// once during startup and are not in the reload loop, so changes
// on disk would otherwise be silently ignored.
func validateListenersImmutableOnReload(_ context.Context, oldConfig *config.Snapshot, snap config.Snapshot) error {
	if oldConfig == nil {
		return nil
	}
	oldL, _ := oldConfig.Root.GetArray("listeners")
	newL, _ := snap.Root.GetArray("listeners")
	if !reflect.DeepEqual(oldL, newL) {
		return errors.New("listeners: block is immutable on reload; restart the process to apply listener changes")
	}
	return nil
}
