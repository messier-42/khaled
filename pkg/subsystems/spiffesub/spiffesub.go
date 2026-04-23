// Package spiffesub provides the shared SPIFFE X.509 source subsystem.
//
// The manager is constructed at startup from the top-level
// `spiffe` config block and is consumed by listeners (for server
// certificates) and the tls-spiffe Authenticator (for the trust
// bundle).
//
// The spiffe.workloadSocketPath config setting is bootstrap-only;
// changes at reload time are warned about by Apply and ignored.
// This keeps the reload process simple; listeners and the authenticator
// do not need to be rebuilt in response to a socket path change.
//
// When the snapshot does not require SPIFFE (no listener uses
// serverCertificate.source=spiffe and clientAuthn is not
// tls-spiffe), the manager is kept in the empty state and Source
// returns nil.
package spiffesub

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/messier-42/khaled/pkg/config"
	"github.com/messier-42/khaled/pkg/lifecycle"
	"github.com/messier-42/khaled/pkg/x509source"
)

// Manager owns the single SPIFFE-backed x509source.Source shared
// across subsystems. New always returns a non-nil *Manager; when
// the snapshot does not require SPIFFE, Current returns nil.
//
// Manager is a lifecycle.Manager configured with the spiffesub-specific
// Apply; the underlying x509source.Source is obtained via Current.
// Reconcile is a Validate-only path: socket path changes are warned
// about and ignored. Rebuilds currently never occur.
type Manager = lifecycle.Manager[x509source.Source]

// New constructs a Shared manager. If snap requires SPIFFE
// somewhere (clientAuthn.use = tls-spiffe, or any listener's
// serverCertificate.source = spiffe), the shared source is built
// and held; otherwise the manager starts empty.
func New(ctx context.Context, snap config.Snapshot) (*Manager, error) {
	return lifecycle.New(ctx, snap, spec())
}

// NewEmpty returns a Shared with no source configured. Used for testing.
func NewEmpty() *Manager {
	return lifecycle.NewEmpty(spec())
}

func spec() lifecycle.Spec[x509source.Source] {
	return lifecycle.Spec[x509source.Source]{
		Name: "shared SPIFFE source",
		Apply: func(ctx context.Context, old x509source.Source, oldSnap, newSnap config.Snapshot) (x509source.Source, error) {
			if !SnapshotNeedsSPIFFE(newSnap) {
				return nil, nil
			}
			newPath := socketPath(newSnap)
			if old != nil {
				// Keep the existing source. Warn if he socket path changed from
				// what we originally bound to.
				if oldPath := socketPath(oldSnap); newPath != oldPath {
					slog.Warn("spiffe.workloadSocketPath changed at reload; bootstrap-only setting",
						"old", oldPath,
						"new", newPath,
					)
				}
				return old, nil
			}
			src, err := x509source.New(ctx, x509source.Config{
				Kind:               x509source.KindSPIFFE,
				WorkloadSocketPath: newPath,
			})
			if err != nil {
				return nil, fmt.Errorf("shared SPIFFE source: %w", err)
			}
			return src, nil
		},
		Close: func(src x509source.Source) error { return src.Close() },
	}
}

func socketPath(snap config.Snapshot) string {
	spiffeBlock, _ := snap.Root.GetMap("spiffe")
	path, _ := spiffeBlock.GetString("workloadSocketPath")
	return path
}

// SnapshotNeedsSPIFFE reports whether snap requires a shared SPIFFE
// source; namely where either the client authenticator is tls-spiffe,
// or some listener's server certificate source is spiffe.
func SnapshotNeedsSPIFFE(snap config.Snapshot) bool {
	if ca, ok := snap.Root.GetMap("clientAuthn"); ok {
		if use, ok := ca.GetString("use"); ok && use == "tls-spiffe" {
			return true
		}
	}
	listeners, _ := snap.Root.GetArray("listeners")
	for _, entry := range listeners {
		obj, ok := entry.(config.Map)
		if !ok {
			continue
		}
		httpBlock, _ := obj.GetMap("http")
		tlsBlock, _ := httpBlock.GetMap("tls")
		serverCert, _ := tlsBlock.GetMap("serverCertificate")
		src, _ := serverCert.GetString("source")
		if src == "spiffe" {
			return true
		}
	}
	return false
}
