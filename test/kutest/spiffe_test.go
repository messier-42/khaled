//go:build integration_k8s

package kutest

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	"sigs.k8s.io/yaml"
)

// khaledBaseURL is the in-cluster base URL the cabetool pod uses to
// reach khaled. The chart's fullname helper collapses to just the
// release name when release name == chart name, which is the case
// here (release "khaled", chart "khaled"), so the Service is named
// "khaled" (not "khaled-khaled"). The /ckap/ path prefix matches
// what khaled's HTTP transport registers handlers under.
const khaledBaseURL = "https://khaled.default.svc:443/ckap/"

// serverSPIFFEIDRegex matches khaled's SPIFFE ID (issued by SPIRE
// per the ClusterSPIFFEID applied by KhaledHelper). Cabetool's
// --server-spiffe-id-regex requires an RE2 pattern.
const serverSPIFFEIDRegex = `^spiffe://example\.test/khaled$`

// cabetoolURIRegex matches the SPIFFE ID SPIRE issues to the
// cabetool pod via the k8s-pod-shaped ClusterSPIFFEID applied by
// CabetoolHelper. Used to assert the round-trip through khaled's
// claims-mapping echoes back a SVID URI for *this* cabetool pod
// (UID and pod-name will vary across runs, so we check the shape
// rather than a literal string).
var cabetoolURIRegex = regexp.MustCompile(`^spiffe://example\.test/ns/default/sa/default/pod/cabetool-[^/]+/[0-9a-f-]+$`)

// TestSPIFFE_GetSelf is the smoke that proves the entire SPIFFE
// topology is wired correctly: cabetool obtains an SVID via the
// Workload API, dials khaled with mTLS using that SVID, khaled
// authenticates the peer cert against its tls-spiffe authenticator
// and runs the static claims mapper, and the principal URI khaled
// echoes back matches the SPIRE-issued SVID URI.
//
// If this test fails, every other Feature in this suite is moot.
func TestSPIFFE_GetSelf(t *testing.T) {
	feature := features.New("SPIFFE GetSelf round-trip").
		Assess("cabetool whoami returns the SPIRE-issued SVID URI", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}
			// We deliberately use cabetool's YAML output (default,
			// not -J) here because k8s-attestation produces nested
			// labels/annotations maps that trip cabetool's JSON
			// marshaller — `json: unsupported type:
			// map[interface{}]interface{}`. The bug is that the
			// CBOR decoder behind ldclabs/cose/key.UnmarshalCBOR
			// produces interface-keyed maps for nested any values,
			// and encoding/json refuses those. YAML marshals them
			// fine; sigs.k8s.io/yaml on the parsing side normalises
			// to map[string]any. Tracking in
			// cabetool-change-requirements.md.
			stdout, stderr, err := ExecInPodFirst(ctx, client,
				CabetoolNamespace, "app.kubernetes.io/name=cabetool",
				"cabetool", "whoami",
				"--base-url", khaledBaseURL,
				"--spiffe-socket", "/spiffe-workload-api/socket",
				"--server-spiffe-id-regex", serverSPIFFEIDRegex,
			)
			if err != nil {
				t.Fatalf("cabetool whoami failed: %v\nstderr: %s", err, stderr)
			}
			var out struct {
				Principal struct {
					URI string `json:"uri" yaml:"uri"`
				} `json:"principal" yaml:"principal"`
			}
			if perr := yaml.Unmarshal([]byte(stdout), &out); perr != nil {
				t.Fatalf("decode whoami YAML: %v\nstdout: %s", perr, stdout)
			}
			if !cabetoolURIRegex.MatchString(out.Principal.URI) {
				t.Errorf("principal.uri = %q, want match for %s\nfull stdout: %s",
					out.Principal.URI, cabetoolURIRegex, stdout)
			}
			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}

// TestSPIFFE_PrograadeRetrograde drives an encap → decap round trip
// through khaled. The encap call mints a fresh Lease (Prograde under
// the hood); the decap call rederives the lease key (Retrograde)
// and unwraps the CBES envelope. If the COSE key bytes diverged
// between the two paths, decap would fail with an AEAD authentication
// error.
//
// This Feature is the load-bearing proof that khaled's keystorage
// PVC actually persists usable lease state — an in-process suite
// can't catch a SQLite corruption / fsync regression that only
// shows up under a real volume mount.
func TestSPIFFE_PrograadeRetrograde(t *testing.T) {
	feature := features.New("Prograde/Retrograde round-trip via cabetool").
		Assess("encap then decap recovers the original message", func(ctx context.Context, t *testing.T, cfg *envconf.Config) context.Context {
			client, err := cfg.NewClient()
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			plaintext := "hello-from-kutest"
			// Encap: read plaintext from stdin via /dev/stdin… kubectl
			// exec doesn't pipe stdin from us, so use a shell here-doc.
			// busybox sh handles `printf | command` cleanly.
			encapCmd := fmt.Sprintf(
				"printf %%s '%s' | cabetool encap -J --attr env=str:test --base-url %s --spiffe-socket /spiffe-workload-api/socket --server-spiffe-id-regex '%s'",
				plaintext, khaledBaseURL, serverSPIFFEIDRegex,
			)
			envelopeJSON, stderr, err := ExecInPodFirst(ctx, client,
				CabetoolNamespace, "app.kubernetes.io/name=cabetool",
				"sh", "-c", encapCmd,
			)
			if err != nil {
				t.Fatalf("cabetool encap failed: %v\nstderr: %s", err, stderr)
			}
			if strings.TrimSpace(envelopeJSON) == "" {
				t.Fatalf("cabetool encap produced empty output")
			}

			// Decap: feed the envelope back in. cabetool's encap output
			// (without --out) is the envelope as binary on stdout when
			// not in JSON mode. Re-run encap *without* -J so we get
			// the raw envelope to feed to decap.
			encapBinaryCmd := fmt.Sprintf(
				"printf %%s '%s' | cabetool encap --attr env=str:test --base-url %s --spiffe-socket /spiffe-workload-api/socket --server-spiffe-id-regex '%s' | cabetool decap --base-url %s --spiffe-socket /spiffe-workload-api/socket --server-spiffe-id-regex '%s'",
				plaintext, khaledBaseURL, serverSPIFFEIDRegex,
				khaledBaseURL, serverSPIFFEIDRegex,
			)
			recovered, stderr, err := ExecInPodFirst(ctx, client,
				CabetoolNamespace, "app.kubernetes.io/name=cabetool",
				"sh", "-c", encapBinaryCmd,
			)
			if err != nil {
				t.Fatalf("encap|decap pipeline failed: %v\nstderr: %s", err, stderr)
			}
			if strings.TrimSpace(recovered) != plaintext {
				t.Errorf("recovered plaintext = %q, want %q\nstderr: %s",
					recovered, plaintext, stderr)
			}
			return ctx
		}).
		Feature()

	testEnv.Test(t, feature)
}
