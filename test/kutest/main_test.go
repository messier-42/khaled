//go:build integration_k8s

package kutest

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	log "k8s.io/klog/v2"

	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc" // For AWS EKS

	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/messier-42/khaled/test/kutest/ocimeta"
)

// minTestTimeout guards against forgetting `-timeout=0` on the
// command line: the suite needs an effectively unbounded budget
// because cluster bringup alone burns several minutes.
const minTestTimeout = 20 * time.Minute

var testEnv *kutestEnvironment

// khaledImageRef and cabetoolImageRef are populated from each OCI
// archive's recorded ref at preload time; helpers (and the chart
// values they emit) reference these so chart and image stay in sync
// without a fragile string.
var (
	khaledImageRef   string
	cabetoolImageRef string
)

type targetTypeT string

var (
	targetTypeBuiltinKind targetTypeT = "builtin-kind"
	targetTypeExternal    targetTypeT = "external"
)

// TestMain wires the helper chain. Stage 1 lands the generic
// scaffolding only; SPIRE / khaled / cabetool helpers land in the
// next commit. The main test (TestAllTimeoutsDisabled) is a
// guardrail, not a real integration scenario yet.
func TestMain(m *testing.M) {
	targetType := targetTypeT(os.Getenv("KUTEST_TARGET_TYPE"))
	ociImagesPath := os.Getenv("KUTEST_OCI_IMAGES_PATH")
	chartPath := os.Getenv("KUTEST_HELM_CHART")

	switch targetType {
	case targetTypeBuiltinKind, targetTypeExternal:
	case "":
		targetType = targetTypeBuiltinKind
		log.InfoS("KUTEST_TARGET_TYPE not set; defaulting", "targetType", targetType)
	default:
		log.Fatalf("env $KUTEST_TARGET_TYPE must be one of: builtin-kind, external")
	}

	if ociImagesPath == "" {
		log.Fatalf("env $KUTEST_OCI_IMAGES_PATH must be specified (path to a directory containing khaled*.oci and cabetool*.oci)")
	}
	if chartPath == "" {
		log.Fatalf("env $KUTEST_HELM_CHART must be specified (path to khaled chart .tgz produced by `make chart`)")
	}

	cfg, err := envconf.NewFromFlags()
	if err != nil {
		fmt.Printf("error: envconf: %v\n", err)
		os.Exit(1)
	}
	integrationBailAndKeep.setKubeconfigPath(cfg.KubeconfigFile())

	var helpers []Helper
	helpers = append(helpers, NewScratchDirHelper())

	switch targetType {
	case targetTypeBuiltinKind:
		helpers = append(helpers, NewKindHelper())
	case targetTypeExternal:
		// External cluster: caller's KUBECONFIG must already point at
		// a kind/k3d/etc cluster with the SPIFFE CSI driver
		// installable.
	}

	helpers = append(helpers, NewNodeWaitHelper())

	khaledImagePath, khaledRef, err := loadOCIImageRef(ociImagesPath, "khaled")
	if err != nil {
		log.Fatalf("could not find khaled image in %q: %v", ociImagesPath, err)
	}
	khaledImageRef = khaledRef
	cabetoolImagePath, cabetoolRef, err := loadOCIImageRef(ociImagesPath, "cabetool")
	if err != nil {
		log.Fatalf("could not find cabetool image in %q: %v", ociImagesPath, err)
	}
	cabetoolImageRef = cabetoolRef
	log.InfoS("preloading images", "khaled", khaledImageRef, "cabetool", cabetoolImageRef)

	helpers = append(helpers, NewPreloadImagesHelper(PreloadImagesHelperConfig{
		Images: []string{khaledImagePath, cabetoolImagePath},
	}))

	// SPIRE first so its CSI driver is in place before khaled and
	// cabetool come up; both pods mount csi.spiffe.io and would fail
	// to schedule otherwise.
	helpers = append(helpers, NewSpireHelper())
	helpers = append(helpers, NewKhaledHelper(KhaledHelperConfig{
		ChartPath: chartPath,
		ImageRef:  khaledImageRef,
		// k8s-attestation is enabled cluster-wide so the Stage 2
		// attestation Features can drive cabetool against a server
		// that actually attests pods. Stage 1 + ConfigSource Features
		// also work under k8s-attestation because cabetool's SVID is
		// issued from the standard k8s-pod template (see
		// CabetoolPodSPIFFEIDTemplate), which the plugin parses
		// successfully and resolves to the live cabetool pod.
		ClaimsMappingMode: "k8s-attestation",
	}))
	helpers = append(helpers, NewCabetoolHelper(CabetoolHelperConfig{
		ImageRef: cabetoolImageRef,
	}))

	setupFuncs := make([]env.Func, 0, len(helpers))
	finishFuncs := make([]env.Func, 0, len(helpers))
	for _, h := range helpers {
		setupFuncs = append(setupFuncs, h.Setup())
		finishFunc := h.Finish()
		name := h.String()
		finishFuncs = append(finishFuncs, func(ctx context.Context, c *envconf.Config) (context.Context, error) {
			if integrationBailAndKeep.shouldSkipCleanup() {
				log.V(0).InfoS("Skipping helper finish due to KUTEST_BAIL_AND_KEEP mode", "helper", name)
				return ctx, nil
			}
			return finishFunc(ctx, c)
		})
	}
	slices.Reverse(finishFuncs)

	testEnv = newKutestEnvironment(env.NewWithConfig(cfg), integrationBailAndKeep)
	testEnv.Setup(setupFuncs...)
	testEnv.Finish(finishFuncs...)

	os.Exit(testEnv.Run(m))
}

// loadOCIImageRef finds the single OCI archive matching `<name>*.oci`
// in dir and returns its on-disk path plus the ref name recorded
// inside the archive.
func loadOCIImageRef(dir, name string) (string, string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, name+"*.oci"))
	if err != nil {
		return "", "", err
	}
	if len(matches) == 0 {
		return "", "", fmt.Errorf("no OCI archives matched %q", name)
	}
	if len(matches) > 1 {
		return "", "", fmt.Errorf("expected one OCI archive matching %q, found %d", name, len(matches))
	}
	ref, err := refNameFromArchive(matches[0])
	if err != nil {
		return "", "", err
	}
	return matches[0], ref, nil
}

func refNameFromArchive(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()
	ref, err := ocimeta.RefNameFromArchive(f)
	if err != nil {
		return "", fmt.Errorf("ref name from %q: %w", path, err)
	}
	return ref, nil
}

// TestAllTimeoutsDisabled is a guardrail against forgetting
// -timeout=0 on the command line. Without it, the runner would kill
// the suite mid-cluster-bringup with a confusing error.
func TestAllTimeoutsDisabled(t *testing.T) {
	flagValue := flag.Lookup("test.timeout")
	if flagValue == nil {
		t.Fatalf("expected -timeout flag to be passed to runner")
	}
	d, err := time.ParseDuration(flagValue.Value.String())
	if err != nil {
		t.Fatalf("bad timeout duration: %v", err)
	}
	if d != 0 && d < minTestTimeout {
		t.Fatalf("timeout %v is too short — pass -timeout=0", d)
	}
}

