package kutest

import (
	"context"
	"io"
	"os"

	log "k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"

	"github.com/messier-42/khaled/test/kutest/preloader"
)

// PreloadImagesHelper streams every OCI archive in cfg.Images into
// every cluster node's containerd via a privileged nerdctl DaemonSet
// (see the preloader package). This is the kind-compatible alternative
// to a registry: the chart's image.repository / image.tag must match
// the OCI archive's recorded ref, but no remote pull is involved.
//
// Ported from qhx-core's kutest.
type PreloadImagesHelperConfig struct {
	Images []string
}

type PreloadImagesHelper struct {
	cfg PreloadImagesHelperConfig
}

var _ Helper = &PreloadImagesHelper{}

func NewPreloadImagesHelper(cfg PreloadImagesHelperConfig) *PreloadImagesHelper {
	return &PreloadImagesHelper{cfg: cfg}
}

func (ch *PreloadImagesHelper) String() string { return "Preload OCI images into kind nodes" }

func (ch *PreloadImagesHelper) Setup() env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		log.V(0).InfoS("Preloading images", "count", len(ch.cfg.Images))
		client, err := cfg.NewClient()
		if err != nil {
			return nil, err
		}

		factories := make([]preloader.ReaderFactory, 0, len(ch.cfg.Images))
		for _, p := range ch.cfg.Images {
			factories = append(factories, makeReaderFactory(p))
		}

		if err := preloader.Preload(ctx, preloader.PreloadArgs{
			Client: client,
			Images: factories,
		}); err != nil {
			return nil, err
		}
		log.V(2).InfoS("Image preloading complete")
		return ctx, nil
	}
}

func (ch *PreloadImagesHelper) Finish() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) { return ctx, nil }
}

func makeReaderFactory(path string) preloader.ReaderFactory {
	return func() (io.ReadCloser, error) { return os.Open(path) }
}
