// Package ocimeta provides utilities for gathering information about OCI image
// archives.
package ocimeta

import (
	"archive/tar"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

const (
	refNameAnnotation  = "org.opencontainers.image.ref.name"
	refNameAnnotation2 = "io.containerd.image.name"
)

var (
	ErrIndexNotFound          = errors.New("oci index.json not found in archive")
	ErrRefNameAnnotationEmpty = errors.New("org.opencontainers.image.ref.name annotation not found")
)

// RefNameFromArchive scans an OCI image tar archive for index.json and returns the
// org.opencontainers.image.ref.name annotation if it exists either on the index
// itself or on any of its manifest descriptors.
func RefNameFromArchive(r io.Reader) (string, error) {
	idx, err := loadIndexManifest(r)
	if err != nil {
		return "", err
	}

	if ref := idx.Annotations[refNameAnnotation2]; ref != "" {
		return ref, nil
	}

	if ref := idx.Annotations[refNameAnnotation]; ref != "" {
		return ref, nil
	}

	for _, desc := range idx.Manifests {
		if ref := desc.Annotations[refNameAnnotation2]; ref != "" {
			return ref, nil
		}

		if ref := desc.Annotations[refNameAnnotation]; ref != "" {
			return ref, nil
		}
	}

	return "", ErrRefNameAnnotationEmpty
}

func loadIndexManifest(r io.Reader) (*v1.IndexManifest, error) {
	data, err := readIndexJSON(r)
	if err != nil {
		return nil, err
	}

	idx, err := v1.ParseIndexManifest(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	return idx, nil
}

func readIndexJSON(r io.Reader) ([]byte, error) {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, ErrIndexNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}

		if hdr.FileInfo().IsDir() {
			continue
		}

		if isIndexJSON(hdr.Name) {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("read index.json: %w", err)
			}
			return data, nil
		}
	}
}

func isIndexJSON(name string) bool {
	clean := path.Clean(name)
	clean = strings.TrimPrefix(clean, "./")
	return clean == "index.json" || path.Base(clean) == "index.json"
}
