// Package ocitest builds tiny OCI-layout image fixtures for hermetic tests
// (Spike A verified layout write→read-by-digest→extract works offline).
package ocitest

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"sort"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// WriteLayoutImage writes an OCI layout at dir containing one single-layer
// image whose rootfs holds files (path inside image, WITHOUT leading slash →
// contents, mode 0755). Returns the image-manifest digest ("sha256:...") —
// the digest a manifest would pin.
func WriteLayoutImage(dir string, files map[string][]byte) (string, error) {
	// Sort keys for deterministic layer digest across runs.
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, name := range keys {
		contents := files[name]
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(contents)), Typeflag: tar.TypeReg,
		}); err != nil {
			return "", err
		}
		if _, err := tw.Write(contents); err != nil {
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	layerBytes := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerBytes)), nil
	})
	if err != nil {
		return "", err
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return "", err
	}
	digest, err := img.Digest()
	if err != nil {
		return "", err
	}
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		return "", fmt.Errorf("ocitest: write layout: %w", err)
	}
	if err := lp.AppendImage(img); err != nil {
		return "", err
	}
	return digest.String(), nil
}
