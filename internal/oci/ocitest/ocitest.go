// Package ocitest builds tiny OCI-layout image fixtures for hermetic tests
// (Spike A verified layout write→read-by-digest→extract works offline).
package ocitest

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"sort"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// imageWithFiles builds a single-layer image whose rootfs holds files (path
// inside image WITHOUT leading slash → contents, mode 0755).
func imageWithFiles(files map[string][]byte) (v1.Image, error) {
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
			return nil, err
		}
		if _, err := tw.Write(contents); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	layerBytes := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerBytes)), nil
	})
	if err != nil {
		return nil, err
	}
	return mutate.AppendLayers(empty.Image, layer)
}

// ArchFiles names the per-platform rootfs of a multi-arch index entry.
type ArchFiles struct {
	OS, Arch string
	Files    map[string][]byte
}

// WriteLayoutIndex writes an OCI layout at dir containing one multi-arch image
// index whose child images carry the given per-platform rootfs. Returns the
// INDEX (manifest-list) digest — the digest a manifest would pin for a
// multi-arch server. Each child entry's descriptor carries its platform so the
// puller can select the host arch.
func WriteLayoutIndex(dir string, entries []ArchFiles) (string, error) {
	idx := v1.ImageIndex(empty.Index)
	for _, e := range entries {
		img, err := imageWithFiles(e.Files)
		if err != nil {
			return "", err
		}
		plat := &v1.Platform{OS: e.OS, Architecture: e.Arch}
		mt, err := img.MediaType()
		if err != nil {
			return "", err
		}
		idx = mutate.AppendManifests(idx, mutate.IndexAddendum{
			Add: img,
			Descriptor: v1.Descriptor{
				MediaType: mt,
				Platform:  plat,
			},
		})
	}
	digest, err := idx.Digest()
	if err != nil {
		return "", err
	}
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		return "", fmt.Errorf("ocitest: write layout: %w", err)
	}
	if err := lp.AppendIndex(idx); err != nil {
		return "", err
	}
	return digest.String(), nil
}

// WriteLayoutImage writes an OCI layout at dir containing one single-layer
// image whose rootfs holds files (path inside image, WITHOUT leading slash →
// contents, mode 0755). Returns the image-manifest digest ("sha256:...") —
// the digest a manifest would pin.
func WriteLayoutImage(dir string, files map[string][]byte) (string, error) {
	img, err := imageWithFiles(files)
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
