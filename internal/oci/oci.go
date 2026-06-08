// Package oci pulls digest-pinned images and extracts the entrypoint binary.
// Daemonless: pure go-containerregistry (Spike A: pull-by-digest verified,
// CGO_ENABLED=0 static builds preserved, OCI-layout reads work offline).
//
// Packaging is static self-contained binaries (spec decision #2): exactly
// one file is extracted and later bind-mounted at /app/server by the existing
// sandbox — NO internal/sandbox changes.
//
// The pinned digest may be EITHER a single platform image manifest (legacy
// single-arch servers) OR a multi-arch image index / Docker manifest list. The
// index is the content-addressed root of trust: we verify the fetched index's
// digest against the pin, then select the child manifest matching the host
// platform. That child digest comes FROM the verified index, so it is
// transitively trusted and is NOT re-compared to the pin (doing so was the
// "digest mismatch" bug — comparing an amd64 sub-manifest to the index pin).
package oci

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Puller fetches images by digest. If LayoutDir is set, images are read from
// an OCI layout directory (hermetic tests, air-gapped installs) instead of a
// remote registry.
type Puller struct {
	LayoutDir string
}

// Extract pulls imageRef pinned to digest, verifies content-addressing against
// the pin, resolves the host platform if the pin is a multi-arch index, and
// writes the regular file at entrypoint (absolute path inside the image) to
// dest with mode 0555.
func (p *Puller) Extract(ctx context.Context, imageRef, digest, entrypoint, dest string) error {
	want, err := v1.NewHash(digest)
	if err != nil {
		return fmt.Errorf("oci: bad digest %q: %w", digest, err)
	}
	var img v1.Image
	if p.LayoutDir != "" {
		img, err = p.imageFromLayout(want, digest)
	} else {
		img, err = p.imageFromRemote(ctx, imageRef, digest, want)
	}
	if err != nil {
		return err
	}
	return extractFile(img, entrypoint, dest)
}

// imageFromRemote fetches the pinned descriptor, then dispatches on whether it
// is an image index (multi-arch) or a single image manifest. In both cases the
// digest of what arrived is anchored to the pin before any layer is read.
func (p *Puller) imageFromRemote(ctx context.Context, imageRef, digest string, want v1.Hash) (v1.Image, error) {
	ref, err := name.NewDigest(imageRef + "@" + digest)
	if err != nil {
		return nil, fmt.Errorf("oci: bad ref %s@%s: %w", imageRef, digest, err)
	}
	// remote.Get leaves the response un-interpreted so we can tell an index from
	// an image manifest by its media type (remote.Image would silently resolve
	// an index to a platform child, which is exactly what masked the pin/child
	// digest confusion before).
	desc, err := remote.Get(ref, remote.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("oci: get %s: %w", ref, err)
	}

	switch {
	case desc.MediaType.IsIndex():
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, fmt.Errorf("oci: read index %s: %w", ref, err)
		}
		// The pin IS the index digest: verify the index is content-addressed to
		// the pin before trusting any child descriptor it names.
		if err := verifyDigest(idx, want, "index"); err != nil {
			return nil, err
		}
		return imageForHost(idx)
	case desc.MediaType.IsImage():
		img, err := desc.Image()
		if err != nil {
			return nil, fmt.Errorf("oci: read image %s: %w", ref, err)
		}
		// Single-arch legacy pin: keep exact-digest behavior unchanged.
		if err := verifyDigest(img, want, "image"); err != nil {
			return nil, err
		}
		return img, nil
	default:
		return nil, fmt.Errorf("oci: %s: unsupported media type %s", ref, desc.MediaType)
	}
}

// imageFromLayout resolves the pinned digest from an OCI layout directory.
//
// NOTE: layout layer blobs are not hash-re-verified on read; LayoutDir must be
// trusted storage (tests, air-gapped installs). The remote path verifies blob
// hashes on stream. The pinned digest is looked up as a child descriptor of the
// layout's top-level index; we dispatch on that child's media type so a
// multi-arch pin resolves to the host platform just like the remote path.
func (p *Puller) imageFromLayout(want v1.Hash, digest string) (v1.Image, error) {
	lp, err := layout.FromPath(p.LayoutDir)
	if err != nil {
		return nil, fmt.Errorf("oci: open layout %s: %w", p.LayoutDir, err)
	}
	top, err := lp.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("oci: read layout index: %w", err)
	}
	man, err := top.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("oci: parse layout index: %w", err)
	}
	for _, d := range man.Manifests {
		if d.Digest != want {
			continue
		}
		if d.MediaType.IsIndex() {
			idx, err := top.ImageIndex(want)
			if err != nil {
				return nil, fmt.Errorf("oci: read index %s from layout: %w", digest, err)
			}
			return imageForHost(idx)
		}
		img, err := top.Image(want)
		if err != nil {
			return nil, fmt.Errorf("oci: read image %s from layout: %w", digest, err)
		}
		return img, nil
	}
	return nil, fmt.Errorf("oci: digest %s not in layout", digest)
}

// hostPlatform is the OCI platform of the gateway host. Go's GOARCH naming
// (amd64/arm64/...) matches OCI image-config architecture naming directly.
func hostPlatform() v1.Platform {
	return v1.Platform{OS: "linux", Architecture: runtime.GOARCH}
}

// imageForHost selects, from a verified index, the child image manifest whose
// platform satisfies the host platform. The child digest is trusted because it
// is named by the already-verified index, so it is NOT re-compared to the pin.
func imageForHost(idx v1.ImageIndex) (v1.Image, error) {
	man, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("oci: parse index manifest: %w", err)
	}
	host := hostPlatform()
	for _, d := range man.Manifests {
		if d.Platform == nil {
			continue
		}
		// Satisfies treats empty spec fields as wildcards; host pins os+arch.
		if d.Platform.Satisfies(host) {
			img, err := idx.Image(d.Digest)
			if err != nil {
				return nil, fmt.Errorf("oci: read child image %s: %w", d.Digest, err)
			}
			return img, nil
		}
	}
	return nil, fmt.Errorf("oci: image index has no %s/%s entry", host.OS, host.Architecture)
}

// verifyDigest re-derives the digest of what actually arrived and anchors it to
// the pin. kind is "index" or "image" for the error message.
func verifyDigest(d interface{ Digest() (v1.Hash, error) }, want v1.Hash, kind string) error {
	got, err := d.Digest()
	if err != nil {
		return fmt.Errorf("oci: digest of pulled %s: %w", kind, err)
	}
	if got != want {
		return fmt.Errorf("oci: digest mismatch: pulled %s %s, manifest pins %s", kind, got, want)
	}
	return nil
}

// extractFile streams the flattened rootfs (whiteouts applied) and writes the
// entrypoint file to dest.
func extractFile(img v1.Image, entrypoint, dest string) error {
	wantName := strings.TrimPrefix(entrypoint, "/")
	rc := mutate.Extract(img)
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("oci: read rootfs: %w", err)
		}
		if filepath.Clean(hdr.Name) != wantName {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("oci: entrypoint %s is not a regular file", entrypoint)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		// Remove existing file first to avoid EPERM on re-extract over 0555.
		os.Remove(dest) // ignore error — file may not exist
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o555)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			os.Remove(dest)
			return fmt.Errorf("oci: write %s: %w", dest, err)
		}
		return f.Close()
	}
	return fmt.Errorf("oci: entrypoint %s not found in image rootfs", entrypoint)
}
