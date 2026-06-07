// Package oci pulls digest-pinned images and extracts the entrypoint binary.
// Daemonless: pure go-containerregistry (Spike A: pull-by-digest verified,
// CGO_ENABLED=0 static builds preserved, OCI-layout reads work offline).
//
// v1 packaging is static self-contained binaries (spec decision #2): exactly
// one file is extracted and later bind-mounted at /app/server by the existing
// sandbox — NO internal/sandbox changes.
package oci

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// Extract pulls imageRef pinned to digest (a PLATFORM image-manifest digest,
// not a multi-arch index digest — Spike A), verifies the content digest
// matches, and writes the regular file at entrypoint (absolute path inside
// the image) to dest with mode 0555.
func (p *Puller) Extract(ctx context.Context, imageRef, digest, entrypoint, dest string) error {
	want, err := v1.NewHash(digest)
	if err != nil {
		return fmt.Errorf("oci: bad digest %q: %w", digest, err)
	}
	var img v1.Image
	if p.LayoutDir != "" {
		// NOTE: layout layer blobs are not hash-re-verified on read; LayoutDir
		// must be trusted storage (tests, air-gapped installs). The remote path
		// verifies blob hashes on stream.
		lp, err := layout.FromPath(p.LayoutDir)
		if err != nil {
			return fmt.Errorf("oci: open layout %s: %w", p.LayoutDir, err)
		}
		img, err = lp.Image(want)
		if err != nil {
			return fmt.Errorf("oci: image %s not in layout: %w", digest, err)
		}
	} else {
		ref, err := name.NewDigest(imageRef + "@" + digest)
		if err != nil {
			return fmt.Errorf("oci: bad ref %s@%s: %w", imageRef, digest, err)
		}
		img, err = remote.Image(ref, remote.WithContext(ctx))
		if err != nil {
			return fmt.Errorf("oci: pull %s: %w", ref, err)
		}
	}
	// Belt-and-suspenders: re-derive the digest of what actually arrived.
	got, err := img.Digest()
	if err != nil {
		return fmt.Errorf("oci: digest of pulled image: %w", err)
	}
	if got != want {
		return fmt.Errorf("oci: digest mismatch: pulled %s, manifest pins %s", got, want)
	}
	return extractFile(img, entrypoint, dest)
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
