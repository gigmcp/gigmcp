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
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Bundle caps (CONTRACT item 4). A toolpack bundle is a small, flat directory:
// the engine binary plus two inert YAML sidecars. These ceilings reject a
// tampered or pathological image before any layer byte is written to disk.
const (
	maxBundleFiles  = 8               // <= 8 regular files in the bundle dir
	maxBundleBytes  = 64 << 20        // <= 64 MiB total uncompressed
	maxSidecarBytes = 1 << 20         // each NON-entrypoint file <= 1 MiB
	manifestSidecar = "manifest.yaml" // cross-checked against the index manifest
	toolspecSidecar = "toolspec.yaml" // inert; integrity from the pinned digest
)

// ErrBundleContract is the sentinel wrapping every toolpack-bundle contract
// violation (extra file, subdir, symlink, second executable, oversize). It lets
// the installer/API surface a single typed class while the wrapped message names
// the specific offending entry. A tampered image must never run, so any of these
// rejects the install.
var ErrBundleContract = errors.New("oci: toolpack bundle contract violation")

// Bundle is the result of a toolpack multi-file extraction: the staging
// directory the three files were written to, and their basenames (sorted).
type Bundle struct {
	Dir   string   // staging dir under DataDir; bind-mounted read-only at the bundle path
	Files []string // basenames of the regular files extracted (sorted)
}

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

// ExtractBundle pulls imageRef (verifying content-addressing and resolving the
// host platform exactly as Extract does) and extracts ALL regular files that sit
// directly under the bundle directory — path.Dir(entrypoint), e.g. "/app" — into
// stageDir, enforcing the toolpack bundle contract (CONTRACT items 2-4):
//
//   - flat only: any tar entry under the bundle dir that is a subdirectory,
//     symlink, hardlink, device, or a file in a nested path is a violation;
//   - exec bits: only the entrypoint may carry an exec bit; a second executable
//     (any non-entrypoint regular file with an exec bit) is a violation;
//   - caps: <= maxBundleFiles files, <= maxBundleBytes total, each non-entrypoint
//     file <= maxSidecarBytes.
//
// The entrypoint is written 0755; the sidecars 0644. On any violation stageDir
// is removed and the error wraps ErrBundleContract. The returned Bundle.Dir is
// stageDir; callers bind-mount it read-only at the bundle path so /app/server,
// /app/manifest.yaml and /app/toolspec.yaml are all present in the sandbox.
func (p *Puller) ExtractBundle(ctx context.Context, imageRef, digest, entrypoint, stageDir string) (Bundle, error) {
	want, err := v1.NewHash(digest)
	if err != nil {
		return Bundle{}, fmt.Errorf("oci: bad digest %q: %w", digest, err)
	}
	var img v1.Image
	if p.LayoutDir != "" {
		img, err = p.imageFromLayout(want, digest)
	} else {
		img, err = p.imageFromRemote(ctx, imageRef, digest, want)
	}
	if err != nil {
		return Bundle{}, err
	}
	return extractBundle(img, entrypoint, stageDir)
}

// extractBundle streams the flattened rootfs and writes the bundle's flat file
// set to stageDir under the contract. It is its own pass (not reusing
// extractFile) because the contract requires inspecting EVERY entry under the
// bundle dir, not just the entrypoint.
func extractBundle(img v1.Image, entrypoint, stageDir string) (b Bundle, err error) {
	bundleDir := path.Dir(entrypoint)                  // e.g. "/app"
	prefix := strings.TrimPrefix(bundleDir, "/") + "/" // "app/" — match rootfs tar names
	entryBase := path.Base(entrypoint)                 // "server"

	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return Bundle{}, err
	}
	// Any failure must not leave a half-extracted (and thus mountable) dir.
	defer func() {
		if err != nil {
			os.RemoveAll(stageDir)
		}
	}()

	rc := mutate.Extract(img)
	defer rc.Close()
	tr := tar.NewReader(rc)

	var (
		total    int64
		count    int
		sawEntry bool
		written  = map[string]bool{}
		files    []string
	)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return Bundle{}, fmt.Errorf("oci: read rootfs: %w", err)
		}
		clean := filepath.Clean(hdr.Name)
		// Only entries under the bundle dir are in scope. Everything else in the
		// rootfs (the engine's base layers, /etc, ...) is ignored, exactly as the
		// single-file extractor ignores non-entrypoint files.
		if !strings.HasPrefix(clean+"/", prefix) || clean+"/" == prefix {
			continue
		}
		rel := strings.TrimPrefix(clean, prefix) // path relative to the bundle dir

		// Flat-only: reject any nested path (a file in a subdir, or a subdir
		// entry itself shows up with a trailing component).
		if strings.Contains(rel, "/") {
			return Bundle{}, fmt.Errorf("%w: %q is not directly under %s (subdirectories are not allowed)",
				ErrBundleContract, clean, bundleDir)
		}
		// Reject anything that is not a plain regular file: dirs, symlinks,
		// hardlinks, devices, fifos. A symlink could redirect a read outside the
		// bundle; a device/subdir breaks the flat-data contract.
		switch hdr.Typeflag {
		case tar.TypeReg:
			// ok
		case tar.TypeDir:
			return Bundle{}, fmt.Errorf("%w: subdirectory %q under %s", ErrBundleContract, clean, bundleDir)
		case tar.TypeSymlink, tar.TypeLink:
			return Bundle{}, fmt.Errorf("%w: link %q under %s (links are not allowed)", ErrBundleContract, clean, bundleDir)
		default:
			return Bundle{}, fmt.Errorf("%w: non-regular entry %q (type %d) under %s",
				ErrBundleContract, clean, hdr.Typeflag, bundleDir)
		}

		isEntry := rel == entryBase
		execBit := hdr.Mode&0o111 != 0
		if !isEntry && execBit {
			return Bundle{}, fmt.Errorf("%w: non-entrypoint file %q is executable (only the entrypoint may be executable)",
				ErrBundleContract, clean)
		}

		// Caps. Count/total are enforced as we go so a hostile image cannot make
		// us buffer or write unbounded data.
		count++
		if count > maxBundleFiles {
			return Bundle{}, fmt.Errorf("%w: more than %d files in %s", ErrBundleContract, maxBundleFiles, bundleDir)
		}
		if !isEntry && hdr.Size > maxSidecarBytes {
			return Bundle{}, fmt.Errorf("%w: file %q is %d bytes (non-entrypoint cap is %d)",
				ErrBundleContract, clean, hdr.Size, maxSidecarBytes)
		}

		mode := os.FileMode(0o644)
		if isEntry {
			mode = 0o755
			sawEntry = true
		}
		dest := filepath.Join(stageDir, rel)
		// LimitReader guards against a tar Size that lies (smaller than the real
		// stream) pushing us past the total cap. We cap each copy at the remaining
		// byte budget + 1 so an overrun is detected.
		remaining := maxBundleBytes - total
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
		if err != nil {
			return Bundle{}, err
		}
		n, copyErr := io.Copy(f, io.LimitReader(tr, remaining+1))
		closeErr := f.Close()
		if copyErr != nil {
			return Bundle{}, fmt.Errorf("oci: write %s: %w", dest, copyErr)
		}
		if closeErr != nil {
			return Bundle{}, closeErr
		}
		total += n
		if total > maxBundleBytes {
			return Bundle{}, fmt.Errorf("%w: bundle exceeds %d bytes total", ErrBundleContract, maxBundleBytes)
		}
		written[rel] = true
		files = append(files, rel)
	}

	if !sawEntry {
		return Bundle{}, fmt.Errorf("%w: entrypoint %s not found in bundle dir %s", ErrBundleContract, entrypoint, bundleDir)
	}
	// The contract requires EXACTLY the three named files. Reject a missing
	// sidecar (the engine ReadFile's hardcoded paths at startup) and reject any
	// surplus regular file (already capped by count, but be explicit about the
	// exact-set rule).
	for _, need := range []string{manifestSidecar, toolspecSidecar} {
		if !written[need] {
			return Bundle{}, fmt.Errorf("%w: required sidecar %s missing from bundle dir %s", ErrBundleContract, need, bundleDir)
		}
	}
	for _, got := range files {
		if got != entryBase && got != manifestSidecar && got != toolspecSidecar {
			return Bundle{}, fmt.Errorf("%w: unexpected file %q in %s (only %s, %s, %s allowed)",
				ErrBundleContract, got, bundleDir, entryBase, manifestSidecar, toolspecSidecar)
		}
	}

	sort.Strings(files)
	return Bundle{Dir: stageDir, Files: files}, nil
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
