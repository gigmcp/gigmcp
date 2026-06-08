package oci

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
)

// TestExtractMultiArchIndexResolvesHost proves a multi-arch index pin resolves
// to the host-platform child image and extracts that child's binary. This is
// the live "hackernews" bug: the pin is the manifest-list digest, and each
// child sub-manifest has a DIFFERENT digest — the puller must verify against the
// index digest and then select the host arch, NOT compare a child to the pin.
func TestExtractMultiArchIndexResolvesHost(t *testing.T) {
	other := "amd64"
	if runtime.GOARCH == "amd64" {
		other = "arm64"
	}
	layoutDir := t.TempDir()
	indexDigest, err := ocitest.WriteLayoutIndex(layoutDir, []ocitest.ArchFiles{
		{OS: "linux", Arch: runtime.GOARCH, Files: map[string][]byte{
			"app/server": []byte("host-arch-binary"),
		}},
		{OS: "linux", Arch: other, Files: map[string][]byte{
			"app/server": []byte("foreign-arch-binary"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(t.TempDir(), "server")
	p := &Puller{LayoutDir: layoutDir}
	// Pin is the INDEX digest; the host child manifest has a different digest.
	if err := p.Extract(context.Background(), "ghcr.io/ignored/by-layout", indexDigest, "/app/server", dest); err != nil {
		t.Fatalf("Extract from multi-arch index: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "host-arch-binary" {
		t.Fatalf("dest contents: %q, %v — want host-arch child selected", got, err)
	}
}

// TestExtractMultiArchIndexNoHostEntry verifies a clear error when the index
// has no child for the host platform (a genuinely foreign-only multi-arch
// image), rather than an opaque digest mismatch or panic.
func TestExtractMultiArchIndexNoHostEntry(t *testing.T) {
	other := "amd64"
	if runtime.GOARCH == "amd64" {
		other = "arm64"
	}
	layoutDir := t.TempDir()
	indexDigest, err := ocitest.WriteLayoutIndex(layoutDir, []ocitest.ArchFiles{
		{OS: "linux", Arch: other, Files: map[string][]byte{
			"app/server": []byte("foreign-arch-binary"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p := &Puller{LayoutDir: layoutDir}
	err = p.Extract(context.Background(), "ref", indexDigest, "/app/server", filepath.Join(t.TempDir(), "out"))
	if err == nil || !strings.Contains(err.Error(), "no linux/"+runtime.GOARCH+" entry") {
		t.Fatalf("want no-host-entry error, got %v", err)
	}
}

func TestExtractFromLayout(t *testing.T) {
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{
		"app/server": []byte("fake-static-binary"),
		"etc/noise":  []byte("ignore me"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "servers", "echo@0.1.0", "server")
	p := &Puller{LayoutDir: layoutDir}
	if err := p.Extract(context.Background(), "ghcr.io/ignored/by-layout", digest, "/app/server", dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "fake-static-binary" {
		t.Fatalf("dest contents: %q, %v", got, err)
	}
	info, _ := os.Stat(dest)
	if info.Mode().Perm() != 0o555 {
		t.Fatalf("dest mode = %v, want 0555", info.Mode().Perm())
	}
}

func TestExtractRejectsWrongDigest(t *testing.T) {
	layoutDir := t.TempDir()
	if _, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{"app/server": []byte("x")}); err != nil {
		t.Fatal(err)
	}
	wrong := "sha256:" + strings.Repeat("0", 64)
	p := &Puller{LayoutDir: layoutDir}
	err := p.Extract(context.Background(), "ref", wrong, "/app/server", filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Fatal("wrong digest must fail (content-addressed lookup)")
	}
}

func TestExtractRejectsMissingEntrypoint(t *testing.T) {
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{"app/server": []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	p := &Puller{LayoutDir: layoutDir}
	err = p.Extract(context.Background(), "ref", digest, "/does/not/exist", filepath.Join(t.TempDir(), "out"))
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want entrypoint-not-found error, got %v", err)
	}
}
