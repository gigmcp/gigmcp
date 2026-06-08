package oci

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
)

// goodBundle is the happy-path 3-file toolpack bundle: server (0755) plus two
// inert sidecars (0644), all directly under /app.
func goodBundle() []ocitest.File {
	return []ocitest.File{
		{Name: "app/server", Data: []byte("engine-binary"), Mode: 0o755},
		{Name: "app/manifest.yaml", Data: []byte("name: x\n"), Mode: 0o644},
		{Name: "app/toolspec.yaml", Data: []byte("tools: []\n"), Mode: 0o644},
	}
}

func extractBundleFromFiles(t *testing.T, files []ocitest.File) (Bundle, string, error) {
	t.Helper()
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutBundle(layoutDir, files)
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(t.TempDir(), "hackernews@0.1.0")
	p := &Puller{LayoutDir: layoutDir}
	b, err := p.ExtractBundle(context.Background(), "ghcr.io/ignored", digest, "/app/server", stage)
	return b, stage, err
}

func TestExtractBundleHappyPath(t *testing.T) {
	b, stage, err := extractBundleFromFiles(t, goodBundle())
	if err != nil {
		t.Fatalf("ExtractBundle: %v", err)
	}
	if b.Dir != stage {
		t.Fatalf("Bundle.Dir = %q, want %q", b.Dir, stage)
	}
	if strings.Join(b.Files, ",") != "manifest.yaml,server,toolspec.yaml" {
		t.Fatalf("Bundle.Files = %v", b.Files)
	}
	// All three files extracted with the contract perms.
	checkMode := func(name string, want os.FileMode) {
		info, err := os.Stat(filepath.Join(stage, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode = %v, want %v", name, info.Mode().Perm(), want)
		}
	}
	checkMode("server", 0o755)
	checkMode("manifest.yaml", 0o644)
	checkMode("toolspec.yaml", 0o644)
	if data, _ := os.ReadFile(filepath.Join(stage, "server")); string(data) != "engine-binary" {
		t.Fatalf("server contents wrong: %q", data)
	}
}

func TestExtractBundleRejectsExtraFile(t *testing.T) {
	files := append(goodBundle(), ocitest.File{Name: "app/extra.txt", Data: []byte("x"), Mode: 0o644})
	_, _, err := extractBundleFromFiles(t, files)
	if !errors.Is(err, ErrBundleContract) || !strings.Contains(err.Error(), "extra.txt") {
		t.Fatalf("want contract violation naming extra.txt, got %v", err)
	}
}

func TestExtractBundleRejectsSubdir(t *testing.T) {
	files := append(goodBundle(),
		ocitest.File{Name: "app/sub", Mode: 0o755, Typeflag: tar.TypeDir},
		ocitest.File{Name: "app/sub/nested", Data: []byte("x"), Mode: 0o644},
	)
	_, _, err := extractBundleFromFiles(t, files)
	if !errors.Is(err, ErrBundleContract) {
		t.Fatalf("want contract violation for subdir, got %v", err)
	}
}

func TestExtractBundleRejectsSymlink(t *testing.T) {
	files := append(goodBundle(),
		ocitest.File{Name: "app/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	)
	_, _, err := extractBundleFromFiles(t, files)
	if !errors.Is(err, ErrBundleContract) || !strings.Contains(err.Error(), "link") {
		t.Fatalf("want contract violation for symlink, got %v", err)
	}
}

func TestExtractBundleRejectsSecondExecutable(t *testing.T) {
	files := []ocitest.File{
		{Name: "app/server", Data: []byte("engine"), Mode: 0o755},
		{Name: "app/manifest.yaml", Data: []byte("name: x\n"), Mode: 0o755}, // exec bit on a sidecar
		{Name: "app/toolspec.yaml", Data: []byte("tools: []\n"), Mode: 0o644},
	}
	_, _, err := extractBundleFromFiles(t, files)
	if !errors.Is(err, ErrBundleContract) || !strings.Contains(err.Error(), "executable") {
		t.Fatalf("want contract violation for 2nd executable, got %v", err)
	}
}

func TestExtractBundleRejectsOversizeSidecar(t *testing.T) {
	big := make([]byte, maxSidecarBytes+1)
	files := []ocitest.File{
		{Name: "app/server", Data: []byte("engine"), Mode: 0o755},
		{Name: "app/manifest.yaml", Data: big, Mode: 0o644},
		{Name: "app/toolspec.yaml", Data: []byte("tools: []\n"), Mode: 0o644},
	}
	_, _, err := extractBundleFromFiles(t, files)
	if !errors.Is(err, ErrBundleContract) || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("want oversize contract violation, got %v", err)
	}
}

func TestExtractBundleRejectsMissingSidecar(t *testing.T) {
	files := []ocitest.File{
		{Name: "app/server", Data: []byte("engine"), Mode: 0o755},
		{Name: "app/manifest.yaml", Data: []byte("name: x\n"), Mode: 0o644},
		// toolspec.yaml omitted
	}
	_, _, err := extractBundleFromFiles(t, files)
	if !errors.Is(err, ErrBundleContract) || !strings.Contains(err.Error(), "toolspec.yaml") {
		t.Fatalf("want missing-sidecar contract violation, got %v", err)
	}
}

func TestExtractBundleRejectsMissingEntrypoint(t *testing.T) {
	files := []ocitest.File{
		{Name: "app/manifest.yaml", Data: []byte("name: x\n"), Mode: 0o644},
		{Name: "app/toolspec.yaml", Data: []byte("tools: []\n"), Mode: 0o644},
	}
	_, _, err := extractBundleFromFiles(t, files)
	if !errors.Is(err, ErrBundleContract) || !strings.Contains(err.Error(), "entrypoint") {
		t.Fatalf("want missing-entrypoint contract violation, got %v", err)
	}
}

// On any rejection the staging dir must be removed so no half-extracted (and
// thus mountable) directory survives.
func TestExtractBundleCleansStageOnReject(t *testing.T) {
	files := append(goodBundle(), ocitest.File{Name: "app/extra", Data: []byte("x"), Mode: 0o644})
	_, stage, err := extractBundleFromFiles(t, files)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if _, statErr := os.Stat(stage); !os.IsNotExist(statErr) {
		t.Fatalf("staging dir must be removed on reject, stat err = %v", statErr)
	}
}
