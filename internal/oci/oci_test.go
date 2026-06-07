package oci

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
)

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
