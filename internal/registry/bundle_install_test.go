package registry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/registry/schema"
)

func toolpackManifest(name, version, digest string) *schema.Manifest {
	m := fixtureManifest(name, version, digest)
	m.Image.Builder = "toolpack"
	// toolpack engine reads sidecars; the demo bundle carries no credentials.
	m.Credentials = nil
	return m
}

// newBundleInstaller wires an installer whose image is a faithful 3-file
// toolpack bundle and whose signed index pins it. Returns the installer, store
// and the index manifest.
func newBundleInstaller(t *testing.T, autoConsent bool) (*IndexInstaller, store.Store, *schema.Manifest) {
	t.Helper()
	layoutDir := t.TempDir()
	author := toolpackManifest("hackernews", "0.1.0", validDigest)
	digest := writeBundleLayout(t, layoutDir, manifestYAML(t, author))
	index := toolpackManifest("hackernews", "0.1.0", digest)
	url, pub := writeSignedIndex(t, index)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &IndexInstaller{
		Store:       st,
		Client:      &Client{IndexURL: url, PublicKeyHex: pub},
		Puller:      &oci.Puller{LayoutDir: layoutDir},
		DataDir:     t.TempDir(),
		AutoConsent: autoConsent,
	}, st, index
}

// builder=="toolpack" → bundle path: server row carries BundleDir and all three
// files are extracted flat into the staging dir.
func TestInstallToolpackBundle(t *testing.T) {
	inst, st, _ := newBundleInstaller(t, true)
	ctx := context.Background()
	srv, err := inst.Install(ctx, "hackernews@0.1.0")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if srv.BundleDir == "" {
		t.Fatal("bundle server must record BundleDir")
	}
	if srv.Binary != "/app/server" {
		t.Fatalf("entrypoint must be the in-image path, got %q", srv.Binary)
	}
	for _, f := range []string{"server", "manifest.yaml", "toolspec.yaml"} {
		if _, err := os.Stat(filepath.Join(srv.BundleDir, f)); err != nil {
			t.Fatalf("bundle file %s missing: %v", f, err)
		}
	}
	// Round-trips through ListServers (the spawn path reads it from here).
	servers, _ := st.ListServers(ctx)
	if len(servers) != 1 || servers[0].BundleDir != srv.BundleDir {
		t.Fatalf("ListServers bundle dir not persisted: %+v", servers)
	}
}

// builder omitted / "go-static" → single-file path: no BundleDir, binary is the
// host artifact at <stage>/server (existing behaviour, unchanged).
func TestInstallSingleFileBranch(t *testing.T) {
	for _, builder := range []string{"", "go-static"} {
		t.Run("builder="+builder, func(t *testing.T) {
			layoutDir := t.TempDir()
			digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{
				"app/server": []byte("static-binary"),
			})
			if err != nil {
				t.Fatal(err)
			}
			m := fixtureManifest("echo", "0.1.0", digest)
			m.Image.Builder = builder
			url, pub := writeSignedIndex(t, m)
			st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { st.Close() })
			inst := &IndexInstaller{
				Store:       st,
				Client:      &Client{IndexURL: url, PublicKeyHex: pub},
				Puller:      &oci.Puller{LayoutDir: layoutDir},
				DataDir:     t.TempDir(),
				AutoConsent: true,
			}
			srv, err := inst.Install(context.Background(), "echo@0.1.0")
			if err != nil {
				t.Fatalf("Install: %v", err)
			}
			if srv.BundleDir != "" {
				t.Fatalf("single-file server must NOT have BundleDir, got %q", srv.BundleDir)
			}
			if data, err := os.ReadFile(srv.Binary); err != nil || string(data) != "static-binary" {
				t.Fatalf("single-file binary: %q %v", data, err)
			}
		})
	}
}

// The bundled manifest.yaml must equal the index manifest (digest excluded). An
// image whose baked manifest declares an extra egress host is a tampered image:
// reject the install with the typed mismatch error.
func TestInstallToolpackManifestMismatchRejected(t *testing.T) {
	layoutDir := t.TempDir()
	// Bundled manifest declares an EXTRA egress host the signed index does not.
	tampered := toolpackManifest("hackernews", "0.1.0", validDigest)
	tampered.Entitlements.Egress = append(tampered.Entitlements.Egress, "evil.example.com")
	digest := writeBundleLayout(t, layoutDir, manifestYAML(t, tampered))

	index := toolpackManifest("hackernews", "0.1.0", digest) // clean index entry
	url, pub := writeSignedIndex(t, index)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	inst := &IndexInstaller{
		Store:       st,
		Client:      &Client{IndexURL: url, PublicKeyHex: pub},
		Puller:      &oci.Puller{LayoutDir: layoutDir},
		DataDir:     t.TempDir(),
		AutoConsent: true,
	}
	_, err = inst.Install(context.Background(), "hackernews@0.1.0")
	var mm *ManifestMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("want *ManifestMismatchError, got %v", err)
	}
	// A rejected install must leave nothing spawnable.
	if _, gerr := st.GetManifest(context.Background(), "hackernews"); gerr == nil {
		t.Fatal("rejected install must not record a manifest row")
	}
}

// A toolpack image that is not a valid 3-file bundle (here: an extra file)
// surfaces the oci bundle-contract violation through Install.
func TestInstallToolpackContractViolationSurfaced(t *testing.T) {
	layoutDir := t.TempDir()
	author := toolpackManifest("hackernews", "0.1.0", validDigest)
	digest, err := ocitest.WriteLayoutBundle(layoutDir, []ocitest.File{
		{Name: "app/server", Data: []byte("engine"), Mode: 0o755},
		{Name: "app/manifest.yaml", Data: manifestYAML(t, author), Mode: 0o644},
		{Name: "app/toolspec.yaml", Data: []byte("tools: []\n"), Mode: 0o644},
		{Name: "app/extra", Data: []byte("x"), Mode: 0o644},
	})
	if err != nil {
		t.Fatal(err)
	}
	index := toolpackManifest("hackernews", "0.1.0", digest)
	url, pub := writeSignedIndex(t, index)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	inst := &IndexInstaller{
		Store:       st,
		Client:      &Client{IndexURL: url, PublicKeyHex: pub},
		Puller:      &oci.Puller{LayoutDir: layoutDir},
		DataDir:     t.TempDir(),
		AutoConsent: true,
	}
	_, err = inst.Install(context.Background(), "hackernews@0.1.0")
	if !errors.Is(err, oci.ErrBundleContract) {
		t.Fatalf("want oci.ErrBundleContract surfaced through Install, got %v", err)
	}
}
