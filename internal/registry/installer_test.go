package registry

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/registry/schema"
)

func newTestInstaller(t *testing.T, autoConsent bool) (*IndexInstaller, store.Store) {
	t.Helper()
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{
		"app/server": []byte("fake-echo-binary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	url, pub := writeSignedIndex(t,
		fixtureManifest("echo", "0.1.0", digest),
		fixtureManifest("echo", "0.2.0", digest),
	)
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
	}, st
}

func TestInstallRecordsServerAndManifest(t *testing.T) {
	inst, st := newTestInstaller(t, true)
	ctx := context.Background()
	srv, err := inst.Install(ctx, "echo@0.1.0")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if srv.Name != "echo" || !strings.Contains(srv.Binary, "echo@0.1.0") {
		t.Fatalf("bad server: %+v", srv)
	}
	if data, err := os.ReadFile(srv.Binary); err != nil || string(data) != "fake-echo-binary" {
		t.Fatalf("extracted binary: %q %v", data, err)
	}
	rec, err := st.GetManifest(ctx, "echo")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != "0.1.0" || rec.AllowedHosts[0] != "api.example.com" {
		t.Fatalf("bad record: %+v", rec)
	}
	if len(rec.Injections) != 1 || !strings.HasPrefix(rec.Injections[0].Placeholder, "gigph-") ||
		len(rec.Injections[0].Placeholder) < 20 {
		t.Fatalf("placeholder must be generated high-entropy: %+v", rec.Injections)
	}
	if rec.NeedsReconsent() {
		t.Fatal("AutoConsent install must be consented")
	}
	if len(rec.Tools) != 2 || !rec.Tools[0].Default || rec.Tools[1].Default {
		t.Fatalf("tools must round-trip: %+v", rec.Tools)
	}
}

func TestInstallIdempotentAndUpgradeFlipsConsent(t *testing.T) {
	inst, st := newTestInstaller(t, true)
	ctx := context.Background()
	if _, err := inst.Install(ctx, "echo@0.1.0"); err != nil {
		t.Fatal(err)
	}
	rec1, _ := st.GetManifest(ctx, "echo")
	if _, err := inst.Install(ctx, "echo@0.1.0"); err != nil { // re-install: no-op
		t.Fatal(err)
	}
	rec2, _ := st.GetManifest(ctx, "echo")
	if rec2.Injections[0].Placeholder != rec1.Injections[0].Placeholder {
		t.Fatal("idempotent re-install must not regenerate placeholders")
	}

	// Upgrade WITHOUT AutoConsent: consent goes stale.
	inst.AutoConsent = false
	if _, err := inst.Install(ctx, "echo"); err != nil { // latest = 0.2.0
		t.Fatal(err)
	}
	rec3, _ := st.GetManifest(ctx, "echo")
	if rec3.Version != "0.2.0" || !rec3.NeedsReconsent() {
		t.Fatalf("upgrade must record 0.2.0 and need re-consent: %+v", rec3)
	}
}

// TestReinstallRefreshesVendorWithoutChurn proves the idempotent re-install
// path picks up a backfilled `vendor` (a RuntimeHash-excluded grouping field)
// WITHOUT regenerating the placeholder or forcing re-consent.
func TestReinstallRefreshesVendorWithoutChurn(t *testing.T) {
	ctx := context.Background()

	// Shared OCI layout + store + DataDir; only the signed index URL changes
	// between the two installs (first without vendor, then with).
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{
		"app/server": []byte("fake-binary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	mkManifest := func(vendor string) *schema.Manifest {
		return &schema.Manifest{
			SchemaVersion: 1, Name: "gmail", Version: "1.0.0",
			Source: schema.Source{Repo: "github.com/gigmcp/gigmcp", Tag: "v1.0.0"},
			Image:  schema.Image{Ref: "ghcr.io/gigmcp/gmail", Digest: digest, Entrypoint: "/app/server"},
			Tier:   schema.TierSealed,
			Credentials: []schema.Credential{{
				ID: "oauth", Type: "oauth2", Provider: "gmail", Vendor: vendor,
				Scopes: []string{"send"},
				Inject: schema.Inject{Header: "Authorization", Format: "Bearer {token}"},
			}},
			Tools: []schema.Tool{{Name: "send", Default: true}},
		}
	}

	// AutoConsent=false so the second install must NOT re-consent on its own —
	// the only thing keeping NeedsReconsent false is that vendor is excluded from
	// RuntimeHash (so consented_hash stays valid).
	url1, pub1 := writeSignedIndex(t, mkManifest(""))
	inst := &IndexInstaller{
		Store:       st,
		Client:      &Client{IndexURL: url1, PublicKeyHex: pub1},
		Puller:      &oci.Puller{LayoutDir: layoutDir},
		DataDir:     t.TempDir(),
		AutoConsent: false,
	}

	if _, err := inst.Install(ctx, "gmail@1.0.0"); err != nil {
		t.Fatalf("first install: %v", err)
	}
	rec1, err := st.GetManifest(ctx, "gmail")
	if err != nil {
		t.Fatal(err)
	}
	if rec1.Injections[0].Vendor != "" {
		t.Fatalf("pre-backfill install must have empty vendor: %+v", rec1.Injections[0])
	}
	// First install is itself the consent (no prior) → not stale.
	if rec1.NeedsReconsent() {
		t.Fatal("first install must be consented")
	}
	ph1 := rec1.Injections[0].Placeholder
	hash1 := rec1.ManifestHash

	// Re-install the SAME version, now WITH vendor backfilled. Point the same
	// installer/store at the re-signed index.
	url2, pub2 := writeSignedIndex(t, mkManifest("google"))
	inst.Client = &Client{IndexURL: url2, PublicKeyHex: pub2}
	if _, err := inst.Install(ctx, "gmail@1.0.0"); err != nil {
		t.Fatalf("re-install with vendor: %v", err)
	}
	rec2, err := st.GetManifest(ctx, "gmail")
	if err != nil {
		t.Fatal(err)
	}
	if rec2.Injections[0].Vendor != "google" {
		t.Fatalf("re-install must backfill vendor: %+v", rec2.Injections[0])
	}
	if rec2.Injections[0].Placeholder != ph1 {
		t.Fatalf("placeholder must be unchanged: %q -> %q", ph1, rec2.Injections[0].Placeholder)
	}
	if rec2.ManifestHash != hash1 {
		t.Fatalf("RuntimeHash must be vendor-stable: %q -> %q", hash1, rec2.ManifestHash)
	}
	if rec2.NeedsReconsent() {
		t.Fatal("vendor-only refresh must NOT force re-consent")
	}
}

// TestInstallPersistsBranding proves the installer propagates the manifest's
// presentation fields (displayName/category/description) into the persisted
// ManifestRecord on a fresh install.
func TestInstallPersistsBranding(t *testing.T) {
	inst, st := newInstallerWithManifest(t, &schema.Manifest{
		SchemaVersion: 1, Name: "gmail", Version: "1.0.0",
		Source: schema.Source{Repo: "github.com/gigmcp/gigmcp", Tag: "v1.0.0"},
		Image: schema.Image{
			Ref:        "ghcr.io/gigmcp/gmail",
			Entrypoint: "/app/server",
		},
		Tier:        schema.TierSealed,
		DisplayName: "Gmail",
		Description: "Read and send mail.",
		Category:    "communication",
		Tools:       []schema.Tool{{Name: "send", Default: true}},
	})
	if _, err := inst.Install(context.Background(), "gmail"); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetManifest(context.Background(), "gmail")
	if err != nil {
		t.Fatal(err)
	}
	if rec.DisplayName != "Gmail" || rec.Description != "Read and send mail." ||
		rec.Category != "communication" {
		t.Fatalf("branding not propagated on fresh install: %+v", rec)
	}
}

// TestReinstallBackfillsBranding proves the idempotent re-install path (same
// version+RuntimeHash) picks up backfilled branding WITHOUT re-pull or
// re-consent — the mechanism that backfills already-installed servers on the
// next boot reconcile. Branding is excluded from RuntimeHash, so it never
// churns the hash or forces re-consent.
func TestReinstallBackfillsBranding(t *testing.T) {
	ctx := context.Background()

	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{
		"app/server": []byte("fake-binary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	mkManifest := func(display, desc, cat string) *schema.Manifest {
		return &schema.Manifest{
			SchemaVersion: 1, Name: "gmail", Version: "1.0.0",
			Source:      schema.Source{Repo: "github.com/gigmcp/gigmcp", Tag: "v1.0.0"},
			Image:       schema.Image{Ref: "ghcr.io/gigmcp/gmail", Digest: digest, Entrypoint: "/app/server"},
			Tier:        schema.TierSealed,
			DisplayName: display, Description: desc, Category: cat,
			Tools: []schema.Tool{{Name: "send", Default: true}},
		}
	}

	// First install WITHOUT branding. AutoConsent=false so the second install
	// must NOT re-consent on its own — branding being excluded from RuntimeHash
	// is the only thing keeping NeedsReconsent false.
	url1, pub1 := writeSignedIndex(t, mkManifest("", "", ""))
	inst := &IndexInstaller{
		Store:       st,
		Client:      &Client{IndexURL: url1, PublicKeyHex: pub1},
		Puller:      &oci.Puller{LayoutDir: layoutDir},
		DataDir:     t.TempDir(),
		AutoConsent: false,
	}
	if _, err := inst.Install(ctx, "gmail@1.0.0"); err != nil {
		t.Fatalf("first install: %v", err)
	}
	rec1, _ := st.GetManifest(ctx, "gmail")
	if rec1.DisplayName != "" || rec1.Category != "" || rec1.Description != "" {
		t.Fatalf("pre-backfill install must have empty branding: %+v", rec1)
	}
	hash1 := rec1.ManifestHash

	// Re-install the SAME version, now WITH branding backfilled.
	url2, pub2 := writeSignedIndex(t, mkManifest("Gmail", "Mail client.", "communication"))
	inst.Client = &Client{IndexURL: url2, PublicKeyHex: pub2}
	if _, err := inst.Install(ctx, "gmail@1.0.0"); err != nil {
		t.Fatalf("re-install with branding: %v", err)
	}
	rec2, _ := st.GetManifest(ctx, "gmail")
	if rec2.DisplayName != "Gmail" || rec2.Description != "Mail client." ||
		rec2.Category != "communication" {
		t.Fatalf("idempotent re-install must backfill branding: %+v", rec2)
	}
	if rec2.ManifestHash != hash1 {
		t.Fatalf("RuntimeHash must be branding-stable: %q -> %q", hash1, rec2.ManifestHash)
	}
	if rec2.NeedsReconsent() {
		t.Fatal("branding-only refresh must NOT force re-consent")
	}
}

func TestInstallByDigestRef(t *testing.T) {
	inst, _ := newTestInstaller(t, true)
	ix, err := inst.Client.FetchIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ix.Resolve("echo@0.1.0")
	if _, err := inst.Install(context.Background(), m.Image.Digest); err != nil {
		t.Fatalf("install by sha256 ref: %v", err)
	}
}

func TestUninstallRemovesEverything(t *testing.T) {
	inst, st := newTestInstaller(t, true)
	ctx := context.Background()
	srv, err := inst.Install(ctx, "echo@0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Uninstall(ctx, "echo"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetManifest(ctx, "echo"); err == nil {
		t.Fatal("manifest must be deleted")
	}
	if servers, _ := st.ListServers(ctx); len(servers) != 0 {
		t.Fatal("server row must be deleted")
	}
	if _, err := os.Stat(srv.Binary); !os.IsNotExist(err) {
		t.Fatal("extracted files must be removed")
	}
}

func TestInstallUnknownRefFails(t *testing.T) {
	inst, _ := newTestInstaller(t, true)
	if _, err := inst.Install(context.Background(), "nope@1.0.0"); err == nil {
		t.Fatal("unknown ref must fail")
	}
}

func TestUninstallRejectsInvalidName(t *testing.T) {
	inst, _ := newTestInstaller(t, true)
	for _, bad := range []string{"../evil", "evil/../../etc", "a/b", "..", "", "UPPER", "name_with_underscore"} {
		if err := inst.Uninstall(context.Background(), bad); err == nil {
			t.Errorf("Uninstall(%q) must be rejected", bad)
		}
	}
}

// newInstallerWithManifest builds an IndexInstaller whose signed index contains
// exactly the given manifest, and returns the installer and the backing store.
// The OCI layout is seeded with a fake binary so Install succeeds end-to-end.
func newInstallerWithManifest(t *testing.T, m *schema.Manifest) (*IndexInstaller, store.Store) {
	t.Helper()
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{
		"app/server": []byte("fake-binary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Patch the manifest's image digest to match the layout image we just wrote.
	m.Image.Digest = digest
	url, pub := writeSignedIndex(t, m)
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
		AutoConsent: true,
	}, st
}

func TestInstallPersistsCredentialMeta(t *testing.T) {
	// Build a manifest with one api_key credential and install it, then read
	// the manifest row back and assert the injection carries type/provider/scopes.
	inst, st := newInstallerWithManifest(t, &schema.Manifest{
		SchemaVersion: 1, Name: "gmail", Version: "1.0.0",
		Source: schema.Source{Repo: "github.com/gigmcp/gigmcp", Tag: "v1.0.0"},
		Image: schema.Image{
			Ref:        "ghcr.io/gigmcp/gmail",
			Entrypoint: "/app/server",
		},
		Tier: schema.TierSealed,
		Credentials: []schema.Credential{{
			ID: "api", Type: "api_key", Provider: "gmail", Scopes: []string{"send"},
			Inject: schema.Inject{Header: "Authorization", Format: "Bearer {token}"},
		}},
		Tools: []schema.Tool{{Name: "send", Default: true}},
	})
	if _, err := inst.Install(context.Background(), "gmail"); err != nil {
		t.Fatal(err)
	}
	rec, err := st.GetManifest(context.Background(), "gmail")
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Injections) != 1 {
		t.Fatalf("want 1 injection, got %d", len(rec.Injections))
	}
	if rec.Injections[0].Type != "api_key" || rec.Injections[0].Provider != "gmail" {
		t.Fatalf("type/provider not persisted: %+v", rec.Injections[0])
	}
	if len(rec.Injections[0].Scopes) != 1 || rec.Injections[0].Scopes[0] != "send" {
		t.Fatalf("scopes not persisted: %+v", rec.Injections[0].Scopes)
	}
}
