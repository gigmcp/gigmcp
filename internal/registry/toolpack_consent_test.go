package registry

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/registry/schema"
)

// hackernewsManifest mirrors the first builder:"toolpack" manifest consumed
// from the published registry index (manifests/hackernews/0.1.0): sealed tier,
// no credentials, 9 tools, two egress hosts.
func hackernewsManifest(digest string) *schema.Manifest {
	tools := []schema.Tool{
		{Name: "get_top_stories", Default: true},
		{Name: "get_new_stories", Default: true},
		{Name: "get_best_stories", Default: true},
		{Name: "get_show_stories", Default: true},
		{Name: "get_ask_stories", Default: true},
		{Name: "get_item", Default: true},
		{Name: "get_user", Default: true},
		{Name: "search_posts", Default: true},
		{Name: "get_updates", Default: true},
	}
	return &schema.Manifest{
		SchemaVersion: 1,
		Name:          "hackernews",
		Version:       "0.1.0",
		Source:        schema.Source{Repo: "github.com/gigmcp/toolpack", Tag: "v0.1.0"},
		Image: schema.Image{
			Ref:        "ghcr.io/gigmcp/hackernews-mcp",
			Digest:     digest,
			Entrypoint: "/app/server",
			Builder:    "toolpack",
		},
		Tier: schema.TierSealed,
		Entitlements: schema.Entitlements{
			Egress: []string{"hacker-news.firebaseio.com", "hn.algolia.com"},
		},
		Tools: tools,
	}
}

// TestDashboardInstallThenSpawnGate reproduces the production sequence
// exactly as the gateway wires it (cmd/gateway newInstaller for the REST API
// install path): POST /api/servers/install → IndexInstaller.Install → attach
// to a profile → first MCP request hits the spawn-side re-consent gate
// (cmd/gateway/main.go Spawn closure: ManifestRecord.NeedsReconsent).
//
// An admin dashboard install is an operator-initiated acceptance of exactly
// this manifest (same trust model as GIG_INSTALL boot installs), so the
// freshly installed, unchanged manifest must be spawnable.
func TestDashboardInstallThenSpawnGate(t *testing.T) {
	ctx := context.Background()
	layoutDir := t.TempDir()
	// Faithful toolpack image: manifest.yaml inside the image is the author
	// manifest. Image.Digest is the image's own content-address, which is
	// self-referential and therefore EXCLUDED from the cross-check; the bundled
	// file carries a placeholder valid digest (Validate requires a well-formed
	// one), and the index entry carries the real one.
	author := hackernewsManifest(validDigest)
	digest := writeBundleLayout(t, layoutDir, manifestYAML(t, author))
	m := hackernewsManifest(digest)
	url, pub := writeSignedIndex(t, m)

	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	// Mirror cmd/gateway newInstaller(cfg, st, false) — the installer handed to
	// the REST API (POST /api/servers/install). This is the EXACT production
	// dashboard-install wiring. LayoutDir is test-only (no network); every
	// other field matches.
	inst := &IndexInstaller{
		Store:       st,
		Client:      &Client{IndexURL: url, PublicKeyHex: pub},
		Puller:      &oci.Puller{LayoutDir: layoutDir},
		DataDir:     t.TempDir(),
		AutoConsent: false, // production API-install path
	}

	// Dashboard install. Nothing else in the system records consent (there is
	// no /api consent endpoint), so Install itself must leave the server
	// spawnable.
	if _, err := inst.Install(ctx, "hackernews"); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// Spawn-side gate (cmd/gateway/main.go Spawn closure).
	rec, err := st.GetManifest(ctx, "hackernews")
	if err != nil {
		t.Fatal(err)
	}
	if rec.NeedsReconsent() {
		t.Fatalf("spawn refused: NeedsReconsent=true for freshly installed manifest\n  manifest_hash  = %q\n  consented_hash = %q",
			rec.ManifestHash, rec.ConsentedHash)
	}

	// A second, idempotent Install (e.g. gateway restart with GIG_INSTALL, or
	// the admin clicking install again) must not flip consent stale either.
	if _, err := inst.Install(ctx, "hackernews"); err != nil {
		t.Fatalf("re-Install: %v", err)
	}
	rec, err = st.GetManifest(ctx, "hackernews")
	if err != nil {
		t.Fatal(err)
	}
	if rec.NeedsReconsent() {
		t.Fatalf("idempotent re-install flipped consent stale\n  manifest_hash  = %q\n  consented_hash = %q",
			rec.ManifestHash, rec.ConsentedHash)
	}

	// SECURITY PROPERTY (DESIGN #7) must hold: a genuinely changed manifest
	// that lands WITHOUT an operator-initiated consent (AutoConsent=false
	// install, i.e. no operator acceptance of the new hash) stays refused.
	author2 := hackernewsManifest(validDigest)
	author2.Version = "0.2.0"
	author2.Source.Tag = "v0.2.0"
	author2.Entitlements.Egress = append(author2.Entitlements.Egress, "evil.example.com")
	// 0.2.0 ships its own faithful bundle image (manifest.yaml matches author2),
	// so the cross-check passes and the install proceeds — the re-consent gate,
	// not the cross-check, is what must keep it from spawning.
	digest2 := writeBundleLayout(t, layoutDir, manifestYAML(t, author2))
	m2 := hackernewsManifest(digest2)
	m2.Version = "0.2.0"
	m2.Source.Tag = "v0.2.0"
	m2.Entitlements.Egress = append(m2.Entitlements.Egress, "evil.example.com")
	url2, pub2 := writeSignedIndex(t, m, m2)
	inst.Client = &Client{IndexURL: url2, PublicKeyHex: pub2}
	inst.AutoConsent = false
	if _, err := inst.Install(ctx, "hackernews@0.2.0"); err != nil {
		t.Fatalf("upgrade install: %v", err)
	}
	rec, err = st.GetManifest(ctx, "hackernews")
	if err != nil {
		t.Fatal(err)
	}
	if !rec.NeedsReconsent() {
		t.Fatal("changed manifest without recorded consent MUST need re-consent (fail closed)")
	}
}
