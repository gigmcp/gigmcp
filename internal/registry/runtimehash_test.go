package registry

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/registry/schema"
)

// TestCrossCheckPresentationOnlyDeltaPasses proves the cross-check keys off the
// runtime/security subset (RuntimeHash), not the full manifest hash: a baked
// manifest that differs from the index ONLY in presentation/grouping fields
// (vendor, displayName, ...) or in image.digest still RuntimeHash-matches, so
// the install is NOT rejected. This is the registry vendor/branding-backfill
// scenario — grouping-only re-sign with zero runtime delta.
func TestCrossCheckPresentationOnlyDeltaPasses(t *testing.T) {
	layoutDir := t.TempDir()

	// Baked manifest: faithful runtime contract, but carries NO presentation
	// fields and a placeholder digest (as a pre-backfill image would).
	baked := toolpackManifest("hackernews", "0.1.0", validDigest)
	digest := writeBundleLayout(t, layoutDir, manifestYAML(t, baked))

	// Index manifest: same runtime contract, real image digest, PLUS the five
	// presentation fields the registry backfilled and re-signed. RuntimeHash
	// excludes all of these, so the cross-check must pass.
	index := toolpackManifest("hackernews", "0.1.0", digest)
	index.DisplayName = "Hacker News"
	index.Description = "Read Hacker News stories and items"
	index.Category = "news"
	index.Icon = "icons/hackernews.svg"
	// toolpack demo carries no credentials; add one purely to exercise the
	// per-credential Vendor presentation field exclusion.
	index.Credentials = []schema.Credential{{
		ID: "token", Type: "api_key", Provider: "hn", Vendor: "ycombinator",
		Inject: schema.Inject{Header: "Authorization", Format: "Bearer {token}"},
	}}
	baked.Credentials = []schema.Credential{{
		ID: "token", Type: "api_key", Provider: "hn", // no Vendor on the baked image
		Inject: schema.Inject{Header: "Authorization", Format: "Bearer {token}"},
	}}
	// Re-bake so the image carries the credential-bearing (vendor-less) manifest.
	digest = writeBundleLayout(t, layoutDir, manifestYAML(t, baked))
	index.Image.Digest = digest

	b, err := (&oci.Puller{LayoutDir: layoutDir}).ExtractBundle(
		context.Background(), index.Image.Ref, index.Image.Digest, index.Image.Entrypoint, t.TempDir())
	if err != nil {
		t.Fatalf("ExtractBundle: %v", err)
	}
	if err := crossCheckBundledManifest(b.Dir, index); err != nil {
		t.Fatalf("presentation/digest-only delta must pass cross-check, got: %v", err)
	}
}

// TestCrossCheckRuntimeDeltaRejected proves the cross-check still catches a real
// runtime/security divergence: a baked manifest that declares an extra egress
// host fails RuntimeHash equality and is rejected with a *ManifestMismatchError.
func TestCrossCheckRuntimeDeltaRejected(t *testing.T) {
	layoutDir := t.TempDir()

	tampered := toolpackManifest("hackernews", "0.1.0", validDigest)
	tampered.Entitlements.Egress = append(tampered.Entitlements.Egress, "evil.example.com")
	digest := writeBundleLayout(t, layoutDir, manifestYAML(t, tampered))

	index := toolpackManifest("hackernews", "0.1.0", digest) // clean runtime contract
	index.DisplayName = "Hacker News"                        // presentation noise must not mask the runtime delta

	b, err := (&oci.Puller{LayoutDir: layoutDir}).ExtractBundle(
		context.Background(), index.Image.Ref, index.Image.Digest, index.Image.Entrypoint, t.TempDir())
	if err != nil {
		t.Fatalf("ExtractBundle: %v", err)
	}
	err = crossCheckBundledManifest(b.Dir, index)
	var mm *ManifestMismatchError
	if !errors.As(err, &mm) {
		t.Fatalf("runtime-field delta must yield *ManifestMismatchError, got: %v", err)
	}
}

// TestPresentationBackfillNoReconsent proves the install/consent hash basis is
// RuntimeHash: after a server is installed (and consented), an upgrade to a
// manifest that differs ONLY in presentation fields leaves ManifestHash
// unchanged, so NeedsReconsent stays false — the registry can backfill
// vendor/branding without forcing re-consent of 102 already-consented servers.
// The contrast case (a runtime-field change → NeedsReconsent true) is covered by
// TestDashboardInstallThenSpawnGate.
func TestPresentationBackfillNoReconsent(t *testing.T) {
	ctx := context.Background()
	layoutDir := t.TempDir()

	author := hackernewsManifest(validDigest)
	digest := writeBundleLayout(t, layoutDir, manifestYAML(t, author))
	m := hackernewsManifest(digest)
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
		AutoConsent: false, // production API-install path
	}

	// First install = consent. Server must be spawnable.
	if _, err := inst.Install(ctx, "hackernews"); err != nil {
		t.Fatalf("Install: %v", err)
	}
	rec, err := st.GetManifest(ctx, "hackernews")
	if err != nil {
		t.Fatal(err)
	}
	if rec.NeedsReconsent() {
		t.Fatal("freshly installed manifest must not need re-consent")
	}
	hashBefore := rec.ManifestHash

	// Registry backfills presentation/grouping fields and re-signs the index for
	// the SAME version. The image is re-baked carrying the same runtime contract
	// (faithful bundle); the index entry now also carries vendor/branding. With
	// RuntimeHash as the basis this is a no-op upgrade: hash unchanged, no
	// re-consent. AutoConsent=false ensures any spurious hash change WOULD surface
	// as NeedsReconsent (fail closed), so a passing test proves the no-op.
	author2 := hackernewsManifest(validDigest)
	digest2 := writeBundleLayout(t, layoutDir, manifestYAML(t, author2))
	m2 := hackernewsManifest(digest2)
	m2.DisplayName = "Hacker News"
	m2.Description = "Read Hacker News stories and items"
	m2.Category = "news"
	m2.Icon = "icons/hackernews.svg"
	url2, pub2 := writeSignedIndex(t, m2)
	inst.Client = &Client{IndexURL: url2, PublicKeyHex: pub2}

	if _, err := inst.Install(ctx, "hackernews"); err != nil {
		t.Fatalf("presentation-backfill re-install: %v", err)
	}
	rec, err = st.GetManifest(ctx, "hackernews")
	if err != nil {
		t.Fatal(err)
	}
	if rec.ManifestHash != hashBefore {
		t.Fatalf("presentation-only backfill changed ManifestHash: before=%q after=%q", hashBefore, rec.ManifestHash)
	}
	if rec.NeedsReconsent() {
		t.Fatalf("presentation-only backfill triggered spurious re-consent\n  manifest_hash  = %q\n  consented_hash = %q",
			rec.ManifestHash, rec.ConsentedHash)
	}
}
