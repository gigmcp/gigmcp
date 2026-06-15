package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// seedExposeUser creates a user and a profile owned by that user bundling the
// given servers, returning the resolved profile.
func seedExposeUser(t *testing.T, st store.Store, slug string, servers []string) store.Profile {
	t.Helper()
	ctx := context.Background()
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "owner-"+slug, slug+"@x", slug, "user")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := auth.NewProfileToken()
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, slug, slug, u.ID, auth.HashToken(tok))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileServers(ctx, p.ID, servers); err != nil {
		t.Fatal(err)
	}
	return p
}

// putToolsManifest installs a manifest for server with the named tools.
func putToolsManifest(t *testing.T, st store.Store, server string, tools ...string) {
	t.Helper()
	rec := store.ManifestRecord{Server: server, Version: "1", Digest: "d", Tier: "t", Entrypoint: "/bin/x"}
	for _, name := range tools {
		rec.Tools = append(rec.Tools, store.ToolEntry{Name: name, Default: true})
	}
	if err := st.PutManifest(context.Background(), rec); err != nil {
		t.Fatal(err)
	}
}

// TestExposeForIsPerUser verifies the manifest-driven expose map is keyed on
// the profile OWNER: each user's personal disabled-tool set applies to their
// own profile, and a server the owner has not installed is not exposed.
func TestExposeForIsPerUser(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "expose.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	if _, err := st.EnsureServer(ctx, "app", "/bin/app"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.EnsureServer(ctx, "other", "/bin/other"); err != nil {
		t.Fatal(err)
	}
	putToolsManifest(t, st, "app", "a", "b")
	putToolsManifest(t, st, "other", "c")

	// Both users have a profile bundling "app". Profile P1 also bundles "other"
	// which its owner has NOT installed.
	p1 := seedExposeUser(t, st, "u1", []string{"app", "other"})
	p2 := seedExposeUser(t, st, "u2", []string{"app"})

	// Both owners install "app".
	if err := st.InstallForUser(ctx, p1.UserID, "app"); err != nil {
		t.Fatal(err)
	}
	if err := st.InstallForUser(ctx, p2.UserID, "app"); err != nil {
		t.Fatal(err)
	}
	// User 1 disables tool "b" on app; user 2 does not.
	if err := st.SetUserToolEnabled(ctx, p1.UserID, "app", "b", false); err != nil {
		t.Fatal(err)
	}

	h := &ProfileHost{Store: st, Version: "test"}

	// User 1's profile: app exposes {a} (b disabled by owner), other skipped
	// (owner never installed it).
	exp1, skip1, err := h.exposeFor(ctx, p1, "app")
	if err != nil {
		t.Fatal(err)
	}
	if skip1 {
		t.Fatal("app must not be skipped for u1 (installed)")
	}
	if !exp1["a"] || exp1["b"] || len(exp1) != 1 {
		t.Fatalf("u1 app expose = %v, want {a}", exp1)
	}
	_, skipOther, err := h.exposeFor(ctx, p1, "other")
	if err != nil {
		t.Fatal(err)
	}
	if !skipOther {
		t.Fatal("other must be skipped for u1 (owner did not install it)")
	}

	// User 2's profile: app exposes {a,b} (no personal disables).
	exp2, skip2, err := h.exposeFor(ctx, p2, "app")
	if err != nil {
		t.Fatal(err)
	}
	if skip2 {
		t.Fatal("app must not be skipped for u2 (installed)")
	}
	if !exp2["a"] || !exp2["b"] || len(exp2) != 2 {
		t.Fatalf("u2 app expose = %v, want {a,b}", exp2)
	}
}

// TestExposeForLegacyNoManifest verifies a server with no manifest keeps its
// legacy behavior: nil expose map (all tools), as long as the owner installed
// it.
func TestExposeForLegacyNoManifest(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "expose-legacy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo"); err != nil {
		t.Fatal(err)
	}
	p := seedExposeUser(t, st, "leg", []string{"echo"})
	if err := st.InstallForUser(ctx, p.UserID, "echo"); err != nil {
		t.Fatal(err)
	}

	h := &ProfileHost{Store: st, Version: "test"}
	exp, skip, err := h.exposeFor(ctx, p, "echo")
	if err != nil {
		t.Fatal(err)
	}
	if skip {
		t.Fatal("echo must not be skipped (installed, no manifest)")
	}
	if exp != nil {
		t.Fatalf("legacy no-manifest expose = %v, want nil (all tools)", exp)
	}
}
