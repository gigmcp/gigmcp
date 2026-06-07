package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	kek := make([]byte, 32)
	v, err := vault.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestResolveManifestBacked(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	v := testVault(t)
	ctx := context.Background()

	enc, err := v.Encrypt([]byte("real-secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Credential row carries ONLY the secret (manifest-backed server) —
	// its legacy injection/allowlist columns are deliberately junk to prove
	// they are ignored.
	if err := st.PutCredential(ctx, store.Credential{
		Server: "slack-mcp", Tenant: "default", EncryptedKey: enc,
		InjectHeader: "X-IGNORED", InjectFormat: "ignored", Placeholder: "ignored",
		AllowedHosts: []string{"ignored.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "slack-mcp", Version: "1.0.0", Digest: "sha256:x", Tier: "sealed",
		Entrypoint: "/server", AllowedHosts: []string{"slack.com", "*.slack.com"},
		Injections: []store.Injection{{
			ID: "tok", Header: "Authorization", Format: "Bearer {token}", Placeholder: "gigph-deadbeef",
		}},
		ManifestHash: "h1",
	}); err != nil {
		t.Fatal(err)
	}

	r := &CredResolver{Store: st, Vault: v}
	cred, err := r.Resolve(proxy.Identity{Server: "slack-mcp", Tenant: "default"}, "slack.com")
	if err != nil {
		t.Fatal(err)
	}
	if cred.RealSecret != "real-secret" {
		t.Fatalf("secret = %q", cred.RealSecret)
	}
	// Manifest is the hard cap: injection + allowlist MUST come from it.
	if cred.InjectHeader != "Authorization" || cred.Placeholder != "gigph-deadbeef" {
		t.Fatalf("injection must come from manifest: %+v", cred)
	}
	if len(cred.AllowedHosts) != 2 || cred.AllowedHosts[0] != "slack.com" {
		t.Fatalf("allowlist must come from manifest: %v", cred.AllowedHosts)
	}
}

func TestResolveLegacyFallback(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	v := testVault(t)
	ctx := context.Background()

	enc, _ := v.Encrypt([]byte("legacy-secret"))
	// No manifest row: legacy GIG_ECHO_BIN-style server — credential row
	// still carries injection + allowlist (unchanged demo flow).
	if err := st.PutCredential(ctx, store.Credential{
		Server: "echo", Tenant: "default", EncryptedKey: enc,
		InjectHeader: "Authorization", InjectFormat: "Bearer {token}",
		Placeholder: "PLACEHOLDER", AllowedHosts: []string{"api.example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	r := &CredResolver{Store: st, Vault: v}
	cred, err := r.Resolve(proxy.Identity{Server: "echo", Tenant: "default"}, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cred.RealSecret != "legacy-secret" || cred.InjectHeader != "Authorization" ||
		cred.Placeholder != "PLACEHOLDER" || cred.AllowedHosts[0] != "api.example.com" {
		t.Fatalf("legacy fallback broken: %+v", cred)
	}
}
