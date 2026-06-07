package gateway_test

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

func newVaultStore(t *testing.T) (*vault.Vault, store.Store) {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return v, st
}

func putCred(t *testing.T, v *vault.Vault, st store.Store, server, tenant, secret string) {
	t.Helper()
	enc, err := v.Encrypt([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutCredential(context.Background(), store.Credential{
		Server: server, Tenant: tenant, EncryptedKey: enc,
		InjectHeader: "Authorization", InjectFormat: "Bearer {token}",
		Placeholder: "PLACEHOLDER", AllowedHosts: []string{"api.example.com"},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResolverJoinsProfileTenantToOwner(t *testing.T) {
	ctx := context.Background()
	v, st := newVaultStore(t)
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "alice", "a@x", "Alice", "user")
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, "main", "Main", u.ID, "hash")
	if err != nil {
		t.Fatal(err)
	}
	// Credential keyed by the OWNER's user id.
	putCred(t, v, st, "github", strconv.FormatInt(u.ID, 10), "OWNER_SECRET")

	r := &gateway.CredResolver{Store: st, Vault: v}
	cred, err := r.Resolve(proxy.Identity{Server: "github", Tenant: strconv.FormatInt(p.ID, 10)}, "api.example.com")
	if err != nil {
		t.Fatalf("resolve via profile tenant: %v", err)
	}
	if cred.RealSecret != "OWNER_SECRET" {
		t.Fatalf("wrong secret: %q", cred.RealSecret)
	}
}

func TestResolverLiteralTenantStillWorks(t *testing.T) {
	v, st := newVaultStore(t)
	putCred(t, v, st, "echo", "default", "LEGACY_SECRET")

	r := &gateway.CredResolver{Store: st, Vault: v}
	cred, err := r.Resolve(proxy.Identity{Server: "echo", Tenant: "default"}, "api.example.com")
	if err != nil || cred.RealSecret != "LEGACY_SECRET" {
		t.Fatalf("legacy tenant broken: %v %q", err, cred.RealSecret)
	}
	// A numeric tenant that is NOT a profile falls back to the literal key.
	putCred(t, v, st, "echo", "424242", "NUMERIC_LITERAL")
	cred, err = r.Resolve(proxy.Identity{Server: "echo", Tenant: "424242"}, "api.example.com")
	if err != nil || cred.RealSecret != "NUMERIC_LITERAL" {
		t.Fatalf("numeric literal fallback broken: %v %q", err, cred.RealSecret)
	}
}
