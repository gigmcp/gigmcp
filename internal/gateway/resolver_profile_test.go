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

// TestResolverJoinsProfileTenantToOwner verifies that when a numeric tenant
// string names an existing profile, the resolver looks up credentials under
// the profile OWNER's user id — not the literal profile-id string.
//
// De-vacuated by seeding TWO users so that user1.ID == profile.ID == 1 but
// user2.ID == profile.UserID == 2. A DECOY credential is stored under tenant
// "1" (the profile-ID string), and the real OWNER_SECRET under
// store.UserTenant(user2.ID) == "2". Resolving via tenant "1" must return
// OWNER_SECRET. If the join block is deleted the test fails because
// GetCredential("github","1") returns the DECOY.
func TestResolverJoinsProfileTenantToOwner(t *testing.T) {
	ctx := context.Background()
	v, st := newVaultStore(t)

	// user1 is seeded only to consume ID=1 so that the next user gets ID=2.
	_, err := st.UpsertUserByOIDC(ctx, "https://idp", "alice-sub", "a@x", "Alice", "user")
	if err != nil {
		t.Fatal(err)
	}
	user2, err := st.UpsertUserByOIDC(ctx, "https://idp", "bob-sub", "b@x", "Bob", "user")
	if err != nil {
		t.Fatal(err)
	}
	// Profile is owned by user2 (ID=2). SQLite auto-increment gives it ID=1,
	// so profile.ID == 1 == user1.ID, but profile.UserID == 2 == user2.ID.
	p, err := st.CreateProfile(ctx, "main", "Main", user2.ID, "hash")
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: the join is only interesting when the profile-ID string differs
	// from the owner-user-tenant string.
	if strconv.FormatInt(p.ID, 10) == store.UserTenant(user2.ID) {
		t.Skip("profile.ID == user2.ID in this DB; decoy separation impossible")
	}

	// DECOY stored under the literal profile-ID string (what a join-less
	// resolver would find).
	putCred(t, v, st, "github", strconv.FormatInt(p.ID, 10), "DECOY")
	// Real credential stored under the OWNER's user tenant (what the join
	// must resolve to).
	putCred(t, v, st, "github", store.UserTenant(user2.ID), "OWNER_SECRET")

	r := &gateway.CredResolver{Store: st, Vault: v}
	cred, err := r.Resolve(proxy.Identity{Server: "github", Tenant: strconv.FormatInt(p.ID, 10)}, "api.example.com")
	if err != nil {
		t.Fatalf("resolve via profile tenant: %v", err)
	}
	if cred.RealSecret == "DECOY" {
		t.Fatal("resolver returned DECOY: join block is missing or broken")
	}
	if cred.RealSecret != "OWNER_SECRET" {
		t.Fatalf("wrong secret: got %q, want OWNER_SECRET", cred.RealSecret)
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
