package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func openStore(t *testing.T) Store {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestAuthConfigCRUD(t *testing.T) {
	st := openStore(t).(*sqliteStore)
	ctx := context.Background()

	ac := AuthConfig{
		Vendor: "google", AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL: "https://oauth2.googleapis.com/token", ClientID: "cid-123",
		EncryptedClientSecret: []byte("ciphertext-bytes"),
		DefaultScopes:         []string{"openid", "email"},
		PKCE:                  true, Mode: "byo",
	}
	if err := st.PutAuthConfig(ctx, ac); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetAuthConfig(ctx, "google")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "cid-123" || got.Mode != "byo" || !got.PKCE ||
		string(got.EncryptedClientSecret) != "ciphertext-bytes" ||
		len(got.DefaultScopes) != 2 || got.DefaultScopes[1] != "email" {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// Upsert replaces.
	ac.ClientID = "cid-456"
	if err := st.PutAuthConfig(ctx, ac); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetAuthConfig(ctx, "google")
	if got.ClientID != "cid-456" {
		t.Fatalf("upsert did not replace: %+v", got)
	}

	// List omits the secret (metadata-only, like ListCredentialsByTenant).
	list, err := st.ListAuthConfigs(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	if list[0].EncryptedClientSecret != nil {
		t.Fatal("ListAuthConfigs must not ship ciphertext")
	}

	// Delete (idempotent).
	if err := st.DeleteAuthConfig(ctx, "google"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetAuthConfig(ctx, "google"); !errors.Is(err, ErrAuthConfigNotFound) {
		t.Fatalf("want ErrAuthConfigNotFound, got %v", err)
	}
	if err := st.DeleteAuthConfig(ctx, "google"); err != nil {
		t.Fatalf("delete missing must be idempotent: %v", err)
	}
}
