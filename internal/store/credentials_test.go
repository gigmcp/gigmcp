package store_test

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestPutGetCredential(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cred := store.Credential{
		Server:       "github",
		Tenant:       "alice",
		EncryptedKey: []byte{0x01, 0x02, 0x03},
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
		Placeholder:  "PLACEHOLDER_GITHUB",
		AllowedHosts: []string{"api.github.com"},
	}
	if err := st.PutCredential(ctx, cred); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.GetCredential(ctx, "github", "alice")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Server != "github" || got.Tenant != "alice" ||
		got.InjectHeader != "Authorization" || got.InjectFormat != "Bearer {token}" ||
		got.Placeholder != "PLACEHOLDER_GITHUB" {
		t.Fatalf("scalar mismatch: %+v", got)
	}
	if !reflect.DeepEqual(got.EncryptedKey, cred.EncryptedKey) {
		t.Fatalf("key bytes mismatch: %v", got.EncryptedKey)
	}
	if !reflect.DeepEqual(got.AllowedHosts, []string{"api.github.com"}) {
		t.Fatalf("allowlist mismatch: %v", got.AllowedHosts)
	}
}

func TestPutCredentialUpsert(t *testing.T) {
	ctx := context.Background()
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	defer st.Close()
	base := store.Credential{Server: "s", Tenant: "t", EncryptedKey: []byte{1},
		InjectHeader: "Authorization", InjectFormat: "Bearer {token}", Placeholder: "P", AllowedHosts: []string{"a.com"}}
	if err := st.PutCredential(ctx, base); err != nil {
		t.Fatal(err)
	}
	base.EncryptedKey = []byte{2, 2}
	base.AllowedHosts = []string{"b.com", "c.com"}
	if err := st.PutCredential(ctx, base); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetCredential(ctx, "s", "t")
	if !reflect.DeepEqual(got.EncryptedKey, []byte{2, 2}) || len(got.AllowedHosts) != 2 {
		t.Fatalf("upsert did not replace: %+v", got)
	}
}

func TestGetCredentialMissing(t *testing.T) {
	ctx := context.Background()
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	defer st.Close()
	if _, err := st.GetCredential(ctx, "nope", "nobody"); err == nil {
		t.Fatal("expected error for missing credential")
	}
}

func TestListCredentialsByTenantAndDelete(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	put := func(server, tenant string) {
		t.Helper()
		if err := st.PutCredential(ctx, store.Credential{
			Server: server, Tenant: tenant, EncryptedKey: []byte{9, 9},
			InjectHeader: "Authorization", InjectFormat: "Bearer {token}",
			Placeholder: "P", AllowedHosts: []string{"api.example.com"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("github", "7")
	put("slack", "7")
	put("github", "8")

	got, err := st.ListCredentialsByTenant(ctx, "7")
	if err != nil || len(got) != 2 {
		t.Fatalf("list: %v %d", err, len(got))
	}
	for _, c := range got {
		if c.Tenant != "7" {
			t.Fatalf("foreign tenant leaked: %+v", c)
		}
		if c.EncryptedKey != nil {
			t.Fatalf("metadata listing must NOT carry ciphertext: %+v", c)
		}
		if c.InjectHeader != "Authorization" || len(c.AllowedHosts) != 1 {
			t.Fatalf("metadata missing: %+v", c)
		}
	}

	deleted, err := st.DeleteCredential(ctx, "github", "7")
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Fatal("expected deleted=true for first delete")
	}
	if _, err := st.GetCredential(ctx, "github", "7"); err == nil {
		t.Fatal("deleted credential still readable")
	}
	if _, err := st.GetCredential(ctx, "github", "8"); err != nil {
		t.Fatalf("other tenant's credential must survive: %v", err)
	}
	// Deleting a missing row is not an error; returns false (noop).
	noop, err := st.DeleteCredential(ctx, "github", "7")
	if err != nil {
		t.Fatalf("double delete: %v", err)
	}
	if noop {
		t.Fatal("expected deleted=false for noop delete")
	}
}
