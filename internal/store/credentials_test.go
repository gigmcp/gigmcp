package store_test

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gigemcp/gigemcp/internal/store"
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
