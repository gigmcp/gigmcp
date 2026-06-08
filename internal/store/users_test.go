package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

// openTestStore is shared by the new store test files.
func openTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestUpsertUserByOIDCCreatesAndUpdates(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	u1, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-1", "a@example.com", "Alice", "user")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if u1.ID == 0 || u1.Role != "user" || u1.Email != "a@example.com" || u1.CreatedAt.IsZero() {
		t.Fatalf("bad user: %+v", u1)
	}

	// Same (issuer, subject) → same row; email/name/role/last_login refreshed.
	u2, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-1", "new@example.com", "Alice A.", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if u2.ID != u1.ID {
		t.Fatalf("upsert created a new row: %d != %d", u2.ID, u1.ID)
	}
	if u2.Email != "new@example.com" || u2.DisplayName != "Alice A." || u2.Role != "admin" {
		t.Fatalf("fields not refreshed: %+v", u2)
	}

	// Different subject → new row.
	u3, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-2", "b@example.com", "Bob", "user")
	if err != nil {
		t.Fatal(err)
	}
	if u3.ID == u1.ID {
		t.Fatal("distinct subject must create a new user")
	}
}

func TestSameSubjectDifferentIssuerCreatesDistinctUser(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	u1, err := st.UpsertUserByOIDC(ctx, "https://idp-a", "sub-1", "a@example.com", "Alice", "user")
	if err != nil {
		t.Fatalf("upsert idp-a: %v", err)
	}
	// Same subject, different issuer → must create a new row.
	u2, err := st.UpsertUserByOIDC(ctx, "https://idp-b", "sub-1", "a@example.com", "Alice", "user")
	if err != nil {
		t.Fatalf("upsert idp-b: %v", err)
	}
	if u2.ID == u1.ID {
		t.Fatalf("same subject under different issuer must create a distinct user row (got same ID %d)", u1.ID)
	}
}

func TestGetUserAndListUsers(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	if _, err := st.GetUser(ctx, 999); !errors.Is(err, store.ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-1", "a@example.com", "Alice", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-2", "b@example.com", "Bob", "admin"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetUser(ctx, u.ID)
	if err != nil || got.Subject != "sub-1" {
		t.Fatalf("get: %v %+v", err, got)
	}
	all, err := st.ListUsers(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("list: %v %d", err, len(all))
	}
}
