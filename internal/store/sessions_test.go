package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestSessionRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "s1", "a@x", "A", "user")
	if err != nil {
		t.Fatal(err)
	}

	exp := time.Now().Add(time.Hour)
	if err := st.CreateSession(ctx, "hash-1", u.ID, exp); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := st.GetSession(ctx, "hash-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UserID != u.ID || got.TokenHash != "hash-1" || got.ImpersonatingUserID != nil {
		t.Fatalf("session mismatch: %+v", got)
	}
	if got.ExpiresAt.Unix() != exp.Unix() {
		t.Fatalf("expiry mismatch: %v vs %v", got.ExpiresAt, exp)
	}

	if err := st.DeleteSession(ctx, "hash-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, "hash-1"); !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("want ErrSessionNotFound after delete, got %v", err)
	}
}

func TestExpiredSessionDeletedOnRead(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u, _ := st.UpsertUserByOIDC(ctx, "https://idp", "s1", "a@x", "A", "user")

	if err := st.CreateSession(ctx, "old", u.ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, "old"); !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("expired session must read as not-found, got %v", err)
	}
	// The expired row was deleted, so re-creating the same hash succeeds.
	if err := st.CreateSession(ctx, "old", u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("expired row not deleted on read: %v", err)
	}
}

func TestImpersonationSetAndClear(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	admin, _ := st.UpsertUserByOIDC(ctx, "https://idp", "adm", "adm@x", "Adm", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "tgt", "tgt@x", "Tgt", "user")

	if err := st.CreateSession(ctx, "h", admin.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	impExp := time.Now().Add(30 * time.Minute)
	if err := st.SetImpersonation(ctx, "h", target.ID, impExp); err != nil {
		t.Fatalf("set impersonation: %v", err)
	}
	got, err := st.GetSession(ctx, "h")
	if err != nil {
		t.Fatal(err)
	}
	if got.ImpersonatingUserID == nil || *got.ImpersonatingUserID != target.ID {
		t.Fatalf("impersonating_user_id: %+v", got)
	}
	if got.ImpersonationExpiresAt == nil || got.ImpersonationExpiresAt.Unix() != impExp.Unix() {
		t.Fatalf("impersonation_expires_at: %+v", got)
	}
	if err := st.ClearImpersonation(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetSession(ctx, "h")
	if got.ImpersonatingUserID != nil || got.ImpersonationExpiresAt != nil {
		t.Fatalf("impersonation not cleared: %+v", got)
	}
}
