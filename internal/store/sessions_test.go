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
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "s1", "a@x", "A", "user")
	if err != nil {
		t.Fatal(err)
	}

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

// TestExpiredImpersonationPassThrough verifies that GetSession returns the
// impersonation fields even when ImpersonationExpiresAt is in the past.
// Expiry enforcement is the responsibility of callers (auth middleware).
func TestExpiredImpersonationPassThrough(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	admin, _ := st.UpsertUserByOIDC(ctx, "https://idp", "adm2", "adm2@x", "Adm2", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "tgt2", "tgt2@x", "Tgt2", "user")

	if err := st.CreateSession(ctx, "h-imp-exp", admin.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Set impersonation with an expiry already in the past.
	pastExp := time.Now().Add(-time.Minute)
	if err := st.SetImpersonation(ctx, "h-imp-exp", target.ID, pastExp); err != nil {
		t.Fatalf("set impersonation: %v", err)
	}
	got, err := st.GetSession(ctx, "h-imp-exp")
	if err != nil {
		t.Fatalf("GetSession must succeed for a live session with expired impersonation: %v", err)
	}
	if got.ImpersonatingUserID == nil || *got.ImpersonatingUserID != target.ID {
		t.Fatalf("ImpersonatingUserID must be populated even when impersonation expired, got %+v", got)
	}
	if got.ImpersonationExpiresAt == nil || got.ImpersonationExpiresAt.Unix() != pastExp.Unix() {
		t.Fatalf("ImpersonationExpiresAt must be populated even when expired, got %+v", got)
	}
}

// TestSetImpersonationMissingSession verifies ErrSessionNotFound is returned
// when SetImpersonation is called for a token hash that doesn't exist.
func TestSetImpersonationMissingSession(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	err := st.SetImpersonation(ctx, "nonexistent-hash", 42, time.Now().Add(time.Hour))
	if !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

// TestDeleteSessionMissingRowNil verifies that deleting a non-existent session
// is not an error.
func TestDeleteSessionMissingRowNil(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	if err := st.DeleteSession(ctx, "does-not-exist"); err != nil {
		t.Fatalf("DeleteSession on missing row must return nil, got %v", err)
	}
}

// TestClearImpersonationWhenNotImpersonatingNil verifies that clearing
// impersonation on a session that is not impersonating anything is not an error.
func TestClearImpersonationWhenNotImpersonatingNil(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "ci-sub", "ci@x", "CI", "user")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, "ci-hash", u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearImpersonation(ctx, "ci-hash"); err != nil {
		t.Fatalf("ClearImpersonation when not impersonating must return nil, got %v", err)
	}
}
