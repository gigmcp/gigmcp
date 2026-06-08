package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConnectedAccountLifecycle(t *testing.T) {
	st := openStore(t).(*sqliteStore)
	ctx := context.Background()
	exp := time.Now().Add(time.Hour).Truncate(time.Second).UTC()

	ca := ConnectedAccount{
		UserID: 7, Vendor: "google",
		EncryptedRefreshToken: []byte("rt-cipher"),
		EncryptedAccessToken:  []byte("at-cipher"),
		ExpiresAt:             exp,
		GrantedScopes:         []string{"email", "profile"},
	}
	if err := st.PutConnectedAccount(ctx, ca); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetConnectedAccount(ctx, 7, "google")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.EncryptedRefreshToken) != "rt-cipher" ||
		string(got.EncryptedAccessToken) != "at-cipher" ||
		!got.ExpiresAt.Equal(exp) || len(got.GrantedScopes) != 2 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}

	// One row per (user, vendor): re-put with new scopes replaces.
	ca.GrantedScopes = []string{"email", "profile", "drive"}
	if err := st.PutConnectedAccount(ctx, ca); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetConnectedAccount(ctx, 7, "google")
	if len(got.GrantedScopes) != 3 {
		t.Fatalf("upsert did not widen scopes: %+v", got)
	}

	// UpdateConnectedAccountTokens rotates only the access token + expiry.
	newExp := exp.Add(time.Hour)
	if err := st.UpdateConnectedAccountTokens(ctx, 7, "google", []byte("at2-cipher"), newExp); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetConnectedAccount(ctx, 7, "google")
	if string(got.EncryptedAccessToken) != "at2-cipher" || !got.ExpiresAt.Equal(newExp) ||
		string(got.EncryptedRefreshToken) != "rt-cipher" {
		t.Fatalf("token update wrong: %+v", got)
	}

	// List by user is metadata-only (no ciphertext).
	list, err := st.ListConnectedAccountsByUser(ctx, 7)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	if list[0].EncryptedRefreshToken != nil || list[0].EncryptedAccessToken != nil {
		t.Fatal("ListConnectedAccountsByUser must not ship ciphertext")
	}
	if list[0].Vendor != "google" || len(list[0].GrantedScopes) != 3 {
		t.Fatalf("list metadata wrong: %+v", list[0])
	}

	// Delete (idempotent) + not-found sentinel.
	if err := st.DeleteConnectedAccount(ctx, 7, "google"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetConnectedAccount(ctx, 7, "google"); !errors.Is(err, ErrConnectedAccountNotFound) {
		t.Fatalf("want ErrConnectedAccountNotFound, got %v", err)
	}
	if err := st.DeleteConnectedAccount(ctx, 7, "google"); err != nil {
		t.Fatalf("delete missing must be idempotent: %v", err)
	}
}
