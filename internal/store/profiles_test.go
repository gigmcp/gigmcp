package store_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func seedUser(t *testing.T, st store.Store, sub string) store.User {
	t.Helper()
	u, err := st.UpsertUserByOIDC(context.Background(), "https://idp", sub, sub+"@x", sub, "user")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestProfileCRUD(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u := seedUser(t, st, "alice")

	p, err := st.CreateProfile(ctx, "main", "Main profile", u.ID, "tokhash-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == 0 || p.Slug != "main" || p.UserID != u.ID || p.TokenHash != "tokhash-1" || p.MetaTools {
		t.Fatalf("bad profile: %+v", p)
	}

	// Duplicate slug must return ErrSlugTaken.
	_, err = st.CreateProfile(ctx, "main", "Dup", u.ID, "tokhash-2")
	if !errors.Is(err, store.ErrSlugTaken) {
		t.Fatalf("duplicate slug: want ErrSlugTaken, got %v", err)
	}

	got, err := st.GetProfileByID(ctx, p.ID)
	if err != nil || got.Slug != "main" {
		t.Fatalf("get by id: %v %+v", err, got)
	}
	if _, err := st.GetProfileByID(ctx, 999); !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("want ErrProfileNotFound, got %v", err)
	}

	if err := st.UpdateProfileName(ctx, p.ID, "Renamed"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetProfileByID(ctx, p.ID)
	if got.Name != "Renamed" {
		t.Fatalf("rename failed: %+v", got)
	}

	if err := st.SetProfileToken(ctx, p.ID, "tokhash-rotated"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetProfileByID(ctx, p.ID)
	if got.TokenHash != "tokhash-rotated" {
		t.Fatalf("rotate failed: %+v", got)
	}
}

func TestGetProfileBySlugAndTokenHash(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u := seedUser(t, st, "alice")
	p, _ := st.CreateProfile(ctx, "main", "Main", u.ID, "good-hash")

	got, err := st.GetProfileBySlugAndTokenHash(ctx, "main", "good-hash")
	if err != nil || got.ID != p.ID {
		t.Fatalf("auth lookup: %v %+v", err, got)
	}
	if _, err := st.GetProfileBySlugAndTokenHash(ctx, "main", "bad-hash"); !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("wrong hash must be not-found, got %v", err)
	}
	if _, err := st.GetProfileBySlugAndTokenHash(ctx, "nope", "good-hash"); !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("wrong slug must be not-found, got %v", err)
	}
}

func TestProfileTokenRotation(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u := seedUser(t, st, "alice")
	p, _ := st.CreateProfile(ctx, "rot", "Rotation", u.ID, "old-hash")

	if err := st.SetProfileToken(ctx, p.ID, "new-hash"); err != nil {
		t.Fatalf("SetProfileToken: %v", err)
	}

	// Old hash must no longer authenticate.
	if _, err := st.GetProfileBySlugAndTokenHash(ctx, "rot", "old-hash"); !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("old hash must be rejected after rotation, got %v", err)
	}

	// New hash must authenticate successfully.
	got, err := st.GetProfileBySlugAndTokenHash(ctx, "rot", "new-hash")
	if err != nil || got.ID != p.ID {
		t.Fatalf("new hash must authenticate after rotation: %v %+v", err, got)
	}
}

func TestListProfilesOwnVsAll(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	a := seedUser(t, st, "alice")
	b := seedUser(t, st, "bob")
	st.CreateProfile(ctx, "a1", "A1", a.ID, "h1")
	st.CreateProfile(ctx, "a2", "A2", a.ID, "h2")
	st.CreateProfile(ctx, "b1", "B1", b.ID, "h3")

	own, err := st.ListProfiles(ctx, a.ID)
	if err != nil || len(own) != 2 {
		t.Fatalf("own: %v %d", err, len(own))
	}
	all, err := st.ListProfiles(ctx, 0) // 0 = all (admin view)
	if err != nil || len(all) != 3 {
		t.Fatalf("all: %v %d", err, len(all))
	}
}

func TestProfileServersReplaceAllAndCascade(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u := seedUser(t, st, "alice")
	p, _ := st.CreateProfile(ctx, "main", "Main", u.ID, "h")

	if err := st.SetProfileServers(ctx, p.ID, []string{"github", "echo"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetProfileServers(ctx, p.ID)
	if err != nil || !reflect.DeepEqual(got, []string{"echo", "github"}) { // ordered by name
		t.Fatalf("servers: %v %v", err, got)
	}

	// Replace-all semantics.
	if err := st.SetProfileServers(ctx, p.ID, []string{"fetch"}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetProfileServers(ctx, p.ID)
	if !reflect.DeepEqual(got, []string{"fetch"}) {
		t.Fatalf("replace-all: %v", got)
	}

	// Empty-list replace clears the bundle.
	if err := st.SetProfileServers(ctx, p.ID, nil); err != nil {
		t.Fatalf("SetProfileServers nil: %v", err)
	}
	got, err = st.GetProfileServers(ctx, p.ID)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty-list replace: want empty, got %v (err: %v)", got, err)
	}

	// Delete cascades the join rows.
	if err := st.DeleteProfile(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetProfileByID(ctx, p.ID); !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("profile not deleted: %v", err)
	}
	got, _ = st.GetProfileServers(ctx, p.ID)
	if len(got) != 0 {
		t.Fatalf("join rows not cascaded: %v", got)
	}
}

func TestSetProfileServersNotFound(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	// SetProfileServers on a non-existent profile must return ErrProfileNotFound.
	err := st.SetProfileServers(ctx, 99999, []string{"foo"})
	if !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("missing profile: want ErrProfileNotFound, got %v", err)
	}
}

func TestSetProfileServersDuplicateInput(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u := seedUser(t, st, "alice")
	p, _ := st.CreateProfile(ctx, "dedup", "Dedup", u.ID, "h")

	// Duplicate names in input must succeed and store only one row.
	if err := st.SetProfileServers(ctx, p.ID, []string{"alpha", "alpha", "beta"}); err != nil {
		t.Fatalf("duplicate input: %v", err)
	}
	got, err := st.GetProfileServers(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetProfileServers: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"alpha", "beta"}) {
		t.Fatalf("dedupe: want [alpha beta], got %v", got)
	}
}
