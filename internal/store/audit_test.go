package store_test

import (
	"context"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestAppendAndListAudit(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	alice := seedUser(t, st, "alice")
	bob := seedUser(t, st, "bob")

	mk := func(uid int64, host string) store.AuditEvent {
		return store.AuditEvent{Kind: store.AuditKindEgress, UserID: &uid, Server: "github", Host: host, Decision: "resolved"}
	}
	if err := st.AppendAudit(ctx, mk(alice.ID, "h1.example.com")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := st.AppendAudit(ctx, mk(bob.ID, "h2.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(ctx, mk(alice.ID, "h3.example.com")); err != nil {
		t.Fatal(err)
	}
	// An event with no user (e.g. legacy "default" tenant egress).
	if err := st.AppendAudit(ctx, store.AuditEvent{Kind: store.AuditKindEgress, Server: "echo", Host: "h4", Decision: "denied", Detail: "host not in allowlist"}); err != nil {
		t.Fatal(err)
	}

	all, err := st.ListAudit(ctx, 0, 10, 0)
	if err != nil || len(all) != 4 {
		t.Fatalf("list all: %v %d", err, len(all))
	}
	// Newest first; ts and id populated.
	if all[0].Host != "h4" || all[3].Host != "h1.example.com" || all[0].ID == 0 || all[0].TS.IsZero() {
		t.Fatalf("ordering/fields: %+v", all)
	}

	// Keyset pagination: page after the newest two.
	page, err := st.ListAudit(ctx, all[1].ID, 10, 0)
	if err != nil || len(page) != 2 || page[0].ID != all[2].ID {
		t.Fatalf("keyset page: %v %+v", err, page)
	}

	// Per-user filter.
	mine, err := st.ListAudit(ctx, 0, 10, alice.ID)
	if err != nil || len(mine) != 2 {
		t.Fatalf("user filter: %v %d", err, len(mine))
	}
	for _, e := range mine {
		if e.UserID == nil || *e.UserID != alice.ID {
			t.Fatalf("foreign event leaked: %+v", e)
		}
	}
}

// TestAuditLimitClamp verifies the [1,500] clamp:
//   - limit=0 → default 100 (tested with only 5 rows: all 5 returned)
//   - limit=2 → exactly 2 rows returned
//   - limit=501 → clamped to 500 (seed 501 rows, assert ≤500 and no error)
func TestAuditLimitClamp(t *testing.T) {
	ctx := context.Background()

	t.Run("zero_defaults_to_100", func(t *testing.T) {
		st := openTestStore(t)
		alice := seedUser(t, st, "alice")
		uid := alice.ID
		for i := 0; i < 5; i++ {
			if err := st.AppendAudit(ctx, store.AuditEvent{Kind: store.AuditKindAuth, UserID: &uid}); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
		rows, err := st.ListAudit(ctx, 0, 0, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		// limit=0 → 100 default; with only 5 rows the result is all 5.
		if len(rows) != 5 {
			t.Fatalf("want 5 rows, got %d", len(rows))
		}
	})

	t.Run("limit_2", func(t *testing.T) {
		st := openTestStore(t)
		alice := seedUser(t, st, "alice")
		uid := alice.ID
		for i := 0; i < 5; i++ {
			if err := st.AppendAudit(ctx, store.AuditEvent{Kind: store.AuditKindAuth, UserID: &uid}); err != nil {
				t.Fatalf("append: %v", err)
			}
		}
		rows, err := st.ListAudit(ctx, 0, 2, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("want 2 rows, got %d", len(rows))
		}
	})

	t.Run("501_clamped_to_500", func(t *testing.T) {
		st := openTestStore(t)
		alice := seedUser(t, st, "alice")
		uid := alice.ID
		for i := 0; i < 501; i++ {
			if err := st.AppendAudit(ctx, store.AuditEvent{Kind: store.AuditKindAdmin, UserID: &uid}); err != nil {
				t.Fatalf("append row %d: %v", i, err)
			}
		}
		rows, err := st.ListAudit(ctx, 0, 501, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(rows) > 500 {
			t.Fatalf("want ≤500 rows, got %d", len(rows))
		}
		if len(rows) != 500 {
			t.Fatalf("want exactly 500 rows (clamp), got %d", len(rows))
		}
	})
}

// TestAuditPaginationTermination verifies that fetching exactly one page worth
// of rows and then fetching the next page returns an empty slice (not an error).
func TestAuditPaginationTermination(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	alice := seedUser(t, st, "alice")
	uid := alice.ID

	// Seed exactly 3 rows.
	for i := 0; i < 3; i++ {
		if err := st.AppendAudit(ctx, store.AuditEvent{Kind: store.AuditKindEgress, UserID: &uid, Host: "h"}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	// Page 1: fetch all 3.
	page1, err := st.ListAudit(ctx, 0, 3, 0)
	if err != nil || len(page1) != 3 {
		t.Fatalf("page1: %v len=%d", err, len(page1))
	}

	// Page 2: must be empty (no error).
	lastID := page1[len(page1)-1].ID
	page2, err := st.ListAudit(ctx, lastID, 3, 0)
	if err != nil {
		t.Fatalf("page2 error: %v", err)
	}
	if len(page2) != 0 {
		t.Fatalf("page2 should be empty, got %d rows", len(page2))
	}
}

// TestAuditUserIDAndBeforeID verifies the combined userID + beforeID branch.
func TestAuditUserIDAndBeforeID(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	alice := seedUser(t, st, "alice")
	bob := seedUser(t, st, "bob")
	aid := alice.ID
	bid := bob.ID

	// Interleave alice and bob events.
	for i := 0; i < 3; i++ {
		if err := st.AppendAudit(ctx, store.AuditEvent{Kind: store.AuditKindEgress, UserID: &aid, Host: "alice-host"}); err != nil {
			t.Fatalf("append alice: %v", err)
		}
		if err := st.AppendAudit(ctx, store.AuditEvent{Kind: store.AuditKindEgress, UserID: &bid, Host: "bob-host"}); err != nil {
			t.Fatalf("append bob: %v", err)
		}
	}

	// Fetch all alice events first (newest-first).
	allAlice, err := st.ListAudit(ctx, 0, 10, alice.ID)
	if err != nil || len(allAlice) != 3 {
		t.Fatalf("allAlice: %v len=%d", err, len(allAlice))
	}

	// Now paginate: fetch alice's events before the newest one.
	pivotID := allAlice[0].ID
	page, err := st.ListAudit(ctx, pivotID, 10, alice.ID)
	if err != nil {
		t.Fatalf("combined filter: %v", err)
	}
	// Should return the remaining 2 alice events.
	if len(page) != 2 {
		t.Fatalf("want 2 alice events before pivot, got %d", len(page))
	}
	for _, e := range page {
		if e.UserID == nil || *e.UserID != alice.ID {
			t.Fatalf("non-alice event in result: %+v", e)
		}
		if e.ID >= pivotID {
			t.Fatalf("event id %d not before pivot %d", e.ID, pivotID)
		}
	}
}

// TestAppendAuditInvalidKind verifies that an invalid kind is rejected by the
// CHECK constraint and AppendAudit returns a non-nil error.
func TestAppendAuditInvalidKind(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	err := st.AppendAudit(ctx, store.AuditEvent{Kind: "invalid-kind", Host: "h"})
	if err == nil {
		t.Fatal("expected error for invalid kind, got nil")
	}
}
