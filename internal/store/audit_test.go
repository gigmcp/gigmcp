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
		return store.AuditEvent{Kind: "egress", UserID: &uid, Server: "github", Host: host, Decision: "resolved"}
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
	if err := st.AppendAudit(ctx, store.AuditEvent{Kind: "egress", Server: "echo", Host: "h4", Decision: "denied", Detail: "host not in allowlist"}); err != nil {
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
