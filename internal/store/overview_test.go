package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/store"
)

func openStats(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "stats.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestAuditStats(t *testing.T) {
	st := openStats(t)
	ctx := context.Background()
	uid := int64(7)
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	// 3 egress for "gmail", 1 egress for "slack" (today); 1 egress "gmail" 2 days ago.
	mk := func(server string, ts time.Time) store.AuditEvent {
		u := uid
		return store.AuditEvent{Kind: store.AuditKindEgress, UserID: &u, Server: server, TS: ts}
	}
	for i := 0; i < 3; i++ {
		if err := st.AppendAudit(ctx, mk("gmail", now)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.AppendAudit(ctx, mk("slack", now)); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(ctx, mk("gmail", now.AddDate(0, 0, -2))); err != nil {
		t.Fatal(err)
	}
	// An admin (non-egress) event must NOT count as a tool call.
	au := uid
	if err := st.AppendAudit(ctx, store.AuditEvent{Kind: store.AuditKindAdmin, UserID: &au, TS: now}); err != nil {
		t.Fatal(err)
	}

	s, err := st.AuditStats(ctx, uid, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	if s.ToolCalls != 5 {
		t.Fatalf("ToolCalls: want 5 egress events, got %d", s.ToolCalls)
	}
	if s.MostUsedApp != "gmail" {
		t.Fatalf("MostUsedApp: want gmail, got %q", s.MostUsedApp)
	}
	if len(s.Heatmap) != 7 {
		t.Fatalf("Heatmap: want 7 day buckets, got %d", len(s.Heatmap))
	}
	// Last bucket = today = 4 egress (3 gmail + 1 slack).
	if got := s.Heatmap[6]; got.Count != 4 {
		t.Fatalf("today bucket: want 4, got %d", got.Count)
	}
	// Bucket 2 days ago (index 4) = 1.
	if got := s.Heatmap[4]; got.Count != 1 {
		t.Fatalf("two-days-ago bucket: want 1, got %d", got.Count)
	}
}
