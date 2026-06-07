package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestEnsureAndListServers(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	first, err := st.EnsureServer(ctx, "echo", "/usr/local/bin/echo-mcp")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if first.ID == 0 || first.Name != "echo" || first.Binary != "/usr/local/bin/echo-mcp" {
		t.Errorf("unexpected record: %+v", first)
	}

	// Idempotent upsert by name: same ID, updated binary.
	second, err := st.EnsureServer(ctx, "echo", "/new/path/echo-mcp")
	if err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("upsert created a new row: %d != %d", second.ID, first.ID)
	}
	if second.Binary != "/new/path/echo-mcp" {
		t.Errorf("binary not updated: %q", second.Binary)
	}

	servers, err := st.ListServers(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(servers))
	}
}
