package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// A pre-bundle database (servers table without bundle_dir, holding an existing
// single-file server row) must migrate additively: the column is added with a
// ” default and the existing row keeps behaving as a single-file server.
func TestMigrateServersAddsBundleDirToExistingRow(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Simulate an old DB: create the original servers schema and seed a row,
	// WITHOUT the bundle_dir column.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, schema); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO servers (name, binary) VALUES ('echo', '/bin/echo-mcp')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// Re-open through OpenSQLite, which runs migrateServers.
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open (migrate): %v", err)
	}
	defer st.Close()

	servers, err := st.ListServers(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(servers) != 1 || servers[0].Name != "echo" || servers[0].Binary != "/bin/echo-mcp" {
		t.Fatalf("existing row not preserved: %+v", servers)
	}
	if servers[0].BundleDir != "" {
		t.Fatalf("migrated row must default to single-file ('' bundle_dir), got %q", servers[0].BundleDir)
	}

	// Migration is idempotent: a second open must not error.
	st2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("re-open (idempotent migrate): %v", err)
	}
	st2.Close()
}
