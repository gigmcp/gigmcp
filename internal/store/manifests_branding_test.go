package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

// oldManifestSchema is the pre-branding manifests table (no
// display_name/category/description columns). Mirrors the historical CREATE
// TABLE so the migration test can seed a legacy DB.
const oldManifestSchema = `
CREATE TABLE IF NOT EXISTS manifests (
	server         TEXT PRIMARY KEY,
	version        TEXT NOT NULL,
	digest         TEXT NOT NULL,
	tier           TEXT NOT NULL,
	entrypoint     TEXT NOT NULL,
	allowed_hosts  TEXT NOT NULL,
	injections     TEXT NOT NULL,
	tools          TEXT NOT NULL,
	manifest_hash  TEXT NOT NULL,
	consented_hash TEXT NOT NULL DEFAULT ''
);`

// A pre-branding database (manifests table without display_name/category/
// description, holding an existing row) must migrate additively: the columns
// are added with ” defaults and the existing row reads back with empty-string
// branding. A second open must be idempotent (no error).
func TestMigrateManifestsAddsBrandingToExistingRow(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Simulate an old DB: create the pre-branding manifests schema and seed a
	// row WITHOUT the branding columns.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, oldManifestSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx,
		`INSERT INTO manifests
		   (server,version,digest,tier,entrypoint,allowed_hosts,injections,tools,manifest_hash,consented_hash)
		 VALUES ('legacy','1.0.0','sha256:x','sealed','/server','','[]','[]','h1','h1')`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	// Re-open through OpenSQLite, which runs migrateManifests.
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("open (migrate): %v", err)
	}
	defer st.Close()

	got, err := st.GetManifest(ctx, "legacy")
	if err != nil {
		t.Fatalf("get migrated row: %v", err)
	}
	if got.Version != "1.0.0" {
		t.Fatalf("existing row not preserved: %+v", got)
	}
	if got.DisplayName != "" || got.Category != "" || got.Description != "" {
		t.Fatalf("migrated legacy row must default to empty branding: %+v", got)
	}

	// Migration is idempotent: a second open must not error.
	st2, err := OpenSQLite(path)
	if err != nil {
		t.Fatalf("re-open (idempotent migrate): %v", err)
	}
	st2.Close()
}

// PutManifest must persist DisplayName/Category/Description and read them back
// intact via both GetManifest and ListManifests. A second PutManifest with
// CHANGED branding (same other fields) must update branding (proves the
// ON CONFLICT DO UPDATE writes branding — the backfill mechanism).
func TestManifestBrandingRoundTripAndUpdate(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	rec := sampleRecord()
	rec.DisplayName = "Slack"
	rec.Category = "communication"
	rec.Description = "Send and read Slack messages."
	if err := st.PutManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}

	got, err := st.GetManifest(ctx, "slack-mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "Slack" || got.Category != "communication" ||
		got.Description != "Send and read Slack messages." {
		t.Fatalf("branding not persisted via GetManifest: %+v", got)
	}

	list, err := st.ListManifests(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].DisplayName != "Slack" ||
		list[0].Category != "communication" ||
		list[0].Description != "Send and read Slack messages." {
		t.Fatalf("branding not persisted via ListManifests: %+v", list)
	}

	// Idempotent update with CHANGED branding (same other fields): the ON
	// CONFLICT DO UPDATE must write the new branding.
	rec.DisplayName = "Slack (updated)"
	rec.Category = "productivity"
	rec.Description = "Updated description."
	if err := st.PutManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got2, err := st.GetManifest(ctx, "slack-mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got2.DisplayName != "Slack (updated)" || got2.Category != "productivity" ||
		got2.Description != "Updated description." {
		t.Fatalf("ON CONFLICT DO UPDATE must refresh branding: %+v", got2)
	}
}
