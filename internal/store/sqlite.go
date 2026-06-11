package store

import (
	"context"
	"database/sql"

	_ "modernc.org/sqlite" // pure-Go driver; keeps CGO_ENABLED=0 builds
)

type sqliteStore struct {
	db *sql.DB
}

var _ Store = (*sqliteStore)(nil)

const schema = `
CREATE TABLE IF NOT EXISTS servers (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	name   TEXT NOT NULL UNIQUE,
	binary TEXT NOT NULL
);`

// migrateServers is an additive, idempotent migration adding the toolpack
// bundle_dir column. Existing rows default to ” (empty), which the spawn path
// treats as a single-file server — so legacy/go-static servers are untouched.
// SQLite has no "ADD COLUMN IF NOT EXISTS"; we probe the column list and add it
// only when absent, making OpenSQLite safe to run against both fresh and
// already-migrated databases.
func migrateServers(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(servers)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	has := false
	for rows.Next() {
		var (
			cid, notnull, pk int
			nameCol, ctype   string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &nameCol, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if nameCol == "bundle_dir" {
			has = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = db.ExecContext(ctx,
		`ALTER TABLE servers ADD COLUMN bundle_dir TEXT NOT NULL DEFAULT ''`)
	return err
}

// migrateManifests is an additive, idempotent migration adding the presentation
// branding columns (display_name/category/description) to the manifests table.
// These mirror the signed index's branding fields and are EXCLUDED from
// RuntimeHash, so an already-installed server backfills them on the next boot
// reconcile without re-consent. Existing rows default to ” (empty). SQLite has
// no "ADD COLUMN IF NOT EXISTS"; we probe the column list and add each only when
// absent, making OpenSQLite safe against both fresh and already-migrated DBs.
func migrateManifests(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info(manifests)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	present := map[string]bool{}
	for rows.Next() {
		var (
			cid, notnull, pk int
			nameCol, ctype   string
			dflt             sql.NullString
		)
		if err := rows.Scan(&cid, &nameCol, &ctype, &notnull, &dflt, &pk); err != nil {
			return err
		}
		present[nameCol] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, col := range []string{"display_name", "category", "description"} {
		if present[col] {
			continue
		}
		if _, err := db.ExecContext(ctx,
			`ALTER TABLE manifests ADD COLUMN `+col+` TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

// OpenSQLite opens (creating if necessary) a SQLite-backed Store at path.
//
// Concurrency: the gateway hits this store from many goroutines at once — every
// /mcp/p/{slug} request does a profile auth read while the AuditingResolver's
// writer goroutine streams egress-audit writes. Plain SQLite would have those
// concurrent reads fail instantly with SQLITE_BUSY ("database is locked"); on
// the auth path that surfaces to the client as a spurious 401 Unauthorized.
// We close that race two ways:
//   - journal_mode=WAL lets readers proceed while a write is in progress
//     (readers never block on the writer, writer never blocks on readers).
//   - busy_timeout=5000 makes the rare remaining contention (writer-vs-writer,
//     WAL checkpoint) WAIT up to 5s and retry instead of erroring immediately.
//
// foreign_keys is left at the SQLite default (off); the schema does not rely on
// FK enforcement. These pragmas are set via the DSN so they apply to every
// pooled connection, not just the one that ran them.
func OpenSQLite(path string) (Store, error) {
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrateServers(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, credSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, manifestSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, disabledToolsSchema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrateManifests(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, usersSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, sessionsSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, profilesSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, profileServersSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, auditSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, authConfigSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, connAccountSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) EnsureServer(ctx context.Context, name, binary string) (Server, error) {
	return s.ensureServer(ctx, name, binary, "")
}

func (s *sqliteStore) EnsureServerBundle(ctx context.Context, name, entrypoint, bundleDir string) (Server, error) {
	return s.ensureServer(ctx, name, entrypoint, bundleDir)
}

// ensureServer upserts a server row, writing bundle_dir so a re-install can flip
// a server between single-file (”) and bundle (a staging path) modes.
func (s *sqliteStore) ensureServer(ctx context.Context, name, binary, bundleDir string) (Server, error) {
	var srv Server
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO servers (name, binary, bundle_dir) VALUES (?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET binary = excluded.binary, bundle_dir = excluded.bundle_dir
		 RETURNING id, name, binary, bundle_dir`,
		name, binary, bundleDir).Scan(&srv.ID, &srv.Name, &srv.Binary, &srv.BundleDir)
	return srv, err
}

func (s *sqliteStore) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, binary, bundle_dir FROM servers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var servers []Server
	for rows.Next() {
		var srv Server
		if err := rows.Scan(&srv.ID, &srv.Name, &srv.Binary, &srv.BundleDir); err != nil {
			return nil, err
		}
		servers = append(servers, srv)
	}
	return servers, rows.Err()
}

func (s *sqliteStore) Close() error { return s.db.Close() }
