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

// OpenSQLite opens (creating if necessary) a SQLite-backed Store at path.
func OpenSQLite(path string) (Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// NOTE: modernc/sqlite serialises writes; if write contention appears,
	// cap the pool with db.SetMaxOpenConns(1).
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, schema); err != nil {
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
	if _, err := db.ExecContext(ctx, usersSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) EnsureServer(ctx context.Context, name, binary string) (Server, error) {
	var srv Server
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO servers (name, binary) VALUES (?, ?)
		 ON CONFLICT(name) DO UPDATE SET binary = excluded.binary
		 RETURNING id, name, binary`,
		name, binary).Scan(&srv.ID, &srv.Name, &srv.Binary)
	return srv, err
}

func (s *sqliteStore) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, binary FROM servers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var servers []Server
	for rows.Next() {
		var srv Server
		if err := rows.Scan(&srv.ID, &srv.Name, &srv.Binary); err != nil {
			return nil, err
		}
		servers = append(servers, srv)
	}
	return servers, rows.Err()
}

func (s *sqliteStore) Close() error { return s.db.Close() }
