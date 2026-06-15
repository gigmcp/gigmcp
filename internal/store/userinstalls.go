package store

import "context"

const userInstallsSchema = `
CREATE TABLE IF NOT EXISTS user_installs (
	user_id    INTEGER NOT NULL,
	server     TEXT    NOT NULL,
	created_at INTEGER NOT NULL,
	PRIMARY KEY (user_id, server)
);`

// InstallForUser records that user installed server (idempotent).
func (s *sqliteStore) InstallForUser(ctx context.Context, userID int64, server string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_installs (user_id, server, created_at) VALUES (?,?,strftime('%s','now'))`,
		userID, server)
	return err
}

// UninstallForUser removes a user's install row.
func (s *sqliteStore) UninstallForUser(ctx context.Context, userID int64, server string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_installs WHERE user_id=? AND server=?`, userID, server)
	return err
}

// IsUserInstalled reports whether the user has installed the given server.
func (s *sqliteStore) IsUserInstalled(ctx context.Context, userID int64, server string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM user_installs WHERE user_id=? AND server=?`, userID, server).Scan(&n)
	return n > 0, err
}

// ListUserInstalls returns the server names a user installed, sorted.
func (s *sqliteStore) ListUserInstalls(ctx context.Context, userID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT server FROM user_installs WHERE user_id=? ORDER BY server`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var srv string
		if err := rows.Scan(&srv); err != nil {
			return nil, err
		}
		out = append(out, srv)
	}
	return out, rows.Err()
}
