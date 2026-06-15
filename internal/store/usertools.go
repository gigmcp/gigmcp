package store

import "context"

const userDisabledToolsSchema = `
CREATE TABLE IF NOT EXISTS user_disabled_tools (
	user_id INTEGER NOT NULL,
	server  TEXT    NOT NULL,
	tool    TEXT    NOT NULL,
	PRIMARY KEY (user_id, server, tool)
);`

// SetUserToolEnabled: enabled=false inserts a disabled row, enabled=true deletes it.
func (s *sqliteStore) SetUserToolEnabled(ctx context.Context, userID int64, server, tool string, enabled bool) error {
	if enabled {
		_, err := s.db.ExecContext(ctx,
			`DELETE FROM user_disabled_tools WHERE user_id=? AND server=? AND tool=?`, userID, server, tool)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO user_disabled_tools (user_id, server, tool) VALUES (?,?,?)`, userID, server, tool)
	return err
}

// ListUserDisabledTools returns the tools a user turned off for a server, sorted.
func (s *sqliteStore) ListUserDisabledTools(ctx context.Context, userID int64, server string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tool FROM user_disabled_tools WHERE user_id=? AND server=? ORDER BY tool`, userID, server)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
