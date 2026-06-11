package store

import "context"

// disabledToolsSchema is the per-app admin-disabled tool set. Presence of a
// (server, tool) row means that tool is DISABLED for the app; the default
// (no row) is enabled. The set is keyed by server name and is global across
// profiles, so it survives a manifest re-install (the installer rewrites
// manifests.tools but never touches this table).
const disabledToolsSchema = `
CREATE TABLE IF NOT EXISTS app_disabled_tools (
	server TEXT NOT NULL,
	tool   TEXT NOT NULL,
	PRIMARY KEY (server, tool)
);`

// ListDisabledTools returns the disabled tool names for an app, sorted.
func (s *sqliteStore) ListDisabledTools(ctx context.Context, server string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tool FROM app_disabled_tools WHERE server=? ORDER BY tool`, server)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetToolEnabled toggles a tool for an app. enabled=false records the tool as
// disabled (INSERT OR IGNORE so it is idempotent); enabled=true clears it
// (DELETE, a noop when absent). Presence == disabled.
func (s *sqliteStore) SetToolEnabled(ctx context.Context, server, tool string, enabled bool) error {
	if enabled {
		_, err := s.db.ExecContext(ctx,
			`DELETE FROM app_disabled_tools WHERE server=? AND tool=?`, server, tool)
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO app_disabled_tools (server, tool) VALUES (?, ?)`, server, tool)
	return err
}

// DeleteDisabledToolsForServer clears an app's entire disabled set (uninstall).
func (s *sqliteStore) DeleteDisabledToolsForServer(ctx context.Context, server string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM app_disabled_tools WHERE server=?`, server)
	return err
}
