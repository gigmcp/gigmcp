package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrProfileNotFound is returned for unknown profiles or failed token lookups.
var ErrProfileNotFound = errors.New("store: profile not found")

// Profile is a named bundle of servers exposed at /mcp/p/<slug> behind its
// own bearer token (DESIGN #11). TokenHash is the SHA-256 hex of the token —
// plaintext is shown once at create/rotate and never stored. MetaTools is the
// DESIGN #11 opt-in flag (schema only in v1; implementation deferred).
type Profile struct {
	ID        int64
	Slug      string
	Name      string
	UserID    int64 // owner
	TokenHash string
	MetaTools bool
	CreatedAt time.Time
}

const profilesSchema = `
CREATE TABLE IF NOT EXISTS profiles (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	slug       TEXT NOT NULL UNIQUE,
	name       TEXT NOT NULL,
	user_id    INTEGER NOT NULL,
	token_hash TEXT NOT NULL,
	meta_tools INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);`

const profileServersSchema = `
CREATE TABLE IF NOT EXISTS profile_servers (
	profile_id  INTEGER NOT NULL,
	server_name TEXT NOT NULL,
	PRIMARY KEY (profile_id, server_name)
);`

const profileCols = `id,slug,name,user_id,token_hash,meta_tools,created_at`

func scanProfile(row *sql.Row) (Profile, error) {
	var p Profile
	var meta int
	var created int64
	err := row.Scan(&p.ID, &p.Slug, &p.Name, &p.UserID, &p.TokenHash, &meta, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrProfileNotFound
	}
	if err != nil {
		return Profile{}, err
	}
	p.MetaTools = meta != 0
	p.CreatedAt = time.Unix(created, 0)
	return p, nil
}

// CreateProfile inserts a profile. Slug uniqueness is enforced by the schema.
func (s *sqliteStore) CreateProfile(ctx context.Context, slug, name string, userID int64, tokenHash string) (Profile, error) {
	return scanProfile(s.db.QueryRowContext(ctx,
		`INSERT INTO profiles (slug,name,user_id,token_hash,created_at)
		 VALUES (?,?,?,?,?) RETURNING `+profileCols,
		slug, name, userID, tokenHash, time.Now().Unix()))
}

// GetProfileByID fetches a profile by id.
func (s *sqliteStore) GetProfileByID(ctx context.Context, id int64) (Profile, error) {
	return scanProfile(s.db.QueryRowContext(ctx,
		`SELECT `+profileCols+` FROM profiles WHERE id=?`, id))
}

// GetProfileBySlugAndTokenHash is the /mcp/p/{slug} auth lookup: both the
// slug and the hashed bearer token must match.
func (s *sqliteStore) GetProfileBySlugAndTokenHash(ctx context.Context, slug, tokenHash string) (Profile, error) {
	return scanProfile(s.db.QueryRowContext(ctx,
		`SELECT `+profileCols+` FROM profiles WHERE slug=? AND token_hash=?`, slug, tokenHash))
}

// ListProfiles returns profiles owned by userID, or ALL profiles when
// userID == 0 (admin view). Ordered by id.
func (s *sqliteStore) ListProfiles(ctx context.Context, userID int64) ([]Profile, error) {
	q := `SELECT ` + profileCols + ` FROM profiles`
	var args []any
	if userID != 0 {
		q += ` WHERE user_id=?`
		args = append(args, userID)
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Profile
	for rows.Next() {
		var p Profile
		var meta int
		var created int64
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.UserID, &p.TokenHash, &meta, &created); err != nil {
			return nil, err
		}
		p.MetaTools = meta != 0
		p.CreatedAt = time.Unix(created, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateProfileName renames a profile.
func (s *sqliteStore) UpdateProfileName(ctx context.Context, id int64, name string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE profiles SET name=? WHERE id=?`, name, id)
	return err
}

// SetProfileToken replaces the stored token hash (rotation).
func (s *sqliteStore) SetProfileToken(ctx context.Context, id int64, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE profiles SET token_hash=? WHERE id=?`, tokenHash, id)
	return err
}

// DeleteProfile removes a profile and its profile_servers rows in one tx.
func (s *sqliteStore) DeleteProfile(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM profile_servers WHERE profile_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM profiles WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetProfileServers replaces the profile's server bundle (replace-all, one tx).
func (s *sqliteStore) SetProfileServers(ctx context.Context, id int64, names []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM profile_servers WHERE profile_id=?`, id); err != nil {
		return err
	}
	for _, n := range names {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO profile_servers (profile_id, server_name) VALUES (?,?)`, id, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetProfileServers returns the profile's bundled server names, ordered.
func (s *sqliteStore) GetProfileServers(ctx context.Context, id int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT server_name FROM profile_servers WHERE profile_id=? ORDER BY server_name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}
