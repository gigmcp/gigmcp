package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrUserNotFound is returned by GetUser for an unknown id.
var ErrUserNotFound = errors.New("store: user not found")

// User is a JIT-provisioned account keyed by the OIDC (issuer, subject) pair.
// Role is a CACHE of the IdP role claim, refreshed on every login;
// it is never edited locally.
type User struct {
	ID          int64
	Issuer      string
	Subject     string
	Email       string
	DisplayName string
	Role        string // "admin" or "user"
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// NOTE: FOREIGN KEY clauses are intentionally omitted from all new schemas.
// SQLite requires PRAGMA foreign_keys=ON per-connection for FK enforcement
// (parity rule, DESIGN #14); ownership is enforced in application code instead.
const usersSchema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	issuer        TEXT NOT NULL,
	subject       TEXT NOT NULL,
	email         TEXT NOT NULL,
	display_name  TEXT NOT NULL,
	role          TEXT NOT NULL CHECK(role IN ('admin','user')),
	created_at    INTEGER NOT NULL,
	last_login_at INTEGER NOT NULL,
	UNIQUE(issuer, subject)
);`

const userCols = `id,issuer,subject,email,display_name,role,created_at,last_login_at`

// rowScanner is satisfied by *sql.Row and *sql.Rows, allowing scanUser to be
// reused for both single-row queries and loop iterations.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (User, error) {
	var u User
	var created, lastLogin int64
	err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Email, &u.DisplayName, &u.Role, &created, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt = time.Unix(created, 0).UTC()
	u.LastLoginAt = time.Unix(lastLogin, 0).UTC()
	return u, nil
}

// UpsertUserByOIDC JIT-provisions (or refreshes) a user keyed by
// UNIQUE(issuer, subject): email, display name, role and last_login are
// updated on every login.
func (s *sqliteStore) UpsertUserByOIDC(ctx context.Context, issuer, subject, email, displayName, role string) (User, error) {
	now := time.Now().Unix()
	row := s.db.QueryRowContext(ctx,
		`INSERT INTO users (issuer,subject,email,display_name,role,created_at,last_login_at)
		 VALUES (?,?,?,?,?,?,?)
		 ON CONFLICT(issuer,subject) DO UPDATE SET
		   email=excluded.email, display_name=excluded.display_name,
		   role=excluded.role, last_login_at=excluded.last_login_at
		 RETURNING `+userCols,
		issuer, subject, email, displayName, role, now, now)
	return scanUser(row)
}

// GetUser fetches a user by id.
func (s *sqliteStore) GetUser(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE id=?`, id))
}

// ListUsers returns all users ordered by id.
func (s *sqliteStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+userCols+` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}
