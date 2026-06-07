package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrSessionNotFound is returned for unknown or expired sessions.
var ErrSessionNotFound = errors.New("store: session not found")

// Session is an opaque DB-backed browser session.
// TokenHash is the SHA-256 hex of the cookie value — the plaintext never
// touches the database. The impersonation columns implement DESIGN #20
// view-as mode.
type Session struct {
	TokenHash string
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
	// ImpersonatingUserID is the target user's ID while view-as is active, or
	// nil when no impersonation is in progress. Consumers reading these fields
	// directly must check ImpersonationExpiresAt; only the auth middleware
	// enforces it.
	ImpersonatingUserID *int64
	// ImpersonationExpiresAt is the wall-clock deadline for view-as mode.
	// Expiry is enforced by callers (auth middleware), not by GetSession.
	ImpersonationExpiresAt *time.Time
}

const sessionsSchema = `
CREATE TABLE IF NOT EXISTS sessions (
	token_hash               TEXT PRIMARY KEY,
	user_id                  INTEGER NOT NULL,
	created_at               INTEGER NOT NULL,
	expires_at               INTEGER NOT NULL,
	impersonating_user_id    INTEGER,
	impersonation_expires_at INTEGER
);`

// CreateSession inserts a session row.
// As a cheap purge of abandoned sessions, any already-expired rows are deleted
// before the insert. Login is low-frequency so the extra DELETE is negligible.
func (s *sqliteStore) CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error {
	// Cheap purge: delete expired sessions opportunistically on login.
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)`,
		tokenHash, userID, time.Now().Unix(), expiresAt.Unix())
	return err
}

// GetSession fetches a live session. Expired rows are deleted on read and
// reported as ErrSessionNotFound (cheap lazy reaping; no background sweeper).
func (s *sqliteStore) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	var created, expires int64
	var impID, impExp sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash,user_id,created_at,expires_at,impersonating_user_id,impersonation_expires_at
		 FROM sessions WHERE token_hash=?`, tokenHash).
		Scan(&sess.TokenHash, &sess.UserID, &created, &expires, &impID, &impExp)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, err
	}
	sess.CreatedAt = time.Unix(created, 0).UTC()
	sess.ExpiresAt = time.Unix(expires, 0).UTC()
	if impID.Valid {
		v := impID.Int64
		sess.ImpersonatingUserID = &v
	}
	if impExp.Valid {
		tv := time.Unix(impExp.Int64, 0).UTC()
		sess.ImpersonationExpiresAt = &tv
	}
	if time.Now().After(sess.ExpiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=? AND expires_at<=?`, tokenHash, sess.ExpiresAt.Unix())
		return Session{}, ErrSessionNotFound
	}
	return sess, nil
}

// DeleteSession removes a session (logout / revocation). Missing rows are not an error.
func (s *sqliteStore) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

// SetImpersonation stamps view-as state onto a session row.
// Returns ErrSessionNotFound if no session with tokenHash exists.
func (s *sqliteStore) SetImpersonation(ctx context.Context, tokenHash string, targetUserID int64, expiresAt time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET impersonating_user_id=?, impersonation_expires_at=? WHERE token_hash=?`,
		targetUserID, expiresAt.Unix(), tokenHash)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrSessionNotFound
	}
	return nil
}

// ClearImpersonation removes view-as state from a session row.
func (s *sqliteStore) ClearImpersonation(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET impersonating_user_id=NULL, impersonation_expires_at=NULL WHERE token_hash=?`,
		tokenHash)
	return err
}
