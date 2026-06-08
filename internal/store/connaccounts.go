package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// ErrConnectedAccountNotFound is returned by GetConnectedAccount with no row.
var ErrConnectedAccountNotFound = errors.New("store: connected account not found")

// ConnectedAccount is a user's OAuth connection to one vendor. One row per
// (user_id, vendor) — a single connection covers all of that vendor's apps.
// Refresh and access tokens are vault ciphertext; List results strip both.
type ConnectedAccount struct {
	UserID                int64
	Vendor                string
	EncryptedRefreshToken []byte // vault ciphertext; nil in List results
	EncryptedAccessToken  []byte // vault ciphertext; nil in List results
	ExpiresAt             time.Time
	GrantedScopes         []string
}

const connAccountSchema = `
CREATE TABLE IF NOT EXISTS connected_accounts (
	user_id                 INTEGER NOT NULL,
	vendor                  TEXT NOT NULL,
	encrypted_refresh_token BLOB NOT NULL,
	encrypted_access_token  BLOB NOT NULL,
	expires_at              INTEGER NOT NULL,
	granted_scopes          TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (user_id, vendor)
);`

func (s *sqliteStore) PutConnectedAccount(ctx context.Context, c ConnectedAccount) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO connected_accounts (user_id,vendor,encrypted_refresh_token,encrypted_access_token,expires_at,granted_scopes)
		 VALUES (?,?,?,?,?,?)
		 ON CONFLICT(user_id,vendor) DO UPDATE SET
		   encrypted_refresh_token=excluded.encrypted_refresh_token,
		   encrypted_access_token=excluded.encrypted_access_token,
		   expires_at=excluded.expires_at, granted_scopes=excluded.granted_scopes`,
		c.UserID, c.Vendor, c.EncryptedRefreshToken, c.EncryptedAccessToken,
		c.ExpiresAt.Unix(), strings.Join(c.GrantedScopes, "\n"))
	return err
}

// UpdateConnectedAccountTokens rotates ONLY the access token + expiry (the
// resolver-time refresh path); the refresh token and granted scopes are
// untouched.
func (s *sqliteStore) UpdateConnectedAccountTokens(ctx context.Context, userID int64, vendor string, encAccess []byte, expiresAt time.Time) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE connected_accounts SET encrypted_access_token=?, expires_at=? WHERE user_id=? AND vendor=?`,
		encAccess, expiresAt.Unix(), userID, vendor)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrConnectedAccountNotFound
	}
	return nil
}

func (s *sqliteStore) GetConnectedAccount(ctx context.Context, userID int64, vendor string) (ConnectedAccount, error) {
	var c ConnectedAccount
	var scopes string
	var exp int64
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id,vendor,encrypted_refresh_token,encrypted_access_token,expires_at,granted_scopes
		 FROM connected_accounts WHERE user_id=? AND vendor=?`, userID, vendor).
		Scan(&c.UserID, &c.Vendor, &c.EncryptedRefreshToken, &c.EncryptedAccessToken, &exp, &scopes)
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectedAccount{}, ErrConnectedAccountNotFound
	}
	if err != nil {
		return ConnectedAccount{}, err
	}
	c.ExpiresAt = time.Unix(exp, 0).UTC()
	if scopes != "" {
		c.GrantedScopes = strings.Split(scopes, "\n")
	}
	return c, nil
}

// ListConnectedAccountsByUser returns a user's connections as METADATA ONLY:
// both token ciphertext fields are left nil.
func (s *sqliteStore) ListConnectedAccountsByUser(ctx context.Context, userID int64) ([]ConnectedAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id,vendor,expires_at,granted_scopes
		 FROM connected_accounts WHERE user_id=? ORDER BY vendor`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectedAccount
	for rows.Next() {
		var c ConnectedAccount
		var scopes string
		var exp int64
		if err := rows.Scan(&c.UserID, &c.Vendor, &exp, &scopes); err != nil {
			return nil, err
		}
		c.ExpiresAt = time.Unix(exp, 0).UTC()
		if scopes != "" {
			c.GrantedScopes = strings.Split(scopes, "\n")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteConnectedAccount removes a (user, vendor) connection; idempotent.
func (s *sqliteStore) DeleteConnectedAccount(ctx context.Context, userID int64, vendor string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM connected_accounts WHERE user_id=? AND vendor=?`, userID, vendor)
	return err
}
