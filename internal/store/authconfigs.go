package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// ErrAuthConfigNotFound is the sentinel for GetAuthConfig with no row.
var ErrAuthConfigNotFound = errors.New("store: auth config not found")

// AuthConfig is a deployment-level OAuth vendor registration. One row per
// canonical vendor. The client secret is vault ciphertext (never plaintext at
// rest); ListAuthConfigs strips it so bulk reads cannot leak it.
type AuthConfig struct {
	Vendor                string
	AuthorizeURL          string
	TokenURL              string
	ClientID              string
	EncryptedClientSecret []byte   // vault ciphertext; nil in List results
	DefaultScopes         []string // space/comma list, stored newline-joined
	PKCE                  bool
	Mode                  string // managed | byo
}

const authConfigSchema = `
CREATE TABLE IF NOT EXISTS auth_configs (
	vendor                  TEXT PRIMARY KEY,
	authorize_url           TEXT NOT NULL,
	token_url               TEXT NOT NULL,
	client_id               TEXT NOT NULL,
	encrypted_client_secret BLOB NOT NULL,
	default_scopes          TEXT NOT NULL DEFAULT '',
	pkce                    INTEGER NOT NULL DEFAULT 0,
	mode                    TEXT NOT NULL DEFAULT 'byo'
);`

func (s *sqliteStore) PutAuthConfig(ctx context.Context, a AuthConfig) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO auth_configs (vendor,authorize_url,token_url,client_id,encrypted_client_secret,default_scopes,pkce,mode)
		 VALUES (?,?,?,?,?,?,?,?)
		 ON CONFLICT(vendor) DO UPDATE SET
		   authorize_url=excluded.authorize_url, token_url=excluded.token_url,
		   client_id=excluded.client_id, encrypted_client_secret=excluded.encrypted_client_secret,
		   default_scopes=excluded.default_scopes, pkce=excluded.pkce, mode=excluded.mode`,
		a.Vendor, a.AuthorizeURL, a.TokenURL, a.ClientID, a.EncryptedClientSecret,
		strings.Join(a.DefaultScopes, "\n"), boolToInt(a.PKCE), a.Mode)
	return err
}

func (s *sqliteStore) GetAuthConfig(ctx context.Context, vendor string) (AuthConfig, error) {
	var a AuthConfig
	var scopes string
	var pkce int
	err := s.db.QueryRowContext(ctx,
		`SELECT vendor,authorize_url,token_url,client_id,encrypted_client_secret,default_scopes,pkce,mode
		 FROM auth_configs WHERE vendor=?`, vendor).
		Scan(&a.Vendor, &a.AuthorizeURL, &a.TokenURL, &a.ClientID, &a.EncryptedClientSecret, &scopes, &pkce, &a.Mode)
	if errors.Is(err, sql.ErrNoRows) {
		return AuthConfig{}, ErrAuthConfigNotFound
	}
	if err != nil {
		return AuthConfig{}, err
	}
	if scopes != "" {
		a.DefaultScopes = strings.Split(scopes, "\n")
	}
	a.PKCE = pkce != 0
	return a, nil
}

// ListAuthConfigs returns metadata only: EncryptedClientSecret is left nil so
// bulk reads can never ship ciphertext to an API response.
func (s *sqliteStore) ListAuthConfigs(ctx context.Context) ([]AuthConfig, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT vendor,authorize_url,token_url,client_id,default_scopes,pkce,mode
		 FROM auth_configs ORDER BY vendor`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuthConfig
	for rows.Next() {
		var a AuthConfig
		var scopes string
		var pkce int
		if err := rows.Scan(&a.Vendor, &a.AuthorizeURL, &a.TokenURL, &a.ClientID, &scopes, &pkce, &a.Mode); err != nil {
			return nil, err
		}
		if scopes != "" {
			a.DefaultScopes = strings.Split(scopes, "\n")
		}
		a.PKCE = pkce != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAuthConfig removes a vendor row; missing rows are not an error.
func (s *sqliteStore) DeleteAuthConfig(ctx context.Context, vendor string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_configs WHERE vendor=?`, vendor)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
