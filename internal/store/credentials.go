package store

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"
)

// ErrCredentialNotFound is returned by GetCredential when no credential row
// exists for the (server, tenant). It is a sentinel so callers can branch on
// it via errors.Is — a credential-less server (e.g. a public-API "sealed"
// server with a manifest but no secret) is distinct from a genuine error.
var ErrCredentialNotFound = errors.New("store: credential not found")

// UserTenant returns the canonical tenant key for per-user credentials
// (decimal user ID). The resolver and API must agree on this encoding so that
// credentials stored via the API are found by the egress proxy's resolver.
func UserTenant(id int64) string { return strconv.FormatInt(id, 10) }

// Credential is a stored, encrypted third-party secret plus the metadata the
// egress proxy needs to inject it and to enforce the per-tenant allowlist.
// EncryptedKey is an opaque vault ciphertext (see internal/vault).
type Credential struct {
	Server       string   // MCP server name (namespace)
	Tenant       string   // user/profile identity
	EncryptedKey []byte   // vault-encrypted real secret
	InjectHeader string   // e.g. "Authorization"
	InjectFormat string   // e.g. "Bearer {token}" — {token} replaced with the real secret
	Placeholder  string   // value the sandbox sends and the proxy looks for
	AllowedHosts []string // egress allowlist for this (server,tenant)
}

const credSchema = `
CREATE TABLE IF NOT EXISTS credentials (
	server        TEXT NOT NULL,
	tenant        TEXT NOT NULL,
	encrypted_key BLOB NOT NULL,
	inject_header TEXT NOT NULL,
	inject_format TEXT NOT NULL,
	placeholder   TEXT NOT NULL,
	allowed_hosts TEXT NOT NULL,
	PRIMARY KEY (server, tenant)
);`

// PutCredential upserts a credential by (server, tenant).
func (s *sqliteStore) PutCredential(ctx context.Context, c Credential) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO credentials (server,tenant,encrypted_key,inject_header,inject_format,placeholder,allowed_hosts)
		 VALUES (?,?,?,?,?,?,?)
		 ON CONFLICT(server,tenant) DO UPDATE SET
		   encrypted_key=excluded.encrypted_key, inject_header=excluded.inject_header,
		   inject_format=excluded.inject_format, placeholder=excluded.placeholder,
		   allowed_hosts=excluded.allowed_hosts`,
		c.Server, c.Tenant, c.EncryptedKey, c.InjectHeader, c.InjectFormat, c.Placeholder,
		strings.Join(c.AllowedHosts, "\n"))
	return err
}

// ListCredentialsByTenant returns a tenant's credentials as METADATA ONLY:
// EncryptedKey is deliberately left nil so bulk reads can never ship
// ciphertext to API responses by accident.
func (s *sqliteStore) ListCredentialsByTenant(ctx context.Context, tenant string) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT server,tenant,inject_header,inject_format,placeholder,allowed_hosts
		 FROM credentials WHERE tenant=? ORDER BY server`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		var hosts string
		if err := rows.Scan(&c.Server, &c.Tenant, &c.InjectHeader, &c.InjectFormat, &c.Placeholder, &hosts); err != nil {
			return nil, err
		}
		if hosts != "" {
			c.AllowedHosts = strings.Split(hosts, "\n")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCredential removes a credential by (server, tenant). Missing rows are
// not an error (idempotent). Returns (true, nil) when a row was deleted,
// (false, nil) when the row did not exist (noop).
func (s *sqliteStore) DeleteCredential(ctx context.Context, server, tenant string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE server=? AND tenant=?`, server, tenant)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// GetCredential fetches a credential by (server, tenant).
func (s *sqliteStore) GetCredential(ctx context.Context, server, tenant string) (Credential, error) {
	var c Credential
	var hosts string
	err := s.db.QueryRowContext(ctx,
		`SELECT server,tenant,encrypted_key,inject_header,inject_format,placeholder,allowed_hosts
		 FROM credentials WHERE server=? AND tenant=?`, server, tenant).
		Scan(&c.Server, &c.Tenant, &c.EncryptedKey, &c.InjectHeader, &c.InjectFormat, &c.Placeholder, &hosts)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, ErrCredentialNotFound
	}
	if err != nil {
		return Credential{}, err
	}
	if hosts != "" {
		c.AllowedHosts = strings.Split(hosts, "\n")
	}
	return c, nil
}
