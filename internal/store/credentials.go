package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

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

// GetCredential fetches a credential by (server, tenant).
func (s *sqliteStore) GetCredential(ctx context.Context, server, tenant string) (Credential, error) {
	var c Credential
	var hosts string
	err := s.db.QueryRowContext(ctx,
		`SELECT server,tenant,encrypted_key,inject_header,inject_format,placeholder,allowed_hosts
		 FROM credentials WHERE server=? AND tenant=?`, server, tenant).
		Scan(&c.Server, &c.Tenant, &c.EncryptedKey, &c.InjectHeader, &c.InjectFormat, &c.Placeholder, &hosts)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, errors.New("store: credential not found")
	}
	if err != nil {
		return Credential{}, err
	}
	if hosts != "" {
		c.AllowedHosts = strings.Split(hosts, "\n")
	}
	return c, nil
}
