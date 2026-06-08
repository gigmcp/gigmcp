package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// ErrManifestNotFound is returned by GetManifest/RecordConsent for servers
// with no installed manifest (e.g. legacy GIG_ECHO_BIN-seeded servers).
var ErrManifestNotFound = errors.New("store: manifest not found")

// Injection is one credential's proxy-injection config from the manifest plus
// the install-time-generated high-entropy placeholder sentinel (the proxy
// matches it as a substring — see proxy.Credential).
//
// Type/Provider/Scopes carry the manifest credential's auth descriptor so the
// OAuth broker can identify oauth2 credentials, key the per-vendor Connected
// Account, and compute the scope union for incremental consent. The proxy
// injection itself is still driven by Header/Format/Env/Placeholder.
type Injection struct {
	ID          string   `json:"id"`
	Type        string   `json:"type,omitempty"`     // oauth2 | api_key | basic | custom_env | none
	Provider    string   `json:"provider,omitempty"` // per-connector slug (least-privilege scopes + incremental consent)
	Vendor      string   `json:"vendor,omitempty"`   // canonical OAuth-app grouping key (e.g. "google"); empty ⇒ fall back to Provider
	Scopes      []string `json:"scopes,omitempty"`   // oauth2 scopes this app requires
	Header      string   `json:"header,omitempty"`   // sealed: header the proxy rewrites
	Format      string   `json:"format,omitempty"`   // sealed: "{token}" → real secret
	Env         string   `json:"env,omitempty"`      // entrusted: env var for the real secret
	Placeholder string   `json:"placeholder,omitempty"`
}

// ToolEntry mirrors the manifest's tool list (DESIGN #11 default subset).
type ToolEntry struct {
	Name    string `json:"name"`
	Default bool   `json:"default"`
}

// ManifestRecord is the persisted, enforcement-relevant projection of a
// registry manifest (kept in its own table and file, separate from the
// control-plane store).
type ManifestRecord struct {
	Server     string
	Version    string
	Digest     string
	Tier       string
	Entrypoint string
	// DisplayName/Category/Description are presentation-only branding from the
	// signed index. They are EXCLUDED from schema.Manifest.RuntimeHash (like
	// vendor), so persisting/backfilling them never diverges a baked image from
	// the index nor triggers re-consent. Nullable/empty for legacy rows.
	DisplayName   string
	Category      string
	Description   string
	AllowedHosts  []string
	Injections    []Injection
	Tools         []ToolEntry
	ManifestHash  string // canonical-JSON SHA-256 of the manifest
	ConsentedHash string // last hash the user accepted ("" = never)
}

// NeedsReconsent reports whether the installed manifest differs from what the
// user last consented to (DESIGN #7: manifest changes on update ⇒ re-consent).
// The gateway's profile spawn path refuses to launch such servers (fail
// closed) until RecordConsent moves consented_hash to the new manifest hash.
func (m ManifestRecord) NeedsReconsent() bool { return m.ManifestHash != m.ConsentedHash }

const manifestSchema = `
CREATE TABLE IF NOT EXISTS manifests (
	server         TEXT PRIMARY KEY,
	version        TEXT NOT NULL,
	digest         TEXT NOT NULL,
	tier           TEXT NOT NULL,
	entrypoint     TEXT NOT NULL,
	display_name   TEXT NOT NULL DEFAULT '',
	category       TEXT NOT NULL DEFAULT '',
	description    TEXT NOT NULL DEFAULT '',
	allowed_hosts  TEXT NOT NULL,
	injections     TEXT NOT NULL,
	tools          TEXT NOT NULL,
	manifest_hash  TEXT NOT NULL,
	consented_hash TEXT NOT NULL DEFAULT ''
);`

// PutManifest upserts by server. consented_hash is PRESERVED on update —
// consent moves only via RecordConsent, so a version bump leaves the old
// consent in place and NeedsReconsent flips true.
func (s *sqliteStore) PutManifest(ctx context.Context, m ManifestRecord) error {
	inj, err := json.Marshal(m.Injections)
	if err != nil {
		return err
	}
	tools, err := json.Marshal(m.Tools)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO manifests (server,version,digest,tier,entrypoint,display_name,category,description,allowed_hosts,injections,tools,manifest_hash,consented_hash)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'')
		 ON CONFLICT(server) DO UPDATE SET
		   version=excluded.version, digest=excluded.digest, tier=excluded.tier,
		   entrypoint=excluded.entrypoint,
		   display_name=excluded.display_name, category=excluded.category,
		   description=excluded.description, allowed_hosts=excluded.allowed_hosts,
		   injections=excluded.injections, tools=excluded.tools,
		   manifest_hash=excluded.manifest_hash`,
		m.Server, m.Version, m.Digest, m.Tier, m.Entrypoint,
		m.DisplayName, m.Category, m.Description,
		strings.Join(m.AllowedHosts, "\n"), string(inj), string(tools), m.ManifestHash)
	return err
}

func (s *sqliteStore) GetManifest(ctx context.Context, server string) (ManifestRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT server,version,digest,tier,entrypoint,display_name,category,description,allowed_hosts,injections,tools,manifest_hash,consented_hash
		 FROM manifests WHERE server=?`, server)
	m, err := scanManifest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ManifestRecord{}, ErrManifestNotFound
	}
	return m, err
}

func (s *sqliteStore) ListManifests(ctx context.Context) ([]ManifestRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT server,version,digest,tier,entrypoint,display_name,category,description,allowed_hosts,injections,tools,manifest_hash,consented_hash
		 FROM manifests ORDER BY server`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManifestRecord
	for rows.Next() {
		m, err := scanManifest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RecordConsent marks hash as the user-accepted manifest hash for server.
// The frontend calls this from its consent flow.
func (s *sqliteStore) RecordConsent(ctx context.Context, server, hash string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE manifests SET consented_hash=? WHERE server=?`, hash, server)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrManifestNotFound
	}
	return nil
}

func (s *sqliteStore) DeleteManifest(ctx context.Context, server string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM manifests WHERE server=?`, server)
	return err
}

// DeleteServer removes a servers row (registry uninstall path; installer-owned).
func (s *sqliteStore) DeleteServer(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM servers WHERE name=?`, name)
	return err
}

type scanner interface{ Scan(dest ...any) error }

func scanManifest(row scanner) (ManifestRecord, error) {
	var m ManifestRecord
	var hosts, inj, tools string
	if err := row.Scan(&m.Server, &m.Version, &m.Digest, &m.Tier, &m.Entrypoint,
		&m.DisplayName, &m.Category, &m.Description,
		&hosts, &inj, &tools, &m.ManifestHash, &m.ConsentedHash); err != nil {
		return ManifestRecord{}, err
	}
	if hosts != "" {
		m.AllowedHosts = strings.Split(hosts, "\n")
	}
	if err := json.Unmarshal([]byte(inj), &m.Injections); err != nil {
		return ManifestRecord{}, err
	}
	if err := json.Unmarshal([]byte(tools), &m.Tools); err != nil {
		return ManifestRecord{}, err
	}
	return m, nil
}
