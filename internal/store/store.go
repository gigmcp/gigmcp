// Package store persists gateway state. The interface is deliberately
// driver-agnostic: DESIGN.md decision #14 requires SQLite and Postgres
// backends with no driver-specific features in core.
package store

import (
	"context"
	"time"
)

// Server is a registered MCP server the gateway should run.
type Server struct {
	ID     int64
	Name   string // unique; used as the tool namespace prefix
	Binary string // absolute host path to the server's entrypoint binary
	// BundleDir is set for toolpack multi-file servers: the host staging
	// directory holding the entrypoint plus its inert sidecars
	// (manifest.yaml, toolspec.yaml). The gateway bind-mounts this directory
	// read-only at the in-image bundle path (path.Dir(entrypoint)) instead of
	// mounting Binary alone. Empty for single-file (go-static) servers, which
	// keep the original single-binary mount — so existing rows behave exactly
	// as before.
	BundleDir string
}

// Store persists gateway state.
type Store interface {
	// EnsureServer upserts a single-file server by name and returns the stored
	// record. bundle_dir is cleared (single-binary mount).
	EnsureServer(ctx context.Context, name, binary string) (Server, error)
	// EnsureServerBundle upserts a toolpack multi-file server by name: entrypoint
	// is the in-bundle binary path, bundleDir is the host staging directory that
	// the gateway bind-mounts read-only at the in-image bundle path.
	EnsureServerBundle(ctx context.Context, name, entrypoint, bundleDir string) (Server, error)
	// ListServers returns all registered servers ordered by name.
	ListServers(ctx context.Context) ([]Server, error)
	// PutCredential upserts a credential by (server, tenant).
	PutCredential(ctx context.Context, c Credential) error
	// GetCredential fetches a credential by (server, tenant); returns error if not found.
	GetCredential(ctx context.Context, server, tenant string) (Credential, error)
	// ListCredentialsByTenant lists a tenant's credentials, metadata only (no ciphertext).
	ListCredentialsByTenant(ctx context.Context, tenant string) ([]Credential, error)
	// DeleteCredential removes a credential by (server, tenant); idempotent.
	// Returns (true, nil) when a row was deleted, (false, nil) when noop.
	DeleteCredential(ctx context.Context, server, tenant string) (bool, error)
	// PutManifest upserts a manifest record by server (consent preserved).
	PutManifest(ctx context.Context, m ManifestRecord) error
	// GetManifest fetches the manifest for a server; ErrManifestNotFound if none.
	GetManifest(ctx context.Context, server string) (ManifestRecord, error)
	// ListManifests returns all manifest records ordered by server.
	ListManifests(ctx context.Context) ([]ManifestRecord, error)
	// RecordConsent stores the manifest hash the user accepted for server.
	RecordConsent(ctx context.Context, server, hash string) error
	// DeleteManifest removes a server's manifest record.
	DeleteManifest(ctx context.Context, server string) error
	// DeleteServer removes a server row (registry uninstall).
	DeleteServer(ctx context.Context, name string) error
	// UpsertUserByOIDC JIT-provisions or refreshes a user by (issuer, subject).
	UpsertUserByOIDC(ctx context.Context, issuer, subject, email, displayName, role string) (User, error)
	// GetUser fetches a user by id; ErrUserNotFound if missing.
	GetUser(ctx context.Context, id int64) (User, error)
	// ListUsers returns all users ordered by id.
	ListUsers(ctx context.Context) ([]User, error)
	// CreateSession inserts an opaque session row keyed by token hash.
	CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error
	// GetSession fetches a live session; expired rows are deleted on read (ErrSessionNotFound).
	GetSession(ctx context.Context, tokenHash string) (Session, error)
	// DeleteSession removes a session.
	DeleteSession(ctx context.Context, tokenHash string) error
	// SetImpersonation stamps view-as state onto a session.
	SetImpersonation(ctx context.Context, tokenHash string, targetUserID int64, expiresAt time.Time) error
	// ClearImpersonation removes view-as state from a session.
	ClearImpersonation(ctx context.Context, tokenHash string) error
	// CreateProfile inserts a profile (slug UNIQUE).
	CreateProfile(ctx context.Context, slug, name string, userID int64, tokenHash string) (Profile, error)
	// GetProfileByID fetches a profile; ErrProfileNotFound if missing.
	GetProfileByID(ctx context.Context, id int64) (Profile, error)
	// GetProfileBySlugAndTokenHash is the MCP endpoint auth lookup.
	GetProfileBySlugAndTokenHash(ctx context.Context, slug, tokenHash string) (Profile, error)
	// ListProfiles returns profiles owned by userID (0 = all).
	ListProfiles(ctx context.Context, userID int64) ([]Profile, error)
	// UpdateProfileName renames a profile.
	UpdateProfileName(ctx context.Context, id int64, name string) error
	// SetProfileToken replaces the stored token hash (rotation).
	SetProfileToken(ctx context.Context, id int64, tokenHash string) error
	// DeleteProfile removes a profile, cascading profile_servers.
	DeleteProfile(ctx context.Context, id int64) error
	// SetProfileServers replaces the profile's server bundle (one tx).
	SetProfileServers(ctx context.Context, id int64, names []string) error
	// GetProfileServers returns the profile's bundled server names.
	GetProfileServers(ctx context.Context, id int64) ([]string, error)
	// RemoveServerFromProfiles removes a server from all profile_servers rows,
	// returning the affected profile IDs (for runtime invalidation).
	RemoveServerFromProfiles(ctx context.Context, serverName string) ([]int64, error)
	// AppendAudit inserts an audit row (zero TS = now).
	AppendAudit(ctx context.Context, e AuditEvent) error
	// ListAudit pages audit rows newest-first (keyset: beforeID, 0 = newest; userID 0 = all).
	ListAudit(ctx context.Context, beforeID int64, limit int, userID int64) ([]AuditEvent, error)
	Close() error
}
