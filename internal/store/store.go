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
	Binary string // absolute host path to the server's binary
}

// Store persists gateway state.
type Store interface {
	// EnsureServer upserts a server by name and returns the stored record.
	EnsureServer(ctx context.Context, name, binary string) (Server, error)
	// ListServers returns all registered servers ordered by name.
	ListServers(ctx context.Context) ([]Server, error)
	// PutCredential upserts a credential by (server, tenant).
	PutCredential(ctx context.Context, c Credential) error
	// GetCredential fetches a credential by (server, tenant); returns error if not found.
	GetCredential(ctx context.Context, server, tenant string) (Credential, error)
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
	// AppendAudit inserts an audit row (zero TS = now).
	AppendAudit(ctx context.Context, e AuditEvent) error
	// ListAudit pages audit rows newest-first (keyset: beforeID, 0 = newest; userID 0 = all).
	ListAudit(ctx context.Context, beforeID int64, limit int, userID int64) ([]AuditEvent, error)
	Close() error
}
