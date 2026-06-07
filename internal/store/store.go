// Package store persists gateway state. The interface is deliberately
// driver-agnostic: DESIGN.md decision #14 requires SQLite and Postgres
// backends with no driver-specific features in core.
package store

import "context"

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
	Close() error
}
