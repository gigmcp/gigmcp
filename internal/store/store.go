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
	Close() error
}
