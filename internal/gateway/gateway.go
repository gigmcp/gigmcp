// Package gateway aggregates backend MCP servers behind one MCP server,
// re-exposing every backend tool as <backend>_<tool> (DESIGN.md decision #11;
// profiles arrive in a later plan — the skeleton has one implicit profile).
package gateway

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Backend is a connected upstream MCP server.
type Backend struct {
	Name    string // namespace prefix for its tools; must not contain "_"
	Session *mcp.ClientSession
	// Expose filters which tools are re-exposed (manifest default subset,
	// DESIGN #11). nil = expose all (legacy servers without a manifest).
	Expose map[string]bool
}

// New builds the aggregating MCP server over the given backends.
func New(ctx context.Context, version string, backends []Backend) (*mcp.Server, error) {
	// Validate all names first: a bad name must fail fast, before any
	// session I/O (and independently of session health).
	seen := map[string]bool{}
	for _, b := range backends {
		if strings.Contains(b.Name, "_") {
			return nil, fmt.Errorf("backend name %q must not contain '_' (it is the tool-namespace separator)", b.Name)
		}
		if seen[b.Name] {
			return nil, fmt.Errorf("duplicate backend name %q", b.Name)
		}
		seen[b.Name] = true
	}
	gw := mcp.NewServer(&mcp.Implementation{Name: "gigmcp", Version: version}, nil)
	for _, b := range backends {
		sess := b.Session
		tools, err := sess.ListTools(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("list tools for backend %q: %w", b.Name, err)
		}
		for _, tool := range tools.Tools {
			if b.Expose != nil && !b.Expose[tool.Name] {
				continue // non-default tool: connected but not exposed (meta-tools path later)
			}
			upstream := tool.Name // captured per-iteration for the closure
			proxied := *tool
			proxied.Name = b.Name + "_" + upstream
			gw.AddTool(&proxied, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				// Raw pass-through: arguments forwarded verbatim; the
				// backend performs its own validation.
				return sess.CallTool(ctx, &mcp.CallToolParams{
					Name:      upstream,
					Arguments: req.Params.Arguments,
				})
			})
		}
	}
	return gw, nil
}
