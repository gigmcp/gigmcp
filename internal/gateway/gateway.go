// Package gateway aggregates backend MCP servers behind one MCP server,
// re-exposing every backend tool as <backend>_<tool> (DESIGN.md decision #11;
// profiles arrive in a later plan — the skeleton has one implicit profile).
package gateway

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Backend is a connected upstream MCP server.
type Backend struct {
	Name    string // namespace prefix for its tools
	Session *mcp.ClientSession
}

// New builds the aggregating MCP server over the given backends.
func New(ctx context.Context, version string, backends []Backend) (*mcp.Server, error) {
	gw := mcp.NewServer(&mcp.Implementation{Name: "gigmcp", Version: version}, nil)
	for _, b := range backends {
		sess := b.Session
		tools, err := sess.ListTools(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("list tools for backend %q: %w", b.Name, err)
		}
		for _, tool := range tools.Tools {
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
