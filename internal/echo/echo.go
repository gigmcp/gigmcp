// Package echo provides a trivial MCP server used by the walking skeleton
// to prove the gateway→sandbox→backend path end to end.
package echo

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Args are the input arguments of the echo tool.
type Args struct {
	Message string `json:"message" jsonschema:"the text to echo back"`
}

// NewServer returns an MCP server exposing a single "echo" tool.
func NewServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "echo-mcp", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echoes a message back"},
		func(ctx context.Context, req *mcp.CallToolRequest, in Args) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "echo: " + in.Message}},
			}, nil, nil
		})
	return s
}
