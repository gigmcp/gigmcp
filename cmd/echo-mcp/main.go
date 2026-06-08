// Command echo-mcp runs the echo MCP server over stdio. The gateway executes
// this binary inside a bubblewrap sandbox.
package main

import (
	"context"
	"log"

	"github.com/gigmcp/gigmcp/internal/echo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := echo.NewServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
