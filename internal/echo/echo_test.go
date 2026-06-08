package echo_test

import (
	"context"
	"testing"

	"github.com/gigmcp/gigmcp/internal/echo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestEchoTool(t *testing.T) {
	ctx := context.Background()
	clientTr, serverTr := mcp.NewInMemoryTransports()

	srv := echo.NewServer()
	serverSess, err := srv.Connect(ctx, serverTr, nil) // server first, then client
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer serverSess.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	sess, err := client.Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer sess.Close()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "hi"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("want 1 content item, got %d", len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("want TextContent, got %T", res.Content[0])
	}
	if text.Text != "echo: hi" {
		t.Errorf("got %q, want %q", text.Text, "echo: hi")
	}
}
