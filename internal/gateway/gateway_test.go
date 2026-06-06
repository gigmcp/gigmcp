package gateway_test

import (
	"context"
	"testing"

	"github.com/gigemcp/gigemcp/internal/echo"
	"github.com/gigemcp/gigemcp/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectEchoBackend wires an in-memory echo server and returns a client
// session to it, as the gateway would hold for a sandboxed backend.
func connectEchoBackend(t *testing.T, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	clientTr, serverTr := mcp.NewInMemoryTransports()
	srv := echo.NewServer()
	serverSess, err := srv.Connect(ctx, serverTr, nil)
	if err != nil {
		t.Fatalf("backend server connect: %v", err)
	}
	t.Cleanup(func() { serverSess.Close() })

	c := mcp.NewClient(&mcp.Implementation{Name: "gigemcp-gw", Version: "test"}, nil)
	sess, err := c.Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatalf("backend client connect: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func TestAggregatorNamespacesAndProxies(t *testing.T) {
	ctx := context.Background()
	backend := connectEchoBackend(t, ctx)

	gw, err := gateway.New(ctx, "test", []gateway.Backend{{Name: "echo", Session: backend}})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	// Connect a client to the aggregating gateway itself.
	clientTr, serverTr := mcp.NewInMemoryTransports()
	gwSess, err := gw.Connect(ctx, serverTr, nil)
	if err != nil {
		t.Fatalf("gateway connect: %v", err)
	}
	defer gwSess.Close()
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	sess, err := c.Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer sess.Close()

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo_echo" {
		t.Fatalf("want exactly [echo_echo], got %+v", tools.Tools)
	}

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo_echo",
		Arguments: map[string]any{"message": "hi"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "echo: hi" {
		t.Fatalf("got %+v, want text %q", res.Content[0], "echo: hi")
	}
}
