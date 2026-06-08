package gateway_test

import (
	"context"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/echo"
	"github.com/gigmcp/gigmcp/internal/gateway"
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

	c := mcp.NewClient(&mcp.Implementation{Name: "gigmcp-gw", Version: "test"}, nil)
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

func TestNewRejectsBadBackendNames(t *testing.T) {
	ctx := context.Background()
	_, err := gateway.New(ctx, "test", []gateway.Backend{{Name: "bad_name"}})
	if err == nil || !strings.Contains(err.Error(), "_") {
		t.Fatalf("underscore name must be rejected, got %v", err)
	}
	_, err = gateway.New(ctx, "test", []gateway.Backend{{Name: "dup"}, {Name: "dup"}})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate names must be rejected, got %v", err)
	}
}

// connectTwoToolBackend wires an in-memory MCP server that exposes two tools
// ("echo" and "loud") and returns a client session to it.
func connectTwoToolBackend(t *testing.T, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	clientTr, serverTr := mcp.NewInMemoryTransports()

	type Args struct {
		Message string `json:"message"`
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "two-tool-backend", Version: "test"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "echo", Description: "echoes"},
		func(_ context.Context, _ *mcp.CallToolRequest, in Args) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo: " + in.Message}}}, nil, nil
		})
	mcp.AddTool(srv, &mcp.Tool{Name: "loud", Description: "louds"},
		func(_ context.Context, _ *mcp.CallToolRequest, in Args) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "LOUD: " + in.Message}}}, nil, nil
		})

	serverSess, err := srv.Connect(ctx, serverTr, nil)
	if err != nil {
		t.Fatalf("two-tool backend server connect: %v", err)
	}
	t.Cleanup(func() { serverSess.Close() })

	c := mcp.NewClient(&mcp.Implementation{Name: "gigmcp-gw", Version: "test"}, nil)
	sess, err := c.Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatalf("two-tool backend client connect: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

// connectGatewayClient connects a test client to the given gateway server and
// returns the client session (closing it via t.Cleanup).
func connectGatewayClient(t *testing.T, ctx context.Context, gw *mcp.Server) *mcp.ClientSession {
	t.Helper()
	clientTr, serverTr := mcp.NewInMemoryTransports()
	gwSess, err := gw.Connect(ctx, serverTr, nil)
	if err != nil {
		t.Fatalf("gateway connect: %v", err)
	}
	t.Cleanup(func() { gwSess.Close() })
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	sess, err := c.Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func TestExposeFilter(t *testing.T) {
	ctx := context.Background()

	t.Run("only_exposed_tool_appears", func(t *testing.T) {
		sess := connectTwoToolBackend(t, ctx)
		gw, err := gateway.New(ctx, "test", []gateway.Backend{{
			Name:    "b",
			Session: sess,
			Expose:  map[string]bool{"echo": true},
		}})
		if err != nil {
			t.Fatalf("gateway.New: %v", err)
		}
		client := connectGatewayClient(t, ctx, gw)
		tools, err := client.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		names := make(map[string]bool, len(tools.Tools))
		for _, tool := range tools.Tools {
			names[tool.Name] = true
		}
		if !names["b_echo"] {
			t.Errorf("expected b_echo to be present, got %v", tools.Tools)
		}
		if names["b_loud"] {
			t.Errorf("expected b_loud to be absent, got %v", tools.Tools)
		}
	})

	t.Run("nil_expose_exposes_all", func(t *testing.T) {
		sess := connectTwoToolBackend(t, ctx)
		gw, err := gateway.New(ctx, "test", []gateway.Backend{{
			Name:    "b",
			Session: sess,
			Expose:  nil,
		}})
		if err != nil {
			t.Fatalf("gateway.New: %v", err)
		}
		client := connectGatewayClient(t, ctx, gw)
		tools, err := client.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("list tools: %v", err)
		}
		names := make(map[string]bool, len(tools.Tools))
		for _, tool := range tools.Tools {
			names[tool.Name] = true
		}
		if !names["b_echo"] {
			t.Errorf("expected b_echo to be present, got %v", tools.Tools)
		}
		if !names["b_loud"] {
			t.Errorf("expected b_loud to be present, got %v", tools.Tools)
		}
	})
}
