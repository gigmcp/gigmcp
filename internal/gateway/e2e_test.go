package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/sandbox"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildEchoBinary compiles cmd/echo-mcp as a static binary for the sandbox.
func buildEchoBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "echo-mcp")
	cmd := exec.Command("go", "build", "-o", out, "github.com/gigmcp/gigmcp/cmd/echo-mcp")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build echo-mcp: %v\n%s", err, b)
	}
	return out
}

// bearerTransport sets a bearer Authorization header on every request. Shared
// by the profile-endpoint tests (profilehost_test.go, profile_e2e_test.go),
// which authenticate with per-profile tokens.
type bearerTransport struct{ token string }

func (b *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

// TestEndToEnd exercises the sandbox → aggregator → streamable-HTTP pipeline
// directly (no auth layer: in production the aggregator is only reachable
// through the ProfileHost, which enforces per-profile tokens — see
// profilehost_test.go).
func TestEndToEnd(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("sandbox requires Linux with bwrap installed — run `make test`")
	}
	ctx := context.Background()
	bin := buildEchoBinary(t)

	// Gateway side: sandboxed echo backend over stdio.
	cmd := sandbox.Command(sandbox.Spec{
		Exec:   "/app/server",
		Mounts: []sandbox.Mount{{Src: bin, Dst: "/app/server"}},
	})
	backendClient := mcp.NewClient(&mcp.Implementation{Name: "gigmcp-gw", Version: "e2e"}, nil)
	backendSess, err := backendClient.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect sandboxed backend: %v", err)
	}
	defer backendSess.Close()

	gw, err := gateway.New(ctx, "e2e", []gateway.Backend{{Name: "echo", Session: backendSess}})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return gw }, nil)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Real MCP client over streamable HTTP.
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "0.0.0"}, nil)
	sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL}, nil)
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
		Arguments: map[string]any{"message": "through the sandbox"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "echo: through the sandbox" {
		t.Fatalf("got %+v, want %q", res.Content[0], "echo: through the sandbox")
	}
}
