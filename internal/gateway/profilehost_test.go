package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// seedProfile creates a user + profile bundling the given servers and
// returns the profile and its plaintext token.
func seedProfile(t *testing.T, st store.Store, slug string, servers []string) (store.Profile, string) {
	t.Helper()
	ctx := context.Background()
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "owner-"+slug, slug+"@x", slug, "user")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := auth.NewProfileToken()
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, slug, slug, u.ID, auth.HashToken(tok))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileServers(ctx, p.ID, servers); err != nil {
		t.Fatal(err)
	}
	return p, tok
}

// echoSpawner is a fake SpawnFunc backed by in-memory echo servers. It
// records every (server, tenant) spawn and every cleanup invocation.
type echoSpawner struct {
	t        *testing.T
	spawns   []string // "name:tenant"
	cleanups int
}

func (e *echoSpawner) spawn(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
	e.spawns = append(e.spawns, srv.Name+":"+tenant)
	sess := connectEchoBackend(e.t, ctx)
	return &gateway.EgressBackend{Session: sess, Cleanup: func() { e.cleanups++ }}, nil
}

func connectProfileClient(t *testing.T, ctx context.Context, baseURL, slug, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "profile-test", Version: "0"}, nil)
	sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   baseURL + "/mcp/p/" + slug,
		HTTPClient: &http.Client{Transport: &bearerTransport{token: token}},
	}, nil)
	if err != nil {
		t.Fatalf("connect profile %s: %v", slug, err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func TestProfileHostAuthAndRouting(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}
	p, tok := seedProfile(t, st, "alpha", []string{"echo"})

	sp := &echoSpawner{t: t}
	host := &gateway.ProfileHost{Store: st, Spawn: sp.spawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	// Register server close via t.Cleanup (not defer) so that session
	// cleanups registered later run first (t.Cleanup is LIFO), preventing
	// httptest.Server.Close from blocking on open SSE connections.
	t.Cleanup(ts.Close)

	// Missing / wrong token and wrong slug → 401, and nothing is spawned.
	for _, c := range []struct{ path, token string }{
		{"/mcp/p/alpha", ""},
		{"/mcp/p/alpha", "gig_wrongtoken"},
		{"/mcp/p/nosuch", tok},
	} {
		req, _ := http.NewRequest("POST", ts.URL+c.path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%+v: want 401, got %d", c, resp.StatusCode)
		}
	}
	if len(sp.spawns) != 0 {
		t.Fatalf("unauthorized requests must not spawn: %v", sp.spawns)
	}

	// Valid token: lazy spawn with Tenant = profile ID, aggregator serves echo_echo.
	sess := connectProfileClient(t, ctx, ts.URL, "alpha", tok)
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo_echo" {
		t.Fatalf("tools: %+v", tools.Tools)
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo_echo", Arguments: map[string]any{"message": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if text, ok := res.Content[0].(*mcp.TextContent); !ok || text.Text != "echo: hi" {
		t.Fatalf("call: %+v", res.Content[0])
	}
	wantTenant := strconv.FormatInt(p.ID, 10)
	if len(sp.spawns) != 1 || sp.spawns[0] != "echo:"+wantTenant {
		t.Fatalf("spawns: %v (want echo:%s)", sp.spawns, wantTenant)
	}

	// Second session reuses the runtime — no new spawn.
	sess2 := connectProfileClient(t, ctx, ts.URL, "alpha", tok)
	if _, err := sess2.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(sp.spawns) != 1 {
		t.Fatalf("runtime not reused: %v", sp.spawns)
	}
}

func TestProfileHostInvalidateTearsDownAndRespawns(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}
	p, tok := seedProfile(t, st, "beta", []string{"echo"})

	sp := &echoSpawner{t: t}
	host := &gateway.ProfileHost{Store: st, Spawn: sp.spawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	// Register server close via t.Cleanup (not defer) so that session
	// cleanups registered later run first (t.Cleanup is LIFO).
	t.Cleanup(ts.Close)

	sess := connectProfileClient(t, ctx, ts.URL, "beta", tok)
	if _, err := sess.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(sp.spawns) != 1 || sp.cleanups != 0 {
		t.Fatalf("initial: spawns=%v cleanups=%d", sp.spawns, sp.cleanups)
	}

	host.Invalidate(p.ID)
	if sp.cleanups != 1 {
		t.Fatalf("invalidate must run cleanups: %d", sp.cleanups)
	}

	// Next request lazily respawns.
	sess2 := connectProfileClient(t, ctx, ts.URL, "beta", tok)
	if _, err := sess2.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(sp.spawns) != 2 {
		t.Fatalf("no respawn after invalidate: %v", sp.spawns)
	}
}
