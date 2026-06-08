package gateway_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/store"
)

// TestProfileHostSurfacesArchMismatch verifies the spawn-time architecture
// error reaches the HTTP client verbatim (the dashboard's error channel) rather
// than the opaque "backend unavailable".
func TestProfileHostSurfacesArchMismatch(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "arch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "hackernews", "/data/servers/hackernews/server"); err != nil {
		t.Fatal(err)
	}
	_, tok := seedProfile(t, st, "news", []string{"hackernews"})

	spawn := func(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
		return nil, &gateway.ArchMismatchError{Server: srv.Name, ImageArch: "amd64", HostArch: "arm64"}
	}
	host := &gateway.ProfileHost{Store: st, Spawn: spawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest("POST", ts.URL+"/mcp/p/news", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	got := string(body)

	if strings.Contains(got, "backend unavailable") {
		t.Fatalf("arch error must replace generic message, got %q", got)
	}
	if !strings.Contains(got, "image architecture amd64 is incompatible with host arm64") {
		t.Fatalf("response body missing arch detail: %q", got)
	}
}
