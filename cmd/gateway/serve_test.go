package main

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	gw "github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

func TestBuildMuxRouting(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	kek := make([]byte, 32)
	rand.Read(kek)
	v, _ := vault.New(kek)

	profiles := &gw.ProfileHost{
		Store: st, Version: "test",
		Spawn: func(ctx context.Context, srv store.Server, tenant string) (*gw.EgressBackend, error) {
			t.Fatal("no spawn expected in routing test")
			return nil, nil
		},
	}
	legacy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // sentinel for "legacy handler reached"
	})

	// OIDC unconfigured: authn == nil → /api is NOT mounted.
	// Pass nil for Installer (no registry configured in this routing-only test).
	mux := buildMux(st, v, nil, nil, profiles, legacy)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	if resp, _ := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader("{}")); resp.StatusCode != http.StatusTeapot {
		t.Fatalf("/mcp must reach legacy handler: %d", resp.StatusCode)
	}
	// "/" catch-all must also reach the legacy handler (backward compat for README-documented URL).
	if resp, _ := http.Get(ts.URL + "/"); resp.StatusCode != http.StatusTeapot {
		t.Fatalf("/ catch-all must reach legacy handler: %d", resp.StatusCode)
	}
	if resp, _ := http.Post(ts.URL+"/mcp/p/some-slug", "application/json", strings.NewReader("{}")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/mcp/p/{slug} without token must 401: %d", resp.StatusCode)
	}
	if resp, _ := http.Get(ts.URL + "/api/me"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/api disabled without OIDC must 404: %d", resp.StatusCode)
	}
}
