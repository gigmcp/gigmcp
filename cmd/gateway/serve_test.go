package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/config"
	gw "github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// minimalFakeIssuer is an httptest OIDC provider serving only the discovery
// doc and JWKS endpoints — enough to bootstrap auth.NewAuthenticator.
type minimalFakeIssuer struct {
	srv *httptest.Server
}

func newMinimalFakeIssuer(t *testing.T) *minimalFakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &minimalFakeIssuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

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
	t.Run("OIDC disabled", func(t *testing.T) {
		// OIDC unconfigured: authn == nil → /api answers control_plane_disabled.
		// Pass nil for Installer and registry client (no registry configured
		// in this routing-only test). Pass nil broker (OAuth disabled in test).
		mux := buildMux(st, v, nil, nil, nil, nil, profiles)
		ts := httptest.NewServer(mux)
		defer ts.Close()

		// The legacy single-tenant "/mcp" path and the "/" catch-all are retired:
		// both must 404 (canonical client endpoint is /mcp/p/<slug>).
		if resp, _ := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader("{}")); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("/mcp is retired and must 404: %d", resp.StatusCode)
		}
		if resp, _ := http.Get(ts.URL + "/"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("/ has no handler and must 404: %d", resp.StatusCode)
		}
		if resp, _ := http.Post(ts.URL+"/mcp/p/some-slug", "application/json", strings.NewReader("{}")); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("/mcp/p/{slug} without token must 401: %d", resp.StatusCode)
		}
		resp, _ := http.Get(ts.URL + "/api/me")
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("/api disabled without OIDC must 404: %d", resp.StatusCode)
		}
		// Verify explanatory JSON body.
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("disabled-API body must be valid JSON: %v", err)
		}
		resp.Body.Close()
		if body.Error.Code != "control_plane_disabled" {
			t.Fatalf("disabled-API body code must be control_plane_disabled, got %q", body.Error.Code)
		}
	})

	t.Run("OIDC enabled", func(t *testing.T) {
		// Stand up a real *auth.Authenticator against a minimal fake OIDC issuer.
		// This validates that when authn != nil, /api/ is mounted (SessionMiddleware
		// responds 401 for unauthenticated requests) and profile routing is unaffected.
		iss := newMinimalFakeIssuer(t)
		cfg := config.Config{
			OIDCIssuer:      iss.srv.URL,
			OIDCClientID:    "gigmcp-client",
			OIDCRedirectURL: "http://localhost:8080/api/auth/callback",
			OIDCAdminRole:   "gigmcp-admin",
			SessionTTL:      time.Hour,
			PublicURL:       "http://localhost:8080",
		}
		authn, err := auth.NewAuthenticator(context.Background(), cfg, st)
		if err != nil {
			t.Fatalf("NewAuthenticator: %v", err)
		}

		mux := buildMux(st, v, authn, nil, nil, nil, profiles)
		ts := httptest.NewServer(mux)
		defer ts.Close()

		// /api/me with authn non-nil must return 401 JSON from SessionMiddleware
		// (not 404 from the disabled handler).
		resp, _ := http.Get(ts.URL + "/api/me")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("/api/me with OIDC enabled but no session must 401: %d", resp.StatusCode)
		}
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("/api/me must return JSON error body: %v", err)
		}
		resp.Body.Close()
		if body.Error.Code == "" {
			t.Fatal("/api/me 401 must include error.code field")
		}

		// /mcp (retired legacy path) must 404 regardless of OIDC state.
		if resp, _ := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader("{}")); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("/mcp is retired and must 404 when OIDC enabled: %d", resp.StatusCode)
		}

		// /mcp/p/x without a bearer token must 401 from ProfileHost.
		if resp, _ := http.Post(ts.URL+"/mcp/p/x", "application/json", strings.NewReader("{}")); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("/mcp/p/x without token must 401 when OIDC enabled: %d", resp.StatusCode)
		}
	})
}

// TestWriteTempCAPermissions verifies that writeTempCA produces a file readable
// by processes other than the owner (mode & 0044 != 0). This is a regression
// test for the 0600 → 0644 fix: the bwrap sandbox runs as uid 65534 and cannot
// read a root-owned 0600 file, which caused "permission denied" opening the CA
// cert and consequently "x509: failed to load system roots" on all HTTPS egress.
func TestWriteTempCAPermissions(t *testing.T) {
	pem := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n")
	path, err := writeTempCA(pem)
	if err != nil {
		t.Fatalf("writeTempCA: %v", err)
	}
	t.Cleanup(func() { os.Remove(path) })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat CA file: %v", err)
	}
	mode := info.Mode()
	if mode&0044 == 0 {
		t.Fatalf("CA file must be world-readable (mode & 0044 != 0) so sandbox uid 65534 can read it; got mode %04o", mode)
	}
}
