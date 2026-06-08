package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/api"
	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// newConnAPI builds a test API server with a real OAuthBroker wired in.
// It re-constructs the server and httptest.Server so that the broker's
// redirect URL points at the running test server.
func newConnAPI(t *testing.T) (*api.Server, *httptest.Server, store.Store) {
	t.Helper()
	srv, ts, st, _ := newTestAPI(t)
	broker, err := auth.NewOAuthBroker(st, srv.Vault,
		ts.URL+"/api/connections/oauth/callback", ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	srv.Broker = broker
	return srv, ts, st
}

func TestListConnections(t *testing.T) {
	_, ts, st := newConnAPI(t)
	user, cookie := seedUserSession(t, st, "connuser@x", "user")

	_ = st.PutConnectedAccount(context.Background(), store.ConnectedAccount{
		UserID: user.ID, Vendor: "google",
		EncryptedRefreshToken: []byte("x"), EncryptedAccessToken: []byte("y"),
		GrantedScopes: []string{"email"},
	})

	code, body := doJSON(t, ts, cookie, "GET", "/api/connections", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "google") || !strings.Contains(bodyStr, "email") {
		t.Fatalf("connection not listed: %s", bodyStr)
	}
	// Never leak token ciphertext.
	if strings.Contains(bodyStr, `"x"`) || strings.Contains(bodyStr, `"y"`) {
		t.Fatalf("token ciphertext leaked: %s", bodyStr)
	}
}

func TestOAuthStartComputesScopeUnionFromManifest(t *testing.T) {
	_, ts, st := newConnAPI(t)
	_, cookie := seedUserSession(t, st, "startuser@x", "user")

	// An installed oauth2 app for vendor google requiring scope "drive".
	_ = st.PutManifest(context.Background(), store.ManifestRecord{
		Server: "gdrive", Version: "1.0.0", Digest: "sha256:x", Tier: "sealed",
		Entrypoint: "/app/server", AllowedHosts: []string{"www.googleapis.com"},
		Injections: []store.Injection{{ID: "oauth", Type: "oauth2", Provider: "google",
			Scopes: []string{"drive"}, Header: "Authorization", Format: "Bearer {token}", Placeholder: "PH"}},
		ManifestHash: "h",
	})
	_ = st.PutAuthConfig(context.Background(), store.AuthConfig{
		Vendor: "google", AuthorizeURL: "https://example.test/authorize",
		TokenURL: "https://example.test/token", ClientID: "cid",
		EncryptedClientSecret: []byte{}, DefaultScopes: []string{"openid"}, Mode: "byo", PKCE: true,
	})

	// Use a non-redirecting client so we capture the 302 without following it.
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", ts.URL+"/api/connections/oauth/start?vendor=google&server=gdrive", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "drive") || !strings.Contains(loc, "openid") {
		t.Fatalf("authorize URL missing scope union: %s", loc)
	}
}

// TestOAuthStartScopeUnionKeysOffVendor verifies that an app whose credential
// declares Vendor != Provider (e.g. gmail → vendor "google") still contributes
// its manifest-declared scopes to the union. Regression guard: keying off
// Provider alone would return an empty scope set for these multi-app vendors.
func TestOAuthStartScopeUnionKeysOffVendor(t *testing.T) {
	_, ts, st := newConnAPI(t)
	_, cookie := seedUserSession(t, st, "vendoruser@x", "user")

	// Installed oauth2 app whose canonical vendor "google" differs from its
	// per-connector provider "gmail"; requires the gmail.readonly scope.
	_ = st.PutManifest(context.Background(), store.ManifestRecord{
		Server: "gmail", Version: "1.0.0", Digest: "sha256:x", Tier: "sealed",
		Entrypoint: "/app/server", AllowedHosts: []string{"www.googleapis.com"},
		Injections: []store.Injection{{ID: "oauth", Type: "oauth2", Provider: "gmail", Vendor: "google",
			Scopes: []string{"https://www.googleapis.com/auth/gmail.readonly"}, Header: "Authorization", Format: "Bearer {token}", Placeholder: "PH"}},
		ManifestHash: "h",
	})
	_ = st.PutAuthConfig(context.Background(), store.AuthConfig{
		Vendor: "google", AuthorizeURL: "https://example.test/authorize",
		TokenURL: "https://example.test/token", ClientID: "cid",
		EncryptedClientSecret: []byte{}, DefaultScopes: []string{"openid"}, Mode: "byo", PKCE: true,
	})

	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", ts.URL+"/api/connections/oauth/start?vendor=google&server=gmail", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := noRedirectClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	// The app's gmail scope must be present in the authorize URL even though
	// the request vendor ("google") != the credential provider ("gmail").
	if !strings.Contains(loc, "gmail.readonly") {
		t.Fatalf("authorize URL missing per-app scope for vendor!=provider app: %s", loc)
	}
}

func TestDisconnect(t *testing.T) {
	_, ts, st := newConnAPI(t)
	user, cookie := seedUserSession(t, st, "discuser@x", "user")

	_ = st.PutConnectedAccount(context.Background(), store.ConnectedAccount{
		UserID: user.ID, Vendor: "slack",
		EncryptedRefreshToken: []byte("r"), EncryptedAccessToken: []byte("a"),
		GrantedScopes: []string{"channels:read"},
	})

	code, body := doJSON(t, ts, cookie, "DELETE", "/api/connections/slack", "")
	if code != http.StatusNoContent {
		t.Fatalf("disconnect: %d %s", code, body)
	}
	// Verify deleted.
	_, err := st.GetConnectedAccount(context.Background(), user.ID, "slack")
	if err == nil {
		t.Fatal("account should be deleted after disconnect")
	}
}

func TestListConnectionsNoTokenLeak(t *testing.T) {
	_, ts, st := newConnAPI(t)
	user, cookie := seedUserSession(t, st, "leakuser@x", "user")

	_ = st.PutConnectedAccount(context.Background(), store.ConnectedAccount{
		UserID: user.ID, Vendor: "github",
		EncryptedRefreshToken: []byte("secret_refresh"), EncryptedAccessToken: []byte("secret_access"),
		GrantedScopes: []string{"repo"},
	})

	code, body := doJSON(t, ts, cookie, "GET", "/api/connections", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	// Ciphertext must never appear in the response.
	if strings.Contains(string(body), "secret_refresh") || strings.Contains(string(body), "secret_access") {
		t.Fatalf("token ciphertext leaked in list response: %s", body)
	}
}
