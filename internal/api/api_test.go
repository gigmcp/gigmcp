package api_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/api"
	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// fakeInvalidator records ProfileHost invalidations.
type fakeInvalidator struct{ ids []int64 }

func (f *fakeInvalidator) Invalidate(id int64) { f.ids = append(f.ids, id) }

// newTestAPI builds an api.Server over a temp SQLite store + random-KEK vault
// (Auth stays nil — the /api/auth/* mounts are skipped; session rows are
// seeded directly).
func newTestAPI(t *testing.T) (*api.Server, *httptest.Server, store.Store, *fakeInvalidator) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	inv := &fakeInvalidator{}
	fi := &fakeInstaller{st: st, installErr: errors.New("fake installer: not wired")}
	srv := &api.Server{Store: st, Vault: v, Installer: fi, Profiles: inv}
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return srv, ts, st, inv
}

// seedUserSession provisions a user + live session, returning the cookie.
func seedUserSession(t *testing.T, st store.Store, email, role string) (store.User, *http.Cookie) {
	t.Helper()
	ctx := context.Background()
	u, err := st.UpsertUserByOIDC(ctx, "https://idp.test", "sub-"+email, email, email, role)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, auth.HashToken(tok), u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return u, &http.Cookie{Name: auth.SessionCookie, Value: tok}
}

// doResp sends a request with optional cookie + JSON body, returning the full response.
// Callers are responsible for closing resp.Body.
func doResp(t *testing.T, ts *httptest.Server, cookie *http.Cookie, method, path, body string) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// doJSON sends a request with optional cookie + JSON body, returning status + body.
func doJSON(t *testing.T, ts *httptest.Server, cookie *http.Cookie, method, path, body string) (int, []byte) {
	t.Helper()
	resp := doResp(t, ts, cookie, method, path, body)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

func TestMeRequiresSession(t *testing.T) {
	_, ts, _, _ := newTestAPI(t)
	code, body := doJSON(t, ts, nil, "GET", "/api/me", "")
	if code != http.StatusUnauthorized || !strings.Contains(string(body), `"error"`) {
		t.Fatalf("unauthed /api/me: %d %s", code, body)
	}
}

func TestMeReturnsEffectiveUser(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	u, cookie := seedUserSession(t, st, "alice@x", "user")

	code, body := doJSON(t, ts, cookie, "GET", "/api/me", "")
	if code != http.StatusOK {
		t.Fatalf("/api/me: %d %s", code, body)
	}
	var got struct {
		User struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
		Impersonating bool `json:"impersonating"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.User.ID != u.ID || got.User.Email != "alice@x" || got.User.Role != "user" || got.Impersonating {
		t.Fatalf("me: %+v", got)
	}
}

// TestMeCacheControl verifies Cache-Control: no-store is set on JSON responses (I1).
func TestMeCacheControl(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	resp := doResp(t, ts, cookie, "GET", "/api/me", "")
	defer resp.Body.Close()
	io.ReadAll(resp.Body) //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control: want no-store, got %q", got)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type: want application/json, got %q", ct)
	}
}

// TestMeNoLeak verifies sensitive OIDC/session data is not leaked in /api/me (M3).
func TestMeNoLeak(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	_, body := doJSON(t, ts, cookie, "GET", "/api/me", "")
	bodyStr := string(body)

	// The OIDC issuer injected in seedUserSession must not appear.
	if strings.Contains(bodyStr, "issuer") {
		t.Fatalf("/api/me leaks 'issuer': %s", bodyStr)
	}
	// The OIDC subject prefix must not appear.
	if strings.Contains(bodyStr, "sub-") {
		t.Fatalf("/api/me leaks OIDC subject: %s", bodyStr)
	}
}

// TestAuthedMux404JSON verifies that an unknown authenticated route returns a
// JSON envelope (not bare text/plain) with status 404 (I2).
func TestAuthedMux404JSON(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	resp := doResp(t, ts, cookie, "GET", "/api/nonexistent", "")
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type: want application/json, got %q", ct)
	}
	if !strings.Contains(string(b), `"not_found"`) {
		t.Fatalf("404 body missing not_found code: %s", b)
	}
}

// TestAuthedMux405JSON verifies that a wrong-method request against a known
// authenticated route returns a JSON envelope (not bare text/plain) with status
// 405 and a non-empty Allow header (I2).
func TestAuthedMux405JSON(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	resp := doResp(t, ts, cookie, "POST", "/api/me", "")
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", resp.StatusCode, b)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type: want application/json, got %q", ct)
	}
	if allow := resp.Header.Get("Allow"); allow == "" {
		t.Fatal("Allow header missing on 405")
	}
	if !strings.Contains(string(b), `"method_not_allowed"`) {
		t.Fatalf("405 body missing method_not_allowed code: %s", b)
	}
}

func TestMeShowsImpersonation(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	admin, cookie := seedUserSession(t, st, "admin@x", "admin")
	target, _ := seedUserSession(t, st, "target@x", "user")
	if err := st.SetImpersonation(context.Background(), auth.HashToken(cookie.Value), target.ID, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/me", "")
	if code != http.StatusOK {
		t.Fatalf("/api/me: %d %s", code, body)
	}
	var got struct {
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
		Impersonating bool `json:"impersonating"`
		RealUser      *struct {
			ID int64 `json:"id"`
		} `json:"real_user"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Impersonating || got.User.ID != target.ID || got.RealUser == nil || got.RealUser.ID != admin.ID {
		t.Fatalf("impersonated me: %+v", got)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func mkEvent(uid *int64, host string) store.AuditEvent {
	return store.AuditEvent{Kind: "egress", UserID: uid, Server: "github", Host: host, Decision: "resolved"}
}
