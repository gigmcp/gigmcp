package api_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
	srv := &api.Server{Store: st, Vault: v, Profiles: inv}
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

// doJSON sends a request with optional cookie + JSON body, returning status + body.
func doJSON(t *testing.T, ts *httptest.Server, cookie *http.Cookie, method, path, body string) (int, []byte) {
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
