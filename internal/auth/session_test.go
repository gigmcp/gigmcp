package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

func openStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func seedSession(t *testing.T, st store.Store, sub, role string) (store.User, *http.Cookie) {
	t.Helper()
	ctx := context.Background()
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", sub, sub+"@x", sub, role)
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

func TestTokenHelpers(t *testing.T) {
	s1, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := auth.NewSessionToken()
	if s1 == s2 || len(s1) != 43 { // 32 bytes base64url unpadded
		t.Fatalf("session tokens: %q %q", s1, s2)
	}
	p, err := auth.NewProfileToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, "gig_") || len(p) != 4+43 {
		t.Fatalf("profile token: %q", p)
	}
	h := auth.HashToken("x")
	if len(h) != 64 || h != auth.HashToken("x") || h == auth.HashToken("y") {
		t.Fatalf("hash: %q", h)
	}
}

func TestSessionMiddlewareAuthenticates(t *testing.T) {
	st := openStore(t)
	u, cookie := seedSession(t, st, "alice", "user")

	var gotReal, gotEff store.User
	var gotImp bool
	h := auth.SessionMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReal, _ = auth.RealUser(r.Context())
		gotEff, _ = auth.EffectiveUser(r.Context())
		gotImp = auth.IsImpersonating(r.Context())
		if _, ok := auth.SessionTokenHash(r.Context()); !ok {
			t.Error("no session hash in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	// No cookie → 401 with the error envelope.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/me", nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("no-cookie: %d %s", rec.Code, rec.Body)
	}

	// Garbage cookie → 401.
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "garbage"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("garbage cookie: %d", rec.Code)
	}

	// Valid cookie → 200, real == effective, not impersonating.
	req = httptest.NewRequest("GET", "/api/me", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotReal.ID != u.ID || gotEff.ID != u.ID || gotImp {
		t.Fatalf("valid: %d real=%+v eff=%+v imp=%v", rec.Code, gotReal, gotEff, gotImp)
	}
}

func TestSessionMiddlewareImpersonation(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	admin, cookie := seedSession(t, st, "admin", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "target", "t@x", "Target", "user")
	if err := st.SetImpersonation(ctx, auth.HashToken(cookie.Value), target.ID, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	var gotReal, gotEff store.User
	h := auth.SessionMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReal, _ = auth.RealUser(r.Context())
		gotEff, _ = auth.EffectiveUser(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// GET: effective = target, real = admin.
	req := httptest.NewRequest("GET", "/api/profiles", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotReal.ID != admin.ID || gotEff.ID != target.ID {
		t.Fatalf("impersonated GET: %d real=%+v eff=%+v", rec.Code, gotReal, gotEff)
	}

	// Any non-GET mutation while impersonating → 403...
	req = httptest.NewRequest("POST", "/api/profiles", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("impersonated POST must be 403, got %d", rec.Code)
	}

	// ...EXCEPT DELETE /api/admin/impersonate (stop view-as).
	req = httptest.NewRequest("DELETE", "/api/admin/impersonate", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stop-impersonation must pass through, got %d", rec.Code)
	}

	// Expired impersonation behaves as not impersonating.
	if err := st.SetImpersonation(ctx, auth.HashToken(cookie.Value), target.ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "/api/profiles", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if gotEff.ID != admin.ID {
		t.Fatalf("expired impersonation must fall back to real user, got eff=%+v", gotEff)
	}
}

func TestRequireAdmin(t *testing.T) {
	st := openStore(t)
	_, userCookie := seedSession(t, st, "plain", "user")
	_, adminCookie := seedSession(t, st, "boss", "admin")

	h := auth.SessionMiddleware(st, auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.AddCookie(userCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("user must be 403, got %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/api/users", nil)
	req.AddCookie(adminCookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin must pass, got %d", rec.Code)
	}
}
