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

// (a) HEAD while impersonating → 200 (safe method, not blocked).
func TestImpersonationHEADAllowed(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	_, cookie := seedSession(t, st, "admin2", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "t2", "t2@x", "T2", "user")
	if err := st.SetImpersonation(ctx, auth.HashToken(cookie.Value), target.ID, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	h := auth.SessionMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodHead, "/api/profiles", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD while impersonating must be 200, got %d", rec.Code)
	}
}

// (b) DELETE with trailing slash is NOT the stop-impersonation carve-out;
// DELETE /api/profiles/1 must also be blocked while impersonating.
func TestImpersonationMutationGuardPaths(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	_, cookie := seedSession(t, st, "admin3", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "t3", "t3@x", "T3", "user")
	if err := st.SetImpersonation(ctx, auth.HashToken(cookie.Value), target.ID, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	h := auth.SessionMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Trailing slash — not the exact carve-out path.
	req := httptest.NewRequest(http.MethodDelete, "/api/admin/impersonate/", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE /api/admin/impersonate/ (trailing slash) must be 403, got %d", rec.Code)
	}

	// A different DELETE path must also be blocked.
	req = httptest.NewRequest(http.MethodDelete, "/api/profiles/1", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE /api/profiles/1 while impersonating must be 403, got %d", rec.Code)
	}
}

// (c) Admin impersonating a user still passes RequireAdmin on GET.
func TestRequireAdminPassesDuringImpersonation(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	_, cookie := seedSession(t, st, "admin4", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "t4", "t4@x", "T4", "user")
	if err := st.SetImpersonation(ctx, auth.HashToken(cookie.Value), target.ID, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	var gotReal store.User
	h := auth.SessionMiddleware(st, auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReal, _ = auth.RealUser(r.Context())
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/api/admin/users", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin impersonating must still pass RequireAdmin on GET, got %d", rec.Code)
	}
	if gotReal.Role != "admin" {
		t.Fatalf("real user must be admin, got role=%q", gotReal.Role)
	}
}

// (d) Target user deleted while impersonating → request proceeds as real user,
// IsImpersonating == false.
func TestImpersonationTargetDeletedFallsBack(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	_, cookie := seedSession(t, st, "admin5", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "gone", "gone@x", "Gone", "user")
	if err := st.SetImpersonation(ctx, auth.HashToken(cookie.Value), target.ID, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	// Simulate the target user being deleted by wrapping the store with a fake
	// that returns ErrUserNotFound for that specific user ID.
	fakeStore := &deletedTargetStore{Store: st, deletedID: target.ID}

	var gotReal, gotEff store.User
	var gotImp bool
	h := auth.SessionMiddleware(fakeStore, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReal, _ = auth.RealUser(r.Context())
		gotEff, _ = auth.EffectiveUser(r.Context())
		gotImp = auth.IsImpersonating(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deleted target must not block request, got %d", rec.Code)
	}
	if gotImp {
		t.Fatal("IsImpersonating must be false when target is gone")
	}
	if gotReal.ID != gotEff.ID {
		t.Fatalf("effective must equal real when target gone: real=%d eff=%d", gotReal.ID, gotEff.ID)
	}
}

// (e) Expired impersonation: assert 200, IsImpersonating false, AND POST is allowed.
func TestExpiredImpersonationAllowsMutations(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	admin, cookie := seedSession(t, st, "admin6", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "t6", "t6@x", "T6", "user")
	// Set an already-expired impersonation.
	if err := st.SetImpersonation(ctx, auth.HashToken(cookie.Value), target.ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	var gotImp bool
	var gotEff store.User
	h := auth.SessionMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotImp = auth.IsImpersonating(r.Context())
		gotEff, _ = auth.EffectiveUser(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// GET → 200, not impersonating.
	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expired impersonation GET must be 200, got %d", rec.Code)
	}
	if gotImp {
		t.Fatal("expired impersonation must set IsImpersonating=false")
	}
	if gotEff.ID != admin.ID {
		t.Fatalf("expired impersonation must fall back to real user, got eff.ID=%d", gotEff.ID)
	}

	// POST → 200 (no longer blocked by impersonation guard).
	req = httptest.NewRequest(http.MethodPost, "/api/profiles", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expired impersonation POST must be 200, got %d", rec.Code)
	}
}

// (f) RequireAdmin with no session context (not wrapped by SessionMiddleware) → 403.
func TestRequireAdminNoContext(t *testing.T) {
	h := auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/admin/users", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no-context RequireAdmin must be 403, got %d", rec.Code)
	}
}

// (g) DB error on GetSession returns 500 not 401.
func TestSessionMiddlewareDBError500(t *testing.T) {
	st := openStore(t)
	_, cookie := seedSession(t, st, "erralice", "user")

	// Close the store to provoke DB errors.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	h := auth.SessionMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// A closed DB returns an error that is not ErrSessionNotFound → must be 500.
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("DB error must yield 500, got %d body=%s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "internal") {
		t.Fatalf("500 body must contain 'internal', got: %s", rec.Body)
	}
	if rec.Result().Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("auth error must set Cache-Control: no-store")
	}
}

// deletedTargetStore wraps a real Store but returns ErrUserNotFound for a
// specific user ID (simulating a deleted impersonation target).
type deletedTargetStore struct {
	store.Store
	deletedID int64
}

func (d *deletedTargetStore) GetUser(ctx context.Context, id int64) (store.User, error) {
	if id == d.deletedID {
		return store.User{}, store.ErrUserNotFound
	}
	return d.Store.GetUser(ctx, id)
}

// Verify deletedTargetStore satisfies store.Store (compile-time check).
var _ store.Store = (*deletedTargetStore)(nil)
