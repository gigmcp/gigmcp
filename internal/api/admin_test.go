package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/api"
	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// fakeInstaller is a small fake implementing registry.Installer for tests.
// List delegates to the store; Install/Uninstall return a configurable error.
type fakeInstaller struct {
	st         store.Store
	installErr error
}

func (f *fakeInstaller) Install(ctx context.Context, ref string) (store.Server, error) {
	if f.installErr != nil {
		return store.Server{}, f.installErr
	}
	return store.Server{Name: ref}, nil
}
func (f *fakeInstaller) Uninstall(ctx context.Context, name string) error {
	return f.installErr
}
func (f *fakeInstaller) List(ctx context.Context) ([]store.Server, error) {
	return f.st.ListServers(ctx)
}

func TestServersListViaInstaller(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/servers", "")
	if code != http.StatusOK {
		t.Fatalf("list servers: %d %s", code, body)
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 1 || list[0].Name != "echo" {
		t.Fatalf("installer list: %v %s", err, body)
	}
}

func TestInstallEndpointsAdminOnly(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, user := seedUserSession(t, st, "alice@x", "user")
	_, admin := seedUserSession(t, st, "admin@x", "admin")

	// Non-admin cannot install.
	if code, _ := doJSON(t, ts, user, "POST", "/api/servers/install", `{"ref":"github@1.0.0"}`); code != http.StatusForbidden {
		t.Fatalf("non-admin install: %d", code)
	}
	// Admin with a failing installer gets 502 (the fake returns an error).
	if code, _ := doJSON(t, ts, admin, "POST", "/api/servers/install", `{"ref":"github@1.0.0"}`); code != http.StatusBadGateway {
		t.Fatalf("failing installer must 502: %d", code)
	}
	if code, _ := doJSON(t, ts, admin, "DELETE", "/api/servers/github", ""); code != http.StatusBadGateway {
		t.Fatalf("failing uninstall must 502: %d", code)
	}
}

// TestUninstallFailingInstaller502 verifies that a failing Installer.Uninstall → 502.
func TestUninstallFailingInstaller502(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")

	code, body := doJSON(t, ts, adminCookie, "DELETE", "/api/servers/echo", "")
	if code != http.StatusBadGateway {
		t.Fatalf("failing installer must 502: %d", code)
	}
	// The client must get a generic message, never the raw installer error.
	if !strings.Contains(string(body), "uninstall failed") {
		t.Fatalf("expected generic message, got: %s", body)
	}
	if strings.Contains(string(body), "not wired") {
		t.Fatalf("raw installer error leaked to client: %s", body)
	}
}

// TestUninstallSuccessHTTP exercises the full HTTP uninstall happy path with a
// success-mode installer: seeds a profile bundling server "fetch", sends
// DELETE /api/servers/fetch as admin, expects 204, verifies profile_servers row
// is gone, the profile ID is in the invalidator, and the audit row is present.
func TestUninstallSuccessHTTP(t *testing.T) {
	ctx := context.Background()
	_, _, st, _ := newTestAPI(t)
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")
	user, _ := seedUserSession(t, st, "alice@x", "user")

	if _, err := st.EnsureServer(ctx, "fetch", "/bin/fetch-mcp"); err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, "prof", "Prof", user.ID, "tok-fetch")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileServers(ctx, p.ID, []string{"fetch"}); err != nil {
		t.Fatal(err)
	}

	// Build a fresh API server with a success-mode installer over the same store.
	inv2 := &fakeInvalidator{}
	successInst := &fakeInstaller{st: st, installErr: nil}
	srv2 := &api.Server{Store: st, Installer: successInst, Profiles: inv2}
	ts2 := httptest.NewServer(srv2.Routes())
	t.Cleanup(ts2.Close)

	code, _ := doJSON(t, ts2, adminCookie, "DELETE", "/api/servers/fetch", "")
	if code != http.StatusNoContent {
		t.Fatalf("success uninstall must 204: %d", code)
	}

	// profile_servers row must be gone.
	srvs, _ := st.GetProfileServers(ctx, p.ID)
	if len(srvs) != 0 {
		t.Fatalf("profile_servers not cleared: %v", srvs)
	}

	// Profile ID must have been invalidated.
	if len(inv2.ids) != 1 || inv2.ids[0] != p.ID {
		t.Fatalf("expected invalidation of profile %d, got %v", p.ID, inv2.ids)
	}

	// Audit row must exist.
	events, _ := st.ListAudit(ctx, 0, 50, 0)
	found := false
	for _, e := range events {
		if e.Decision == "server_uninstall" {
			found = true
		}
	}
	if !found {
		t.Fatalf("server_uninstall audit row missing")
	}
}

// TestUninstallCascadesPerUserState verifies that an admin DELETE
// /api/servers/{name} sweeps all per-user state for the connector: the user's
// install, their disabled tools, and their profile's bundling of the server.
func TestUninstallCascadesPerUserState(t *testing.T) {
	ctx := context.Background()
	_, _, st, _ := newTestAPI(t)
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")
	user, _ := seedUserSession(t, st, "alice@x", "user")

	if _, err := st.EnsureServer(ctx, "fetch", "/bin/fetch-mcp"); err != nil {
		t.Fatal(err)
	}
	if err := st.InstallForUser(ctx, user.ID, "fetch"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserToolEnabled(ctx, user.ID, "fetch", "fetch_do", false); err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, "prof", "Prof", user.ID, "tok-fetch")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileServers(ctx, p.ID, []string{"fetch"}); err != nil {
		t.Fatal(err)
	}

	// Build a fresh API server with a success-mode installer over the same store.
	inv2 := &fakeInvalidator{}
	successInst := &fakeInstaller{st: st, installErr: nil}
	srv2 := &api.Server{Store: st, Installer: successInst, Profiles: inv2}
	ts2 := httptest.NewServer(srv2.Routes())
	t.Cleanup(ts2.Close)

	code, _ := doJSON(t, ts2, adminCookie, "DELETE", "/api/servers/fetch", "")
	if code != http.StatusNoContent {
		t.Fatalf("success uninstall must 204: %d", code)
	}

	// The user's install must be gone.
	if installed, err := st.IsUserInstalled(ctx, user.ID, "fetch"); err != nil || installed {
		t.Fatalf("user install not swept: installed=%v err=%v", installed, err)
	}
	// The user's disabled tools for the server must be gone.
	if disabled, err := st.ListUserDisabledTools(ctx, user.ID, "fetch"); err != nil || len(disabled) != 0 {
		t.Fatalf("user disabled tools not swept: %v err=%v", disabled, err)
	}
	// The profile must no longer bundle the server.
	if srvs, _ := st.GetProfileServers(ctx, p.ID); len(srvs) != 0 {
		t.Fatalf("profile_servers not cleared: %v", srvs)
	}
}

func TestUsersListAdminOnly(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, user := seedUserSession(t, st, "alice@x", "user")
	_, admin := seedUserSession(t, st, "admin@x", "admin")

	if code, _ := doJSON(t, ts, user, "GET", "/api/users", ""); code != http.StatusForbidden {
		t.Fatalf("non-admin users list: %d", code)
	}
	code, body := doJSON(t, ts, admin, "GET", "/api/users", "")
	if code != http.StatusOK {
		t.Fatalf("admin users list: %d %s", code, body)
	}
	var list []struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 2 {
		t.Fatalf("users: %v %s", err, body)
	}
}

func TestImpersonationLifecycle(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	target, _ := seedUserSession(t, st, "target@x", "user")
	admin, adminCookie := seedUserSession(t, st, "admin@x", "admin")
	_ = admin

	// ttl clamp: 999 minutes requested, ≤ 60 stored.
	code, body := doJSON(t, ts, adminCookie, "POST", "/api/admin/impersonate",
		`{"user_id":`+itoa(target.ID)+`,"ttl_minutes":999}`)
	if code != http.StatusNoContent {
		t.Fatalf("start impersonation: %d %s", code, body)
	}
	sess, err := st.GetSession(ctx, auth.HashToken(adminCookie.Value))
	if err != nil || sess.ImpersonatingUserID == nil || *sess.ImpersonatingUserID != target.ID {
		t.Fatalf("session not stamped: %v %+v", err, sess)
	}
	if sess.ImpersonationExpiresAt.After(time.Now().Add(61 * time.Minute)) {
		t.Fatalf("ttl not clamped to 60m: %v", sess.ImpersonationExpiresAt)
	}

	// While impersonating: /api/me shows both identities; mutations 403.
	code, body = doJSON(t, ts, adminCookie, "GET", "/api/me", "")
	if code != http.StatusOK {
		t.Fatalf("me: %d", code)
	}
	var me struct {
		Impersonating bool `json:"impersonating"`
	}
	json.Unmarshal(body, &me)
	if !me.Impersonating {
		t.Fatalf("me while impersonating: %s", body)
	}
	if code, _ := doJSON(t, ts, adminCookie, "POST", "/api/profiles", `{"name":"X","slug":"xx"}`); code != http.StatusForbidden {
		t.Fatalf("mutation while impersonating must 403: %d", code)
	}

	// Stop — must be reachable via DELETE /api/admin/impersonate while impersonating.
	if code, _ := doJSON(t, ts, adminCookie, "DELETE", "/api/admin/impersonate", ""); code != http.StatusNoContent {
		t.Fatalf("stop impersonation: %d", code)
	}
	sess, _ = st.GetSession(ctx, auth.HashToken(adminCookie.Value))
	if sess.ImpersonatingUserID != nil {
		t.Fatalf("not cleared: %+v", sess)
	}

	// Both directions audited, attributed to the target (their audit view).
	events, _ := st.ListAudit(ctx, 0, 50, target.ID)
	decisions := map[string]bool{}
	for _, e := range events {
		decisions[e.Decision] = true
	}
	if !decisions["impersonate_start"] || !decisions["impersonate_stop"] {
		t.Fatalf("impersonation audit events missing: %v", decisions)
	}
}

func TestImpersonationStopRouteExact(t *testing.T) {
	// The auth middleware's carve-out is an exact match on "/api/admin/impersonate".
	// Verify that the stop endpoint is exactly that path (no trailing slash).
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	target, _ := seedUserSession(t, st, "target@x", "user")
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")

	// Start impersonation.
	code, _ := doJSON(t, ts, adminCookie, "POST", "/api/admin/impersonate",
		`{"user_id":`+itoa(target.ID)+`,"ttl_minutes":10}`)
	if code != http.StatusNoContent {
		t.Fatalf("start: %d", code)
	}

	// Stop via the exact path — must succeed (not 403 from mutation guard).
	code, _ = doJSON(t, ts, adminCookie, "DELETE", "/api/admin/impersonate", "")
	if code != http.StatusNoContent {
		t.Fatalf("stop via exact path: %d", code)
	}

	// Verify cleared.
	sess, _ := st.GetSession(ctx, auth.HashToken(adminCookie.Value))
	if sess.ImpersonatingUserID != nil {
		t.Fatalf("impersonation not cleared")
	}
}

func TestAuditReadScoping(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	alice, aliceCookie := seedUserSession(t, st, "alice@x", "user")
	bob, _ := seedUserSession(t, st, "bob@x", "user")
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")

	aid, bid := alice.ID, bob.ID
	st.AppendAudit(ctx, mkEvent(&aid, "a1"))
	st.AppendAudit(ctx, mkEvent(&bid, "b1"))
	st.AppendAudit(ctx, mkEvent(&aid, "a2"))

	// Non-admin is forced to own user_id regardless of query params.
	code, body := doJSON(t, ts, aliceCookie, "GET", "/api/audit?user_id="+itoa(bob.ID), "")
	if code != http.StatusOK {
		t.Fatalf("audit: %d %s", code, body)
	}
	var page struct {
		Events []struct {
			UserID *int64 `json:"user_id"`
			Host   string `json:"host"`
		} `json:"events"`
		NextBefore int64 `json:"next_before"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("alice events: %s", body)
	}
	for _, e := range page.Events {
		if e.UserID == nil || *e.UserID != alice.ID {
			t.Fatalf("foreign audit row leaked: %+v", e)
		}
	}

	// Admin sees all, can filter, and pages by keyset.
	code, body = doJSON(t, ts, adminCookie, "GET", "/api/audit?limit=2", "")
	if code != http.StatusOK {
		t.Fatalf("admin audit: %d", code)
	}
	json.Unmarshal(body, &page)
	if len(page.Events) != 2 || page.NextBefore == 0 {
		t.Fatalf("admin page 1: %s", body)
	}
	_, body = doJSON(t, ts, adminCookie, "GET", "/api/audit?limit=2&before="+itoa(page.NextBefore), "")
	json.Unmarshal(body, &page)
	if len(page.Events) != 1 || page.Events[0].Host != "a1" {
		t.Fatalf("admin page 2: %s", body)
	}
}

func TestAuditImpersonatingSeesTargetEvents(t *testing.T) {
	// While impersonating, admin sees the target's audit events (EffectiveUser filter).
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	target, _ := seedUserSession(t, st, "target@x", "user")
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")

	tid := target.ID
	st.AppendAudit(ctx, mkEvent(&tid, "target-event"))

	// Start impersonation.
	code, _ := doJSON(t, ts, adminCookie, "POST", "/api/admin/impersonate",
		`{"user_id":`+itoa(target.ID)+`,"ttl_minutes":10}`)
	if code != http.StatusNoContent {
		t.Fatalf("start: %d", code)
	}

	// While impersonating, GET /api/audit is a read (allowed) and should
	// key off EffectiveUser (target).
	code, body := doJSON(t, ts, adminCookie, "GET", "/api/audit", "")
	if code != http.StatusOK {
		t.Fatalf("audit while impersonating: %d %s", code, body)
	}
	var page struct {
		Events []struct {
			Host string `json:"host"`
		} `json:"events"`
	}
	json.Unmarshal(body, &page)
	// Should include the target's event (plus the impersonate_start/stop audit rows).
	found := false
	for _, e := range page.Events {
		if e.Host == "target-event" {
			found = true
		}
	}
	if !found {
		t.Fatalf("impersonating admin did not see target's event: %s", body)
	}

	// Stop impersonation (exempt from mutation guard).
	doJSON(t, ts, adminCookie, "DELETE", "/api/admin/impersonate", "")
}

// TestNilInstallerReturns501 verifies that install/uninstall routes return 501
// when the Server has no Installer wired (nil-guard in handlers).
func TestNilInstallerReturns501(t *testing.T) {
	_, _, st, _ := newTestAPI(t)
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")

	// Build a server with Installer explicitly nil.
	srv := &api.Server{Store: st, Installer: nil}
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)

	if code, _ := doJSON(t, ts, adminCookie, "POST", "/api/servers/install", `{"ref":"x"}`); code != http.StatusNotImplemented {
		t.Fatalf("nil installer install: want 501, got %d", code)
	}
	if code, _ := doJSON(t, ts, adminCookie, "DELETE", "/api/servers/x", ""); code != http.StatusNotImplemented {
		t.Fatalf("nil installer uninstall: want 501, got %d", code)
	}
}

// TestImpersonateNonexistentUser verifies that targeting a user ID that does
// not exist returns 404.
func TestImpersonateNonexistentUser(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")

	code, _ := doJSON(t, ts, adminCookie, "POST", "/api/admin/impersonate",
		`{"user_id":99999,"ttl_minutes":10}`)
	if code != http.StatusNotFound {
		t.Fatalf("nonexistent target: want 404, got %d", code)
	}
}

// TestImpersonateAdminIsAllowed verifies that an admin can impersonate another
// admin user (view-as is permitted for any user including admins — DESIGN #20).
func TestImpersonateAdminIsAllowed(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")
	otherAdmin, _ := seedUserSession(t, st, "otheradmin@x", "admin")

	code, _ := doJSON(t, ts, adminCookie, "POST", "/api/admin/impersonate",
		`{"user_id":`+itoa(otherAdmin.ID)+`,"ttl_minutes":10}`)
	if code != http.StatusNoContent {
		t.Fatalf("impersonating another admin: want 204, got %d", code)
	}
	sess, err := st.GetSession(ctx, auth.HashToken(adminCookie.Value))
	if err != nil || sess.ImpersonatingUserID == nil || *sess.ImpersonatingUserID != otherAdmin.ID {
		t.Fatalf("session not stamped for admin target: %v %+v", err, sess)
	}
}

// Verify that fakeInstaller satisfies registry.Installer (compile-time check).
var _ interface {
	Install(ctx context.Context, ref string) (store.Server, error)
	Uninstall(ctx context.Context, name string) error
	List(ctx context.Context) ([]store.Server, error)
} = (*fakeInstaller)(nil)
