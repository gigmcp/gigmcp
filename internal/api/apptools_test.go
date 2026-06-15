package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

// seedMultiToolApp installs an app with two manifest tools.
func seedMultiToolApp(t *testing.T, st store.Store, name string) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.EnsureServer(ctx, name, "/bin/"+name); err != nil {
		t.Fatal(err)
	}
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: name, Version: "1.0.0", Digest: "sha256:d", Tier: "sealed",
		Entrypoint: "/bin/" + name,
		Tools: []store.ToolEntry{
			{Name: "send", Default: true},
			{Name: "admin", Default: false},
		},
		ManifestHash: "h",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestGetAppToolsEnabledByDefault(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	seedMultiToolApp(t, st, "slack")

	code, body := doJSON(t, ts, cookie, "GET", "/api/apps/slack", "")
	if code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", code, body)
	}
	var d struct {
		Tools []struct {
			Name    string `json:"name"`
			Default bool   `json:"default"`
			Enabled bool   `json:"enabled"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	if len(d.Tools) != 2 {
		t.Fatalf("want 2 tools, got %d: %s", len(d.Tools), body)
	}
	// Default-all-on: every tool enabled with no disabled rows, regardless of
	// the manifest's informational `default` flag.
	for _, tl := range d.Tools {
		if !tl.Enabled {
			t.Fatalf("tool %q must be enabled by default: %+v", tl.Name, tl)
		}
	}
}

func TestGetAppToolsReflectsDisabled(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	user, cookie := seedUserSession(t, st, "alice@x", "user")
	seedMultiToolApp(t, st, "slack")

	// Disable "admin" for this user — the detail endpoint reports per-user state.
	if err := st.SetUserToolEnabled(context.Background(), user.ID, "slack", "admin", false); err != nil {
		t.Fatal(err)
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/apps/slack", "")
	if code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", code, body)
	}
	var d struct {
		Tools []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	by := map[string]bool{}
	for _, tl := range d.Tools {
		by[tl.Name] = tl.Enabled
	}
	if !by["send"] {
		t.Fatalf("send must stay enabled")
	}
	if by["admin"] {
		t.Fatalf("admin must report enabled=false after disable")
	}
}

// TestToggleToolPerUser: tool on/off is per-user. A normal user who installed
// the app can disable/re-enable a tool for themselves; the change lands in that
// user's own disabled set and does not leak to other users.
func TestToggleToolPerUser(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	user, cookie := seedUserSession(t, st, "alice@x", "user")
	seedMultiToolApp(t, st, "slack")
	if err := st.InstallForUser(context.Background(), user.ID, "slack"); err != nil {
		t.Fatal(err)
	}

	// Normal (non-admin) installed user disables the tool for themselves.
	code, _ := doJSON(t, ts, cookie, "PUT", "/api/apps/slack/tools/admin", `{"enabled":false}`)
	if code != http.StatusNoContent {
		t.Fatalf("disable: want 204, got %d", code)
	}
	disabled, _ := st.ListUserDisabledTools(context.Background(), user.ID, "slack")
	if len(disabled) != 1 || disabled[0] != "admin" {
		t.Fatalf("user disabled set not updated: %v", disabled)
	}

	// Re-enable removes it.
	code, _ = doJSON(t, ts, cookie, "PUT", "/api/apps/slack/tools/admin", `{"enabled":true}`)
	if code != http.StatusNoContent {
		t.Fatalf("enable: want 204, got %d", code)
	}
	disabled, _ = st.ListUserDisabledTools(context.Background(), user.ID, "slack")
	if len(disabled) != 0 {
		t.Fatalf("user disabled set not cleared: %v", disabled)
	}
}

// TestToggleToolRequiresInstall: a user who hasn't installed the app gets 404.
func TestToggleToolRequiresInstall(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	seedMultiToolApp(t, st, "slack")

	code, _ := doJSON(t, ts, cookie, "PUT", "/api/apps/slack/tools/admin", `{"enabled":false}`)
	if code != http.StatusNotFound {
		t.Fatalf("not installed: want 404, got %d", code)
	}
}

// TestToggleToolIsolation: user A disabling a tool does not affect user B.
func TestToggleToolIsolation(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	a, cookieA := seedUserSession(t, st, "alice@x", "user")
	b, _ := seedUserSession(t, st, "bob@x", "user")
	seedMultiToolApp(t, st, "slack")
	ctx := context.Background()
	if err := st.InstallForUser(ctx, a.ID, "slack"); err != nil {
		t.Fatal(err)
	}
	if err := st.InstallForUser(ctx, b.ID, "slack"); err != nil {
		t.Fatal(err)
	}

	code, _ := doJSON(t, ts, cookieA, "PUT", "/api/apps/slack/tools/admin", `{"enabled":false}`)
	if code != http.StatusNoContent {
		t.Fatalf("A disable: want 204, got %d", code)
	}
	if d, _ := st.ListUserDisabledTools(ctx, a.ID, "slack"); len(d) != 1 {
		t.Fatalf("A disabled set: want 1, got %v", d)
	}
	if d, _ := st.ListUserDisabledTools(ctx, b.ID, "slack"); len(d) != 0 {
		t.Fatalf("B disabled set must be unaffected, got %v", d)
	}
}

func TestToggleToolUnknownAppAndTool(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	user, cookie := seedUserSession(t, st, "alice@x", "user")
	seedMultiToolApp(t, st, "slack")
	if err := st.InstallForUser(context.Background(), user.ID, "slack"); err != nil {
		t.Fatal(err)
	}

	// Unknown app → 404 (no install for it either).
	code, _ := doJSON(t, ts, cookie, "PUT", "/api/apps/ghost/tools/admin", `{"enabled":false}`)
	if code != http.StatusNotFound {
		t.Fatalf("unknown app: want 404, got %d", code)
	}

	// Unknown tool (not in the manifest) → 400.
	code, _ = doJSON(t, ts, cookie, "PUT", "/api/apps/slack/tools/bogus", `{"enabled":false}`)
	if code != http.StatusBadRequest {
		t.Fatalf("unknown tool: want 400, got %d", code)
	}
}
