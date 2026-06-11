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
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	seedMultiToolApp(t, st, "slack")

	// Disable "admin" directly in the store.
	if err := st.SetToolEnabled(context.Background(), "slack", "admin", false); err != nil {
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

func TestToggleToolAdminOnly(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, user := seedUserSession(t, st, "alice@x", "user")
	_, admin := seedUserSession(t, st, "admin@x", "admin")
	seedMultiToolApp(t, st, "slack")

	// Non-admin cannot toggle.
	code, _ := doJSON(t, ts, user, "PUT", "/api/apps/slack/tools/admin", `{"enabled":false}`)
	if code != http.StatusForbidden {
		t.Fatalf("non-admin toggle: want 403, got %d", code)
	}

	// Admin disables the tool.
	code, _ = doJSON(t, ts, admin, "PUT", "/api/apps/slack/tools/admin", `{"enabled":false}`)
	if code != http.StatusNoContent {
		t.Fatalf("admin disable: want 204, got %d", code)
	}
	disabled, _ := st.ListDisabledTools(context.Background(), "slack")
	if len(disabled) != 1 || disabled[0] != "admin" {
		t.Fatalf("store not updated: %v", disabled)
	}

	// Admin re-enables the tool.
	code, _ = doJSON(t, ts, admin, "PUT", "/api/apps/slack/tools/admin", `{"enabled":true}`)
	if code != http.StatusNoContent {
		t.Fatalf("admin enable: want 204, got %d", code)
	}
	disabled, _ = st.ListDisabledTools(context.Background(), "slack")
	if len(disabled) != 0 {
		t.Fatalf("store not cleared: %v", disabled)
	}
}

func TestToggleToolUnknownAppAndTool(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, admin := seedUserSession(t, st, "admin@x", "admin")
	seedMultiToolApp(t, st, "slack")

	// Unknown app → 404.
	code, _ := doJSON(t, ts, admin, "PUT", "/api/apps/ghost/tools/admin", `{"enabled":false}`)
	if code != http.StatusNotFound {
		t.Fatalf("unknown app: want 404, got %d", code)
	}

	// Unknown tool (not in the manifest) → 400.
	code, _ = doJSON(t, ts, admin, "PUT", "/api/apps/slack/tools/bogus", `{"enabled":false}`)
	if code != http.StatusBadRequest {
		t.Fatalf("unknown tool: want 400, got %d", code)
	}
}
