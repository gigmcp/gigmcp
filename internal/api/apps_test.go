package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func seedApp(t *testing.T, st store.Store, name, authType string, hosts []string) {
	t.Helper()
	ctx := context.Background()
	if _, err := st.EnsureServer(ctx, name, "/bin/"+name); err != nil {
		t.Fatal(err)
	}
	inj := []store.Injection{}
	if authType != "none" {
		inj = []store.Injection{{ID: "c", Type: authType, Provider: name,
			Header: "Authorization", Format: "Bearer {token}", Placeholder: "gigph-x"}}
	}
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: name, Version: "1.0.0", Digest: "sha256:d", Tier: "sealed",
		Entrypoint: "/bin/" + name, AllowedHosts: hosts, Injections: inj,
		Tools: []store.ToolEntry{{Name: name + "_do", Default: true}}, ManifestHash: "h",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestListApps(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	user, cookie := seedUserSession(t, st, "alice@x", "user")

	seedApp(t, st, "gmail", "oauth2", []string{"gmail.googleapis.com"})
	seedApp(t, st, "stripe", "api_key", []string{"api.stripe.com"})
	seedApp(t, st, "hackernews", "none", []string{"hacker-news.firebaseio.com"})

	// The user has an api_key credential for stripe → connected=true for stripe.
	if err := st.PutCredential(context.Background(), store.Credential{
		Server: "stripe", Tenant: store.UserTenant(user.ID), EncryptedKey: []byte("x"),
		InjectHeader: "Authorization", InjectFormat: "Bearer {token}", Placeholder: "p",
	}); err != nil {
		t.Fatal(err)
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/apps", "")
	if code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", code, body)
	}
	var resp struct {
		Apps []struct {
			Name      string `json:"name"`
			AuthType  string `json:"auth_type"`
			Connected bool   `json:"connected"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	if len(resp.Apps) != 3 {
		t.Fatalf("want 3 apps, got %d: %s", len(resp.Apps), body)
	}
	by := map[string]struct {
		auth      string
		connected bool
	}{}
	for _, a := range resp.Apps {
		by[a.Name] = struct {
			auth      string
			connected bool
		}{a.AuthType, a.Connected}
	}
	if by["gmail"].auth != "oauth2" {
		t.Fatalf("gmail auth: want oauth2, got %q", by["gmail"].auth)
	}
	if by["hackernews"].auth != "none" {
		t.Fatalf("hackernews auth: want none, got %q", by["hackernews"].auth)
	}
	if !by["stripe"].connected {
		t.Fatalf("stripe must be connected (user has a credential)")
	}
	if by["gmail"].connected {
		t.Fatalf("gmail must not be connected (no credential)")
	}
}

func TestListAppsBranding(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	ctx := context.Background()

	// 1. Manifest with branding → DisplayName/Category surfaced.
	if _, err := st.EnsureServer(ctx, "hackernews", "/bin/hackernews"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "hackernews", Version: "1.0.0", Digest: "sha256:d", Tier: "sealed",
		Entrypoint: "/bin/hackernews", DisplayName: "Hacker News", Category: "news",
		Tools: []store.ToolEntry{{Name: "hn_top", Default: true}}, ManifestHash: "h",
	}); err != nil {
		t.Fatal(err)
	}

	// 2. Manifest record with empty DisplayName → falls back to slug.
	if _, err := st.EnsureServer(ctx, "stripe", "/bin/stripe"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "stripe", Version: "1.0.0", Digest: "sha256:d", Tier: "sealed",
		Entrypoint: "/bin/stripe", DisplayName: "", Category: "",
		Tools: []store.ToolEntry{{Name: "stripe_do", Default: true}}, ManifestHash: "h",
	}); err != nil {
		t.Fatal(err)
	}

	// 3. Legacy server with NO manifest record → DisplayName == slug, Category == "".
	if _, err := st.EnsureServer(ctx, "legacy", "/bin/legacy"); err != nil {
		t.Fatal(err)
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/apps", "")
	if code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", code, body)
	}
	var resp struct {
		Apps []struct {
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
			Category    string `json:"category"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	by := map[string]struct {
		display  string
		category string
	}{}
	for _, a := range resp.Apps {
		by[a.Name] = struct {
			display  string
			category string
		}{a.DisplayName, a.Category}
	}
	if by["hackernews"].display != "Hacker News" || by["hackernews"].category != "news" {
		t.Fatalf("hackernews branding: want (Hacker News, news), got %+v", by["hackernews"])
	}
	if by["stripe"].display != "stripe" {
		t.Fatalf("stripe display: empty manifest DisplayName must fall back to slug, got %q", by["stripe"].display)
	}
	if by["stripe"].category != "" {
		t.Fatalf("stripe category: want empty, got %q", by["stripe"].category)
	}
	if by["legacy"].display != "legacy" {
		t.Fatalf("legacy display: no manifest must fall back to slug, got %q", by["legacy"].display)
	}
	if by["legacy"].category != "" {
		t.Fatalf("legacy category: want empty, got %q", by["legacy"].category)
	}
}

func TestGetAppDetailBranding(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	ctx := context.Background()

	// Manifest with full branding.
	if _, err := st.EnsureServer(ctx, "hackernews", "/bin/hackernews"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "hackernews", Version: "1.0.0", Digest: "sha256:d", Tier: "sealed",
		Entrypoint: "/bin/hackernews", DisplayName: "Hacker News", Category: "news",
		Description: "Read the front page of Hacker News.",
		Tools:       []store.ToolEntry{{Name: "hn_top", Default: true}}, ManifestHash: "h",
	}); err != nil {
		t.Fatal(err)
	}

	// Manifest with empty DisplayName but a Description → fallback + passthrough.
	if _, err := st.EnsureServer(ctx, "legacy", "/bin/legacy"); err != nil {
		t.Fatal(err)
	}
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "legacy", Version: "1.0.0", Digest: "sha256:d", Tier: "sealed",
		Entrypoint: "/bin/legacy", DisplayName: "", Category: "", Description: "",
		Tools: []store.ToolEntry{{Name: "legacy_do", Default: true}}, ManifestHash: "h",
	}); err != nil {
		t.Fatal(err)
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/apps/hackernews", "")
	if code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", code, body)
	}
	var d struct {
		DisplayName string `json:"display_name"`
		Category    string `json:"category"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	if d.DisplayName != "Hacker News" || d.Category != "news" ||
		d.Description != "Read the front page of Hacker News." {
		t.Fatalf("detail branding: %+v", d)
	}

	// Empty DisplayName falls back to slug; empty Category/Description pass through.
	code, body = doJSON(t, ts, cookie, "GET", "/api/apps/legacy", "")
	if code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", code, body)
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	if d.DisplayName != "legacy" {
		t.Fatalf("empty DisplayName must fall back to slug, got %q", d.DisplayName)
	}
	if d.Category != "" || d.Description != "" {
		t.Fatalf("empty category/description must pass through, got cat=%q desc=%q", d.Category, d.Description)
	}
}

func TestGetAppDetail(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	seedApp(t, st, "stripe", "api_key", []string{"api.stripe.com", "files.stripe.com"})

	code, body := doJSON(t, ts, cookie, "GET", "/api/apps/stripe", "")
	if code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", code, body)
	}
	var d struct {
		Name         string   `json:"name"`
		AuthType     string   `json:"auth_type"`
		Provider     string   `json:"provider"`
		Vendor       string   `json:"vendor"`
		AllowedHosts []string `json:"allowed_hosts"`
		Tools        []struct {
			Name string `json:"name"`
		} `json:"tools"`
		InjectHeader string `json:"inject_header"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	if d.Name != "stripe" || d.AuthType != "api_key" {
		t.Fatalf("detail header wrong: %+v", d)
	}
	// seedApp sets no vendor → the detail must fall back to provider.
	if d.Vendor != "stripe" || d.Vendor != d.Provider {
		t.Fatalf("vendor must fall back to provider: provider=%q vendor=%q", d.Provider, d.Vendor)
	}
	if len(d.AllowedHosts) != 2 {
		t.Fatalf("allowed_hosts: want 2, got %d", len(d.AllowedHosts))
	}
	if len(d.Tools) != 1 || d.Tools[0].Name != "stripe_do" {
		t.Fatalf("tools wrong: %+v", d.Tools)
	}
	if d.InjectHeader != "Authorization" {
		t.Fatalf("inject_header: want Authorization, got %q", d.InjectHeader)
	}
}

func TestGetAppDetailSurfacesVendor(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	ctx := context.Background()
	if _, err := st.EnsureServer(ctx, "gmail", "/bin/gmail"); err != nil {
		t.Fatal(err)
	}
	// Connector provider "gmail" but canonical vendor "google".
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "gmail", Version: "1.0.0", Digest: "sha256:d", Tier: "sealed",
		Entrypoint: "/bin/gmail", AllowedHosts: []string{"gmail.googleapis.com"},
		Injections: []store.Injection{{
			ID: "oauth", Type: "oauth2", Provider: "gmail", Vendor: "google",
			Header: "Authorization", Format: "Bearer {token}", Placeholder: "gigph-x",
		}},
		Tools: []store.ToolEntry{{Name: "send", Default: true}}, ManifestHash: "h",
	}); err != nil {
		t.Fatal(err)
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/apps/gmail", "")
	if code != http.StatusOK {
		t.Fatalf("status: want 200, got %d: %s", code, body)
	}
	var d struct {
		Provider string `json:"provider"`
		Vendor   string `json:"vendor"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, body)
	}
	if d.Provider != "gmail" || d.Vendor != "google" {
		t.Fatalf("want provider=gmail vendor=google, got provider=%q vendor=%q", d.Provider, d.Vendor)
	}
}

func TestGetAppDetailNotFound(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	code, body := doJSON(t, ts, cookie, "GET", "/api/apps/ghost", "")
	if code != http.StatusNotFound {
		t.Fatalf("want 404 for unknown app, got %d: %s", code, body)
	}
}
