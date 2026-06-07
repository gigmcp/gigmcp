package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type profileResp struct {
	ID       int64    `json:"id"`
	Slug     string   `json:"slug"`
	Name     string   `json:"name"`
	UserID   int64    `json:"user_id"`
	Endpoint string   `json:"endpoint"`
	Servers  []string `json:"servers"`
	Token    string   `json:"token"`
}

func TestProfileCreateReturnsTokenOnce(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	code, body := doJSON(t, ts, cookie, "POST", "/api/profiles", `{"name":"Main","slug":"main"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created profileResp
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, "gig_") || created.Endpoint != "/mcp/p/main" {
		t.Fatalf("created: %+v", created)
	}

	// Detail never returns the token.
	code, body = doJSON(t, ts, cookie, "GET", "/api/profiles/"+itoa(created.ID), "")
	if code != http.StatusOK || strings.Contains(string(body), created.Token) || strings.Contains(string(body), `"token"`) {
		t.Fatalf("detail leaked token: %d %s", code, body)
	}

	// Duplicate slug → 409.
	code, _ = doJSON(t, ts, cookie, "POST", "/api/profiles", `{"name":"Dup","slug":"main"}`)
	if code != http.StatusConflict {
		t.Fatalf("duplicate slug: %d", code)
	}
}

func TestProfileSlugValidation(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	for _, slug := range []string{"", "A", "-x", "has space", "x", strings.Repeat("a", 64)} {
		code, _ := doJSON(t, ts, cookie, "POST", "/api/profiles", `{"name":"N","slug":"`+slug+`"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("slug %q must 400, got %d", slug, code)
		}
	}
}

func TestProfileOwnership(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, alice := seedUserSession(t, st, "alice@x", "user")
	_, bob := seedUserSession(t, st, "bob@x", "user")
	_, admin := seedUserSession(t, st, "admin@x", "admin")

	code, body := doJSON(t, ts, alice, "POST", "/api/profiles", `{"name":"Main","slug":"main"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created profileResp
	json.Unmarshal(body, &created)

	// Bob can neither see nor mutate Alice's profile (404, not 403 — no existence leak).
	if code, _ := doJSON(t, ts, bob, "GET", "/api/profiles/"+itoa(created.ID), ""); code != http.StatusNotFound {
		t.Fatalf("bob GET: %d", code)
	}
	if code, _ := doJSON(t, ts, bob, "DELETE", "/api/profiles/"+itoa(created.ID), ""); code != http.StatusNotFound {
		t.Fatalf("bob DELETE: %d", code)
	}
	// Admin can.
	if code, _ := doJSON(t, ts, admin, "GET", "/api/profiles/"+itoa(created.ID), ""); code != http.StatusOK {
		t.Fatalf("admin GET: %d", code)
	}
	// List: alice sees hers, bob sees none, admin sees all.
	_, body = doJSON(t, ts, alice, "GET", "/api/profiles", "")
	var mine []profileResp
	json.Unmarshal(body, &mine)
	if len(mine) != 1 {
		t.Fatalf("alice list: %s", body)
	}
	_, body = doJSON(t, ts, bob, "GET", "/api/profiles", "")
	var theirs []profileResp
	json.Unmarshal(body, &theirs)
	if len(theirs) != 0 {
		t.Fatalf("bob list: %s", body)
	}
	_, body = doJSON(t, ts, admin, "GET", "/api/profiles", "")
	var all []profileResp
	json.Unmarshal(body, &all)
	if len(all) != 1 {
		t.Fatalf("admin list: %s", body)
	}
}

func TestProfileServersAndRotateAndDelete(t *testing.T) {
	ctx := context.Background()
	_, ts, st, inv := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}

	_, body := doJSON(t, ts, cookie, "POST", "/api/profiles", `{"name":"Main","slug":"main"}`)
	var created profileResp
	json.Unmarshal(body, &created)
	id := itoa(created.ID)

	// Unknown server name → 400.
	if code, _ := doJSON(t, ts, cookie, "PUT", "/api/profiles/"+id+"/servers", `{"servers":["nope"]}`); code != http.StatusBadRequest {
		t.Fatalf("unknown server: %d", code)
	}
	// Valid bundle → 200 + runtime invalidated.
	if code, _ := doJSON(t, ts, cookie, "PUT", "/api/profiles/"+id+"/servers", `{"servers":["echo"]}`); code != http.StatusOK {
		t.Fatalf("set servers: %d", code)
	}
	if len(inv.ids) != 1 || inv.ids[0] != created.ID {
		t.Fatalf("bundle change must invalidate runtime: %v", inv.ids)
	}
	names, _ := st.GetProfileServers(ctx, created.ID)
	if len(names) != 1 || names[0] != "echo" {
		t.Fatalf("servers not persisted: %v", names)
	}

	// Rotate: new plaintext, old hash replaced, runtime NOT invalidated.
	before := len(inv.ids)
	code, body := doJSON(t, ts, cookie, "POST", "/api/profiles/"+id+"/token", "")
	if code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, body)
	}
	var rotated profileResp
	json.Unmarshal(body, &rotated)
	if !strings.HasPrefix(rotated.Token, "gig_") || rotated.Token == created.Token {
		t.Fatalf("rotated token: %+v", rotated)
	}
	if len(inv.ids) != before {
		t.Fatal("token rotation must NOT invalidate the runtime")
	}

	// Rename.
	if code, _ := doJSON(t, ts, cookie, "PATCH", "/api/profiles/"+id, `{"name":"Renamed"}`); code != http.StatusOK {
		t.Fatalf("patch: %d", code)
	}

	// Delete → 204, runtime invalidated, audit rows exist.
	if code, _ := doJSON(t, ts, cookie, "DELETE", "/api/profiles/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if inv.ids[len(inv.ids)-1] != created.ID {
		t.Fatalf("delete must invalidate runtime: %v", inv.ids)
	}
	events, err := st.ListAudit(ctx, 0, 50, 0)
	if err != nil || len(events) == 0 {
		t.Fatalf("audit: %v %d", err, len(events))
	}
	decisions := map[string]bool{}
	for _, e := range events {
		decisions[e.Decision] = true
	}
	for _, want := range []string{"profile_create", "profile_servers", "profile_token_rotate", "profile_delete"} {
		if !decisions[want] {
			t.Fatalf("missing audit decision %q in %v", want, decisions)
		}
	}
}
