package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestCredentialPutEncryptsAndScopesToUser(t *testing.T) {
	ctx := context.Background()
	srv, ts, st, _ := newTestAPI(t)
	u, cookie := seedUserSession(t, st, "alice@x", "user")

	code, body := doJSON(t, ts, cookie, "PUT", "/api/credentials/github",
		`{"secret":"ghp_real","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"PLACEHOLDER","allowed_hosts":["api.github.com"]}`)
	if code != http.StatusNoContent {
		t.Fatalf("put: %d %s", code, body)
	}

	// The row is keyed by the OWNING USER ID as decimal string.
	cred, err := st.GetCredential(ctx, "github", store.UserTenant(u.ID))
	if err != nil {
		t.Fatalf("row missing under user-id tenant: %v", err)
	}
	if string(cred.EncryptedKey) == "ghp_real" {
		t.Fatal("secret stored in plaintext")
	}
	plain, err := srv.Vault.Decrypt(cred.EncryptedKey)
	if err != nil || string(plain) != "ghp_real" {
		t.Fatalf("vault round trip: %v %q", err, plain)
	}
	if cred.InjectHeader != "Authorization" || cred.Placeholder != "PLACEHOLDER" {
		t.Fatalf("metadata: %+v", cred)
	}
}

func TestCredentialListNeverReturnsSecrets(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, alice := seedUserSession(t, st, "alice@x", "user")
	_, bob := seedUserSession(t, st, "bob@x", "user")

	doJSON(t, ts, alice, "PUT", "/api/credentials/github",
		`{"secret":"SUPERSECRET","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"PLACEHOLDER_ALICE","allowed_hosts":["api.github.com"]}`)

	code, body := doJSON(t, ts, alice, "GET", "/api/credentials", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	if strings.Contains(string(body), "SUPERSECRET") || strings.Contains(string(body), "encrypted") {
		t.Fatalf("secret material leaked: %s", body)
	}
	var list []struct {
		Server string `json:"server"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 1 || list[0].Server != "github" {
		t.Fatalf("list shape: %v %s", err, body)
	}

	// Bob's view is empty — credentials are per-user.
	_, body = doJSON(t, ts, bob, "GET", "/api/credentials", "")
	var bobList []struct{}
	json.Unmarshal(body, &bobList)
	if len(bobList) != 0 {
		t.Fatalf("cross-user credential leak: %s", body)
	}
}

func TestCredentialValidationAndDelete(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	u, cookie := seedUserSession(t, st, "alice@x", "user")

	// Empty secret → 400.
	if code, _ := doJSON(t, ts, cookie, "PUT", "/api/credentials/github", `{"secret":""}`); code != http.StatusBadRequest {
		t.Fatalf("empty secret: %d", code)
	}

	doJSON(t, ts, cookie, "PUT", "/api/credentials/github",
		`{"secret":"k","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"PLACEHOLDER_LONG","allowed_hosts":["api.github.com"]}`)
	if code, _ := doJSON(t, ts, cookie, "DELETE", "/api/credentials/github", ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if _, err := st.GetCredential(ctx, "github", store.UserTenant(u.ID)); err == nil {
		t.Fatal("credential not deleted")
	}

	events, _ := st.ListAudit(ctx, 0, 50, 0)
	decisions := map[string]bool{}
	for _, e := range events {
		decisions[e.Decision] = true
	}
	if !decisions["credential_put"] || !decisions["credential_delete"] {
		t.Fatalf("missing credential audit events: %v", decisions)
	}
}

// TestCredentialServerNameValidation verifies {server} path validation.
func TestCredentialServerNameValidation(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	cases := []struct {
		server string
		wantOK bool
	}{
		{"github", true},
		{"my-server", true},
		{"my_server", true},
		{"server123", true},
		{"a", true}, // single char: matches ^[a-z0-9][a-z0-9_-]{0,63}$ (0 trailing chars ok)
		{"-bad", false},
		{"Bad", false},
		// Note: "has/slash" is not tested here because Go's ServeMux routes it
		// to a different path entirely (404), not to the credential handler.
	}

	for _, tc := range cases {
		path := "/api/credentials/" + tc.server
		if tc.server == "" {
			continue // empty server doesn't route
		}
		code, _ := doJSON(t, ts, cookie, "PUT", path,
			`{"secret":"s12345678","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"PLACEHOLDER_OK"}`)
		if tc.wantOK {
			if code != http.StatusNoContent {
				t.Errorf("server=%q: expected 204, got %d", tc.server, code)
			}
		} else {
			if code != http.StatusBadRequest {
				t.Errorf("server=%q: expected 400, got %d", tc.server, code)
			}
		}
	}
}

// TestCredentialFieldValidation covers each invalid transitional field.
func TestCredentialFieldValidation(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	cases := []struct {
		name string
		body string
		want int
		msg  string // substring expected in body on 400
	}{
		{
			"valid all fields",
			`{"secret":"s","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"PLACEHOLDER_OK","allowed_hosts":["api.github.com"]}`,
			http.StatusNoContent, "",
		},
		{
			"inject_header with space",
			`{"secret":"s","inject_header":"Bad Header"}`,
			http.StatusBadRequest, "inject_header",
		},
		{
			"inject_header too long",
			`{"secret":"s","inject_header":"` + strings.Repeat("A", 65) + `"}`,
			http.StatusBadRequest, "inject_header",
		},
		{
			"inject_format missing {token}",
			`{"secret":"s","inject_format":"Bearer TOKEN"}`,
			http.StatusBadRequest, "inject_format",
		},
		{
			"inject_format too long",
			`{"secret":"s","inject_format":"` + strings.Repeat("a", 257) + `"}`,
			http.StatusBadRequest, "inject_format",
		},
		{
			"placeholder too short",
			`{"secret":"s","placeholder":"short"}`,
			http.StatusBadRequest, "placeholder",
		},
		{
			"placeholder too long",
			`{"secret":"s","placeholder":"` + strings.Repeat("p", 257) + `"}`,
			http.StatusBadRequest, "placeholder",
		},
		{
			"allowed_hosts empty entry",
			`{"secret":"s","allowed_hosts":[""]}`,
			http.StatusBadRequest, "allowed_hosts",
		},
		{
			"allowed_hosts with uppercase",
			`{"secret":"s","allowed_hosts":["API.GITHUB.COM"]}`,
			http.StatusBadRequest, "allowed_hosts",
		},
		{
			"allowed_hosts with newline",
			`{"secret":"s","allowed_hosts":["api.github.com\nbad.com"]}`,
			http.StatusBadRequest, "allowed_hosts",
		},
		{
			// 65 entries: above the 64-entry cap.
			"allowed_hosts too many",
			`{"secret":"s","allowed_hosts":["a.com","b.com","c.com","d.com","e.com","f.com","g.com","h.com","i.com","j.com","k.com","l.com","m.com","n.com","o.com","p.com","q.com","r.com","s.com","t.com","u.com","v.com","w.com","x.com","y.com","z.com","aa.com","ab.com","ac.com","ad.com","ae.com","af.com","ag.com","ah.com","ai.com","aj.com","ak.com","al.com","am.com","an.com","ao.com","ap.com","aq.com","ar.com","as.com","at.com","au.com","av.com","aw.com","ax.com","ay.com","az.com","ba.com","bb.com","bc.com","bd.com","be.com","bf.com","bg.com","bh.com","bi.com","bj.com","bk.com","bl.com","bm.com"]}`,
			http.StatusBadRequest, "allowed_hosts",
		},
		{
			"allowed_hosts wildcard valid",
			`{"secret":"s","allowed_hosts":["*.github.com"],"inject_format":"Bearer {token}","placeholder":"PLACEHOLDER_WC"}`,
			http.StatusNoContent, "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := doJSON(t, ts, cookie, "PUT", "/api/credentials/test-server", tc.body)
			if code != tc.want {
				t.Fatalf("got %d, want %d; body: %s", code, tc.want, body)
			}
			if tc.msg != "" && !strings.Contains(string(body), tc.msg) {
				t.Fatalf("expected %q in body, got: %s", tc.msg, body)
			}
		})
	}
}

// TestCredentialDeleteNoop verifies that DELETE on a non-existent credential
// still returns 204 but records noop=true in the audit detail.
func TestCredentialDeleteNoop(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	// DELETE a credential that was never PUT.
	code, body := doJSON(t, ts, cookie, "DELETE", "/api/credentials/never-existed", "")
	if code != http.StatusNoContent {
		t.Fatalf("noop delete: got %d %s", code, body)
	}

	// Audit row should record noop=true.
	events, _ := st.ListAudit(ctx, 0, 50, 0)
	var found bool
	for _, e := range events {
		if e.Decision == "credential_delete" && strings.Contains(e.Detail, "noop=true") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected audit event with noop=true; events: %+v", events)
	}
}

// TestCredentialIsolation verifies per-user isolation: bob's writes don't
// affect alice's data; bob's delete leaves alice's row intact.
func TestCredentialIsolation(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	uAlice, alice := seedUserSession(t, st, "alice@iso", "user")
	_, bob := seedUserSession(t, st, "bob@iso", "user")

	// Alice stores a credential.
	code, body := doJSON(t, ts, alice, "PUT", "/api/credentials/shared-server",
		`{"secret":"alice-secret","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"ALICE_PLACEHOLDER"}`)
	if code != http.StatusNoContent {
		t.Fatalf("alice put: %d %s", code, body)
	}

	// Bob stores a different credential for the same server name.
	code, body = doJSON(t, ts, bob, "PUT", "/api/credentials/shared-server",
		`{"secret":"bob-secret","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"BOB__PLACEHOLDER"}`)
	if code != http.StatusNoContent {
		t.Fatalf("bob put: %d %s", code, body)
	}

	// Alice's GET returns only her credential.
	code, body = doJSON(t, ts, alice, "GET", "/api/credentials", "")
	if code != http.StatusOK {
		t.Fatalf("alice list: %d %s", code, body)
	}
	if strings.Contains(string(body), "bob-secret") || strings.Contains(string(body), "BOB__PLACEHOLDER") {
		t.Fatalf("alice list leaked bob data: %s", body)
	}

	// Verify alice's row via store.
	aliceCred, err := st.GetCredential(ctx, "shared-server", store.UserTenant(uAlice.ID))
	if err != nil {
		t.Fatalf("alice row missing: %v", err)
	}
	if aliceCred.Placeholder != "ALICE_PLACEHOLDER" {
		t.Fatalf("alice placeholder wrong: %q", aliceCred.Placeholder)
	}

	// Bob DELETE removes only his row.
	code, _ = doJSON(t, ts, bob, "DELETE", "/api/credentials/shared-server", "")
	if code != http.StatusNoContent {
		t.Fatalf("bob delete: %d", code)
	}

	// Alice's row must still exist.
	if _, err := st.GetCredential(ctx, "shared-server", store.UserTenant(uAlice.ID)); err != nil {
		t.Fatalf("alice row deleted by bob's delete: %v", err)
	}
}
