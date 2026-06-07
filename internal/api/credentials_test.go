package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
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

	// The row is keyed by the OWNING USER ID as decimal string (spec §3).
	cred, err := st.GetCredential(ctx, "github", strconv.FormatInt(u.ID, 10))
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
		`{"secret":"SUPERSECRET","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"P","allowed_hosts":["api.github.com"]}`)

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
		`{"secret":"k","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"P","allowed_hosts":["api.github.com"]}`)
	if code, _ := doJSON(t, ts, cookie, "DELETE", "/api/credentials/github", ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if _, err := st.GetCredential(ctx, "github", strconv.FormatInt(u.ID, 10)); err == nil {
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
