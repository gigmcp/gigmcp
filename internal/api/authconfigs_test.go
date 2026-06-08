package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestAuthConfigPutGetListDelete(t *testing.T) {
	srv, ts, st, _ := newTestAPI(t)
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")

	// PUT creates.
	body := `{"authorize_url":"https://a/auth","token_url":"https://a/token","client_id":"cid","client_secret":"sek","default_scopes":["openid","email"],"pkce":true,"mode":"byo"}`
	code, respBody := doJSON(t, ts, adminCookie, "PUT", "/api/auth-configs/google", body)
	if code != http.StatusNoContent {
		t.Fatalf("put: %d %s", code, respBody)
	}

	// Secret is vault-encrypted at rest, not plaintext.
	stored, err := st.GetAuthConfig(t.Context(), "google")
	if err != nil {
		t.Fatal(err)
	}
	if string(stored.EncryptedClientSecret) == "sek" {
		t.Fatal("client secret must be vault-encrypted, not stored plaintext")
	}
	// Verify vault round-trip.
	plain, err := srv.Vault.Decrypt(stored.EncryptedClientSecret)
	if err != nil || string(plain) != "sek" {
		t.Fatalf("vault round trip: %v %q", err, plain)
	}

	// GET list never includes the secret.
	code, respBody = doJSON(t, ts, adminCookie, "GET", "/api/auth-configs", "")
	if code != http.StatusOK || strings.Contains(string(respBody), "sek") {
		t.Fatalf("list leaked secret or wrong status: %d %s", code, respBody)
	}
	if !strings.Contains(string(respBody), "google") {
		t.Fatalf("list missing vendor: %s", respBody)
	}

	// DELETE.
	code, respBody = doJSON(t, ts, adminCookie, "DELETE", "/api/auth-configs/google", "")
	if code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, respBody)
	}
	if _, err := st.GetAuthConfig(t.Context(), "google"); err == nil {
		t.Fatal("config not deleted")
	}
}

func TestAuthConfigRequiresAdmin(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, userCookie := seedUserSession(t, st, "alice@x", "user")

	code, _ := doJSON(t, ts, userCookie, "GET", "/api/auth-configs", "")
	if code != http.StatusForbidden {
		t.Fatalf("non-admin must be 403, got %d", code)
	}
	_ = store.AuthConfig{} // keep import
}
