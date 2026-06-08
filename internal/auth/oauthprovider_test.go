package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
)

// fakeProvider is a minimal OAuth2 authorization server: /authorize (records
// the redirect + scopes, hands back a code) and /token (exchanges code →
// access+refresh, and refresh_token grant → a fresh access token). No OIDC.
type fakeProvider struct {
	srv          *httptest.Server
	mu           sync.Mutex
	lastScopes   string // raw scope param seen on /authorize or /token
	lastGrant    string // grant_type seen on /token
	codeToScopes map[string]string
	accessSeq    int // increments so each minted access token is distinct
	tokenErr     int // if non-zero, /token responds with this status
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	f := &fakeProvider{codeToScopes: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.lastScopes = r.URL.Query().Get("scope")
		f.codeToScopes["code-xyz"] = f.lastScopes
		f.mu.Unlock()
		// Bounce straight back to redirect_uri with code+state (simulated consent).
		ru, _ := url.Parse(r.URL.Query().Get("redirect_uri"))
		q := ru.Query()
		q.Set("code", "code-xyz")
		q.Set("state", r.URL.Query().Get("state"))
		ru.RawQuery = q.Encode()
		http.Redirect(w, r, ru.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.lastGrant = r.Form.Get("grant_type")
		f.accessSeq++
		seq := f.accessSeq
		if s := r.Form.Get("scope"); s != "" {
			f.lastScopes = s
		}
		errCode := f.tokenErr
		grantedScopes := f.codeToScopes[r.Form.Get("code")]
		f.mu.Unlock()
		if errCode != 0 {
			w.WriteHeader(errCode)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"access_token":  "access-" + itoa(seq),
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "refresh-tok",
		}
		if grantedScopes != "" {
			resp["scope"] = grantedScopes
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
