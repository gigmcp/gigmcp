package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/store"
)

// fakeBrokerStore implements ConfigStore for broker tests.
type fakeBrokerStore struct {
	cfg     store.AuthConfig
	account *store.ConnectedAccount
	puts    []store.ConnectedAccount
}

func (f *fakeBrokerStore) GetAuthConfig(_ context.Context, vendor string) (store.AuthConfig, error) {
	if f.cfg.Vendor != vendor {
		return store.AuthConfig{}, store.ErrAuthConfigNotFound
	}
	return f.cfg, nil
}
func (f *fakeBrokerStore) GetConnectedAccount(_ context.Context, _ int64, vendor string) (store.ConnectedAccount, error) {
	if f.account == nil || f.account.Vendor != vendor {
		return store.ConnectedAccount{}, store.ErrConnectedAccountNotFound
	}
	return *f.account, nil
}
func (f *fakeBrokerStore) PutConnectedAccount(_ context.Context, c store.ConnectedAccount) error {
	f.puts = append(f.puts, c)
	f.account = &c
	return nil
}
func (f *fakeBrokerStore) UpdateConnectedAccountTokens(_ context.Context, _ int64, _ string, enc []byte, exp time.Time) error {
	if f.account == nil {
		return store.ErrConnectedAccountNotFound
	}
	f.account.EncryptedAccessToken = enc
	f.account.ExpiresAt = exp
	return nil
}

// passthroughVault is a no-op Vaulter for broker tests (ciphertext == plaintext
// with a marker prefix so we can assert the broker called Encrypt).
type passthroughVault struct{}

func (passthroughVault) Encrypt(p []byte) ([]byte, error) { return append([]byte("enc:"), p...), nil }
func (passthroughVault) Decrypt(b []byte) ([]byte, error) { return b[len("enc:"):], nil }

func newTestBroker(t *testing.T, fs *fakeBrokerStore) *OAuthBroker {
	t.Helper()
	b, err := NewOAuthBroker(fs, passthroughVault{},
		"http://localhost:8080/api/connections/oauth/callback", "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStartRedirectsToAuthorizeWithScopeUnion(t *testing.T) {
	fp := newFakeProvider(t)
	fs := &fakeBrokerStore{cfg: store.AuthConfig{
		Vendor: "google", AuthorizeURL: fp.srv.URL + "/authorize",
		TokenURL: fp.srv.URL + "/token", ClientID: "cid",
		EncryptedClientSecret: []byte("enc:sek"), DefaultScopes: []string{"openid"},
		PKCE: true, Mode: "byo",
	}}
	b := newTestBroker(t, fs)

	// required scopes passed by the API layer (manifest scopes for this app).
	req := httptest.NewRequest("GET", "/api/connections/oauth/start?vendor=google", nil)
	rec := httptest.NewRecorder()
	b.StartHandler(rec, req, 42, []string{"email", "profile"}, "/servers/gmail")
	if rec.Code != http.StatusFound {
		t.Fatalf("start status %d body=%s", rec.Code, rec.Body)
	}
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if !strings.HasPrefix(loc.String(), fp.srv.URL+"/authorize") {
		t.Fatalf("redirect not to authorize: %s", loc)
	}
	scope := loc.Query().Get("scope")
	// union of default openid + required email/profile, space-joined.
	if !strings.Contains(scope, "email") || !strings.Contains(scope, "profile") || !strings.Contains(scope, "openid") {
		t.Fatalf("scope union missing: %q", scope)
	}
	if loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE challenge missing: %s", loc)
	}
	if loc.Query().Get("state") == "" {
		t.Fatal("state missing")
	}
	var flow *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == oauthFlowCookie {
			flow = c
		}
	}
	if flow == nil {
		t.Fatal("no oauth flow cookie set")
	}
}

func TestUnionScopes(t *testing.T) {
	got := unionScopes([]string{"email", "profile"}, []string{"profile", "drive"})
	want := []string{"drive", "email", "profile"} // sorted, deduped
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unionScopes = %v, want %v", got, want)
	}
	if got := unionScopes(nil, nil); len(got) != 0 {
		t.Fatalf("empty union must be empty, got %v", got)
	}
}

func TestScopesSatisfied(t *testing.T) {
	if !scopesSatisfied([]string{"email", "profile", "drive"}, []string{"email", "drive"}) {
		t.Fatal("granted superset must satisfy required")
	}
	if scopesSatisfied([]string{"email"}, []string{"email", "drive"}) {
		t.Fatal("missing 'drive' must NOT be satisfied")
	}
}

func TestCallbackExchangesAndStoresTokens(t *testing.T) {
	fp := newFakeProvider(t)
	fs := &fakeBrokerStore{cfg: store.AuthConfig{
		Vendor: "google", AuthorizeURL: fp.srv.URL + "/authorize",
		TokenURL: fp.srv.URL + "/token", ClientID: "cid",
		EncryptedClientSecret: []byte("enc:sek"), DefaultScopes: []string{"openid"},
		PKCE: true, Mode: "byo",
	}}
	b := newTestBroker(t, fs)

	// Drive Start to get a valid flow cookie + state.
	startReq := httptest.NewRequest("GET", "/api/connections/oauth/start?vendor=google", nil)
	startRec := httptest.NewRecorder()
	b.StartHandler(startRec, startReq, 42, []string{"email", "profile"}, "/servers/gmail")
	loc, _ := url.Parse(startRec.Header().Get("Location"))
	state := loc.Query().Get("state")
	var flow *http.Cookie
	for _, c := range startRec.Result().Cookies() {
		if c.Name == oauthFlowCookie {
			flow = c
		}
	}

	// Provider's /authorize bounced us a code; feed it to the callback.
	cbReq := httptest.NewRequest("GET", "/api/connections/oauth/callback?code=code-xyz&state="+url.QueryEscape(state), nil)
	cbReq.AddCookie(flow)
	cbRec := httptest.NewRecorder()
	b.CallbackHandler(cbRec, cbReq)
	if cbRec.Code != http.StatusFound || cbRec.Header().Get("Location") != "/servers/gmail" {
		t.Fatalf("callback: code=%d loc=%q body=%s", cbRec.Code, cbRec.Header().Get("Location"), cbRec.Body)
	}
	if len(fs.puts) != 1 {
		t.Fatalf("expected one PutConnectedAccount, got %d", len(fs.puts))
	}
	got := fs.puts[0]
	if got.UserID != 42 || got.Vendor != "google" {
		t.Fatalf("stored account wrong identity: %+v", got)
	}
	// Tokens are vault ciphertext (passthroughVault prefixes "enc:").
	if string(got.EncryptedRefreshToken) != "enc:refresh-tok" {
		t.Fatalf("refresh token not vault-encrypted: %q", got.EncryptedRefreshToken)
	}
	if !strings.HasPrefix(string(got.EncryptedAccessToken), "enc:access-") {
		t.Fatalf("access token not vault-encrypted: %q", got.EncryptedAccessToken)
	}
	// granted_scopes reflect what the provider returned (the union it consented).
	if !scopesSatisfied(got.GrantedScopes, []string{"email", "profile", "openid"}) {
		t.Fatalf("granted scopes missing union members: %v", got.GrantedScopes)
	}
}

func TestEnsureFreshTokenReturnsCachedWhenValid(t *testing.T) {
	fp := newFakeProvider(t)
	fs := &fakeBrokerStore{
		cfg: store.AuthConfig{
			Vendor: "google", TokenURL: fp.srv.URL + "/token", ClientID: "cid",
			EncryptedClientSecret: []byte("enc:sek"), Mode: "byo",
		},
		account: &store.ConnectedAccount{
			UserID: 42, Vendor: "google",
			EncryptedRefreshToken: []byte("enc:refresh-tok"),
			EncryptedAccessToken:  []byte("enc:cached-access"),
			ExpiresAt:             time.Now().Add(30 * time.Minute),
			GrantedScopes:         []string{"email"},
		},
	}
	b := newTestBroker(t, fs)
	at, err := b.EnsureFreshToken(context.Background(), 42, "google")
	if err != nil {
		t.Fatal(err)
	}
	if at != "cached-access" {
		t.Fatalf("valid cached token must be returned verbatim, got %q", at)
	}
	if fp.lastGrant != "" {
		t.Fatal("token endpoint must NOT be called when the cached token is valid")
	}
}

func TestEnsureFreshTokenRefreshesWhenExpired(t *testing.T) {
	fp := newFakeProvider(t)
	fs := &fakeBrokerStore{
		cfg: store.AuthConfig{
			Vendor: "google", TokenURL: fp.srv.URL + "/token", ClientID: "cid",
			EncryptedClientSecret: []byte("enc:sek"), Mode: "byo",
		},
		account: &store.ConnectedAccount{
			UserID: 42, Vendor: "google",
			EncryptedRefreshToken: []byte("enc:refresh-tok"),
			EncryptedAccessToken:  []byte("enc:stale-access"),
			ExpiresAt:             time.Now().Add(-time.Minute), // expired
			GrantedScopes:         []string{"email"},
		},
	}
	b := newTestBroker(t, fs)
	at, err := b.EnsureFreshToken(context.Background(), 42, "google")
	if err != nil {
		t.Fatal(err)
	}
	if fp.lastGrant != "refresh_token" {
		t.Fatalf("expected a refresh_token grant, saw %q", fp.lastGrant)
	}
	if !strings.HasPrefix(at, "access-") {
		t.Fatalf("expected a freshly minted access token, got %q", at)
	}
	// The rotated access token must be persisted (vault-encrypted).
	if !strings.HasPrefix(string(fs.account.EncryptedAccessToken), "enc:access-") {
		t.Fatalf("rotated token not persisted: %q", fs.account.EncryptedAccessToken)
	}
	if !fs.account.ExpiresAt.After(time.Now()) {
		t.Fatal("expiry not advanced after refresh")
	}
}

func TestCallbackRejectsBrokerStateMismatch(t *testing.T) {
	fp := newFakeProvider(t)
	fs := &fakeBrokerStore{cfg: store.AuthConfig{
		Vendor: "google", AuthorizeURL: fp.srv.URL + "/authorize",
		TokenURL: fp.srv.URL + "/token", ClientID: "cid",
		EncryptedClientSecret: []byte("enc:sek"), Mode: "byo",
	}}
	b := newTestBroker(t, fs)
	startReq := httptest.NewRequest("GET", "/api/connections/oauth/start?vendor=google", nil)
	startRec := httptest.NewRecorder()
	b.StartHandler(startRec, startReq, 42, nil, "/servers/gmail")
	var flow *http.Cookie
	for _, c := range startRec.Result().Cookies() {
		if c.Name == oauthFlowCookie {
			flow = c
		}
	}
	cbReq := httptest.NewRequest("GET", "/api/connections/oauth/callback?code=code-xyz&state=EVIL", nil)
	cbReq.AddCookie(flow)
	cbRec := httptest.NewRecorder()
	b.CallbackHandler(cbRec, cbReq)
	if cbRec.Code != http.StatusBadRequest {
		t.Fatalf("state mismatch must 400, got %d", cbRec.Code)
	}
	if len(fs.puts) != 0 {
		t.Fatal("no account may be stored on state mismatch")
	}
}
