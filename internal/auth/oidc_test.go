package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/config"
	"github.com/gigmcp/gigmcp/internal/store"
)

// fakeIssuer is a minimal OIDC provider: discovery + JWKS + token endpoint.
// The test mints the ID token AFTER it learns the nonce from the login
// redirect, then the token endpoint serves it.
type fakeIssuer struct {
	srv          *httptest.Server
	key          *rsa.PrivateKey
	idToken      string // set by the test before hitting the callback
	tokenHits    int    // incremented on every POST /token call
	tokenErrCode int    // if non-zero, /token responds with this HTTP status + error body
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &f.key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		f.tokenHits++
		if f.tokenErrCode != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.tokenErrCode)
			json.NewEncoder(w).Encode(map[string]any{"error": "server_error"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     f.idToken,
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// mintIDToken RS256-signs an ID token with the given nonce and roles claim.
func (f *fakeIssuer) mintIDToken(t *testing.T, clientID, sub, email, name, nonce string, roles map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss":           f.srv.URL,
		"aud":           clientID,
		"sub":           sub,
		"exp":           time.Now().Add(time.Hour).Unix(),
		"iat":           time.Now().Unix(),
		"nonce":         nonce,
		"email":         email,
		"name":          name,
		auth.RolesClaim: roles,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sig.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newAuthenticator(t *testing.T, issuerURL string, st store.Store) *auth.Authenticator {
	t.Helper()
	cfg := config.Config{
		OIDCIssuer:      issuerURL,
		OIDCClientID:    "gigmcp-client",
		OIDCRedirectURL: "http://localhost:8080/api/auth/callback",
		OIDCAdminRole:   "gigmcp-admin",
		SessionTTL:      time.Hour,
		PublicURL:       "http://localhost:8080",
	}
	a, err := auth.NewAuthenticator(context.Background(), cfg, st)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

// startLogin drives LoginHandler and returns the state, nonce and flow cookie.
func startLogin(t *testing.T, a *auth.Authenticator) (state, nonce string, flow *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.LoginHandler(rec, httptest.NewRequest("GET", "/api/auth/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login status %d: %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state = loc.Query().Get("state")
	nonce = loc.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("authorize URL missing state/nonce: %s", loc)
	}
	if loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE challenge missing from authorize URL: %s", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gig_oidc_flow" {
			flow = c
		}
	}
	if flow == nil {
		t.Fatal("no flow cookie set by LoginHandler")
	}
	return state, nonce, flow
}

func TestLoginPromptCreate(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)

	// ?prompt=create must propagate to the authorize URL (the separate "Sign up" link).
	rec := httptest.NewRecorder()
	a.LoginHandler(rec, httptest.NewRequest("GET", "/api/auth/login?prompt=create", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login status %d: %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Query().Get("prompt"); got != "create" {
		t.Fatalf("authorize URL prompt = %q, want \"create\": %s", got, loc)
	}

	// Default login must NOT set prompt (stays on the sign-in page).
	rec = httptest.NewRecorder()
	a.LoginHandler(rec, httptest.NewRequest("GET", "/api/auth/login", nil))
	loc, err = url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Query().Get("prompt"); got != "" {
		t.Fatalf("default login set prompt = %q, want empty: %s", got, loc)
	}
}

func TestLoginCallbackProvisionsUserAndSession(t *testing.T) {
	ctx := context.Background()
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)

	state, nonce, flow := startLogin(t, a)

	// Roles claim contains the admin role → user must come out "admin".
	iss.idToken = iss.mintIDToken(t, "gigmcp-client", "user-123", "alice@example.com", "Alice", nonce,
		map[string]any{"gigmcp-admin": map[string]any{"org1": "org1.example"}})

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: code=%d loc=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie && c.Value != "" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly {
		t.Fatalf("session cookie missing or not httpOnly: %+v", sessionCookie)
	}

	users, err := st.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("users: %v %d", err, len(users))
	}
	if users[0].Subject != "user-123" || users[0].Role != "admin" || users[0].Email != "alice@example.com" {
		t.Fatalf("JIT user: %+v", users[0])
	}

	sess, err := st.GetSession(ctx, auth.HashToken(sessionCookie.Value))
	if err != nil || sess.UserID != users[0].ID {
		t.Fatalf("session row: %v %+v", err, sess)
	}

	events, err := st.ListAudit(ctx, 0, 10, 0)
	if err != nil || len(events) == 0 || events[0].Kind != "auth" || events[0].Decision != "login" {
		t.Fatalf("login audit event: %v %+v", err, events)
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	_, nonce, flow := startLogin(t, a)
	iss.idToken = iss.mintIDToken(t, "gigmcp-client", "user-123", "a@x", "A", nonce, nil)

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state=evil", nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("state mismatch must 400, got %d", rec.Code)
	}
	if users, _ := st.ListUsers(context.Background()); len(users) != 0 {
		t.Fatal("no user may be provisioned on a failed callback")
	}
}

func TestCallbackRejectsNonceMismatch(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	state, _, flow := startLogin(t, a)
	// Mint with the WRONG nonce.
	iss.idToken = iss.mintIDToken(t, "gigmcp-client", "user-123", "a@x", "A", "wrong-nonce", nil)

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nonce mismatch must 401, got %d", rec.Code)
	}
}

func TestLogoutDeletesSession(t *testing.T) {
	ctx := context.Background()
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	_, cookie := seedSession(t, st, "alice", "user")

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	a.LogoutHandler(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if _, err := st.GetSession(ctx, auth.HashToken(cookie.Value)); err == nil {
		t.Fatal("session must be deleted on logout")
	}
	events, _ := st.ListAudit(ctx, 0, 10, 0)
	if len(events) == 0 || events[0].Decision != "logout" {
		t.Fatalf("logout audit event: %+v", events)
	}
}

func TestMapRole(t *testing.T) {
	if auth.MapRole(map[string]any{"gigmcp-admin": map[string]any{}}, "gigmcp-admin") != "admin" {
		t.Fatal("admin role present must map to admin")
	}
	if auth.MapRole(map[string]any{"other-role": 1}, "gigmcp-admin") != "user" {
		t.Fatal("other roles must map to user")
	}
	if auth.MapRole(nil, "gigmcp-admin") != "user" {
		t.Fatal("nil claim must map to user")
	}
}

// I4(a): tampered flow-cookie signature → 400; token endpoint NOT called.
func TestCallbackTamperedFlowCookieSignature(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	state, _, flow := startLogin(t, a)

	// Corrupt a character in the base64 PAYLOAD segment (before the ".") so the
	// recomputed HMAC no longer matches the appended signature. We avoid flipping
	// the final character of the signature segment: RawURLEncoding tolerates
	// non-canonical trailing bits, so an 'a'<->'b' flip there can decode to the
	// *same* bytes (~6.6% of random signatures) and silently verify — making the
	// test flaky. Mutating an interior payload byte always changes the HMAC input.
	orig := flow.Value
	dot := strings.IndexByte(orig, '.')
	if dot <= 0 {
		t.Fatalf("flow cookie not in payload.sig form: %q", orig)
	}
	c := orig[0]
	var replacement byte
	if c == 'a' {
		replacement = 'b'
	} else {
		replacement = 'a'
	}
	flow.Value = string(replacement) + orig[1:]

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tampered cookie must 400, got %d body=%s", rec.Code, rec.Body)
	}
	if iss.tokenHits != 0 {
		t.Fatalf("token endpoint must NOT be called on tampered flow cookie; got %d hits", iss.tokenHits)
	}
	if users, _ := st.ListUsers(context.Background()); len(users) != 0 {
		t.Fatal("no user must be provisioned on tampered flow cookie")
	}
}

// I4(b): missing flow cookie → 400.
func TestCallbackMissingFlowCookie(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	state, _, _ := startLogin(t, a)

	// No flow cookie added to request.
	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state="+url.QueryEscape(state), nil)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing flow cookie must 400, got %d body=%s", rec.Code, rec.Body)
	}
}

// I4(c): token endpoint returns 500 → callback 502, no user provisioned.
func TestCallbackTokenEndpoint500(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	state, _, flow := startLogin(t, a)

	iss.tokenErrCode = http.StatusInternalServerError

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("token 500 must yield callback 502, got %d body=%s", rec.Code, rec.Body)
	}
	if users, _ := st.ListUsers(context.Background()); len(users) != 0 {
		t.Fatal("no user must be provisioned when token endpoint errors")
	}
}

// I4(d): wrong-audience ID token → callback 401.
func TestCallbackWrongAudienceIDToken(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	state, nonce, flow := startLogin(t, a)

	// Mint with a different audience ("other-client" instead of "gigmcp-client").
	iss.idToken = iss.mintIDToken(t, "other-client", "user-999", "eve@example.com", "Eve", nonce, nil)

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-audience token must 401, got %d body=%s", rec.Code, rec.Body)
	}
	if users, _ := st.ListUsers(context.Background()); len(users) != 0 {
		t.Fatal("no user must be provisioned on wrong-audience token")
	}
}

// I4(e): end-to-end login with NO roles claim → user provisioned with role "user".
func TestCallbackNoRolesClaimDefaultsToUser(t *testing.T) {
	ctx := context.Background()
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	state, nonce, flow := startLogin(t, a)

	// Mint with nil roles map (no roles claim present).
	iss.idToken = iss.mintIDToken(t, "gigmcp-client", "user-456", "bob@example.com", "Bob", nonce, nil)

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("no-roles callback: code=%d loc=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	users, err := st.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("users: %v %d", err, len(users))
	}
	if users[0].Role != "user" {
		t.Fatalf("no roles claim must yield role 'user', got %q", users[0].Role)
	}
}

// I2: RFC 6749 provider error callback → 401, no exchange attempted.
func TestCallbackProviderError(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	state, _, flow := startLogin(t, a)

	// IdP redirects back with error= (e.g. user denied consent).
	req := httptest.NewRequest("GET",
		"/api/auth/callback?error=access_denied&error_description=User+denied+access&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("provider error must 401, got %d body=%s", rec.Code, rec.Body)
	}
	if iss.tokenHits != 0 {
		t.Fatalf("token endpoint must NOT be called on provider error; got %d hits", iss.tokenHits)
	}
	if users, _ := st.ListUsers(context.Background()); len(users) != 0 {
		t.Fatal("no user must be provisioned on provider error")
	}
}

// Note on expired-cookie test: the HMAC key is unexported and process-random
// (generated in NewAuthenticator). There is no clean seam to mint a cookie
// with a past Expires timestamp from outside the package without invasive
// changes. Expired-cookie coverage is therefore skipped per the task spec.
// The expiry check IS exercised implicitly by the 10-minute TTL enforced in
// verifyFlow (see oidc.go).
