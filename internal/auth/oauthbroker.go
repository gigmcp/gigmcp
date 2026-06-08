package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/gigmcp/gigmcp/internal/store"
)

// oauthFlowCookie is the cookie name for connect-flow state. Separate from the
// OIDC login flow cookie (gig_oidc_flow) so a connect-in-flight never collides
// with a login-in-flight.
const oauthFlowCookie = "gig_oauth_flow"

// oauthFlowState is the signed payload of the 10-minute connect-flow cookie:
// state + PKCE verifier + the vendor being connected + where to send the user
// back after callback. Mirrors oidc.go's stateless signed-cookie design.
type oauthFlowState struct {
	State    string   `json:"state"`
	Verifier string   `json:"verifier"` // PKCE code verifier
	Vendor   string   `json:"vendor"`
	UserID   int64    `json:"uid"` // bind the flow to the initiating user
	ReturnTo string   `json:"return_to"`
	Scopes   []string `json:"scopes"` // the union requested (for granted-scope persistence)
	Expires  int64    `json:"expires"`
}

// ConfigStore is the slice of store.Store the broker needs (satisfied by the
// real *sqliteStore and by test fakes).
type ConfigStore interface {
	GetAuthConfig(ctx context.Context, vendor string) (store.AuthConfig, error)
	GetConnectedAccount(ctx context.Context, userID int64, vendor string) (store.ConnectedAccount, error)
	PutConnectedAccount(ctx context.Context, c store.ConnectedAccount) error
	UpdateConnectedAccountTokens(ctx context.Context, userID int64, vendor string, encAccess []byte, expiresAt time.Time) error
}

// Vaulter is the encrypt/decrypt seam (satisfied by *vault.Vault).
type Vaulter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(box []byte) ([]byte, error)
}

// OAuthBroker drives per-vendor OAuth authorization-code+PKCE connect flows and
// resolver-time token refresh. It generalizes the single-issuer OIDC
// Authenticator (oidc.go) to arbitrary providers configured per Auth Config.
type OAuthBroker struct {
	Store     ConfigStore // store.Store, named locally to avoid an import cycle in tests
	Vault     Vaulter     // vault.Vault
	hmacKey   []byte      // process-random; signs the transient flow cookie
	secure    bool        // Secure cookie flag (https public URL)
	redirect  string      // the gateway's OAuth callback URL (absolute)
	publicURL string      // base for building ReturnTo redirects
	now       func() time.Time
}

// NewOAuthBroker builds a broker. redirect is the absolute callback URL
// (e.g. https://gig.example.com/api/connections/oauth/callback); publicURL is
// the https-aware base used for Secure-cookie + ReturnTo decisions.
func NewOAuthBroker(st ConfigStore, vlt Vaulter, redirect, publicURL string) (*OAuthBroker, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &OAuthBroker{
		Store:     st,
		Vault:     vlt,
		hmacKey:   key,
		secure:    strings.HasPrefix(publicURL, "https://"),
		redirect:  redirect,
		publicURL: publicURL,
		now:       time.Now,
	}, nil
}

// unionScopes returns the sorted, de-duplicated union of all scope lists.
func unionScopes(lists ...[]string) []string {
	set := map[string]struct{}{}
	for _, l := range lists {
		for _, s := range l {
			if s != "" {
				set[s] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// scopesSatisfied reports whether every required scope is present in granted.
func scopesSatisfied(granted, required []string) bool {
	have := map[string]struct{}{}
	for _, s := range granted {
		have[s] = struct{}{}
	}
	for _, s := range required {
		if _, ok := have[s]; !ok {
			return false
		}
	}
	return true
}

func (b *OAuthBroker) signFlow(fs oauthFlowState) (string, error) {
	payload, err := json.Marshal(fs)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, b.hmacKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (b *OAuthBroker) verifyFlow(v string) (oauthFlowState, error) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return oauthFlowState{}, errors.New("malformed oauth flow cookie")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oauthFlowState{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return oauthFlowState{}, err
	}
	mac := hmac.New(sha256.New, b.hmacKey)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return oauthFlowState{}, errors.New("bad oauth flow cookie signature")
	}
	var fs oauthFlowState
	if err := json.Unmarshal(payload, &fs); err != nil {
		return oauthFlowState{}, err
	}
	if b.now().Unix() > fs.Expires {
		return oauthFlowState{}, errors.New("oauth flow expired")
	}
	return fs, nil
}

func (b *OAuthBroker) setFlowCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     oauthFlowCookie,
		Value:    value,
		Path:     "/api/connections",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   b.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// oauthConfigFor builds a golang.org/x/oauth2 Config from a vendor's AuthConfig,
// decrypting the client secret via the vault. scopes is the exact set to
// request (already the union).
func (b *OAuthBroker) oauthConfigFor(ac store.AuthConfig, scopes []string) (oauth2.Config, error) {
	secret := ""
	if len(ac.EncryptedClientSecret) > 0 {
		pt, err := b.Vault.Decrypt(ac.EncryptedClientSecret)
		if err != nil {
			return oauth2.Config{}, fmt.Errorf("decrypt client secret for %s: %w", ac.Vendor, err)
		}
		secret = string(pt)
	}
	return oauth2.Config{
		ClientID:     ac.ClientID,
		ClientSecret: secret,
		Endpoint:     oauth2.Endpoint{AuthURL: ac.AuthorizeURL, TokenURL: ac.TokenURL},
		RedirectURL:  b.redirect,
		Scopes:       scopes,
	}, nil
}

// CallbackHandler — GET /api/connections/oauth/callback: validate the signed
// flow cookie + state, exchange the code at the vendor token endpoint (PKCE
// verifier), vault-encrypt the refresh + access tokens, persist the per-vendor
// Connected Account with the granted scopes, then 302 back to ReturnTo.
func (b *OAuthBroker) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(oauthFlowCookie)
	if err != nil {
		writeAuthError(w, http.StatusBadRequest, "oauth", "missing connect flow cookie (start again)")
		return
	}
	fs, err := b.verifyFlow(c.Value)
	if err != nil {
		log.Printf("WARN: oauth flow-cookie verify: %v", err)
		writeAuthError(w, http.StatusBadRequest, "oauth", "invalid or expired connect flow (start again)")
		return
	}
	if provErr := r.URL.Query().Get("error"); provErr != "" {
		log.Printf("WARN: oauth provider error=%q desc=%q", provErr, r.URL.Query().Get("error_description"))
		writeAuthError(w, http.StatusUnauthorized, "oauth", "the provider rejected or cancelled the connection")
		return
	}
	if r.URL.Query().Get("state") != fs.State {
		writeAuthError(w, http.StatusBadRequest, "oauth", "state mismatch")
		return
	}
	ac, err := b.Store.GetAuthConfig(r.Context(), fs.Vendor)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "load auth config")
		return
	}
	conf, err := b.oauthConfigFor(ac, fs.Scopes)
	if err != nil {
		log.Printf("ERROR: oauth callback config %s: %v", fs.Vendor, err)
		writeAuthError(w, http.StatusInternalServerError, "internal", "build oauth config")
		return
	}
	tok, err := conf.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(fs.Verifier))
	if err != nil {
		log.Printf("WARN: oauth code exchange %s: %v", fs.Vendor, err)
		writeAuthError(w, http.StatusBadGateway, "oauth", "code exchange failed")
		return
	}
	if tok.RefreshToken == "" {
		// Some providers omit a refresh token on re-consent; without one we
		// cannot refresh at resolve time, so reject rather than store a
		// short-lived dead connection.
		writeAuthError(w, http.StatusBadGateway, "oauth", "provider returned no refresh token (offline access required)")
		return
	}
	encRefresh, err := b.Vault.Encrypt([]byte(tok.RefreshToken))
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "encrypt refresh token")
		return
	}
	encAccess, err := b.Vault.Encrypt([]byte(tok.AccessToken))
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "encrypt access token")
		return
	}
	// granted_scopes: prefer the provider's returned "scope", else the request union.
	granted := fs.Scopes
	if s := tok.Extra("scope"); s != nil {
		if str, ok := s.(string); ok && str != "" {
			granted = unionScopes(strings.Fields(str))
		}
	}
	if err := b.Store.PutConnectedAccount(r.Context(), store.ConnectedAccount{
		UserID: fs.UserID, Vendor: fs.Vendor,
		EncryptedRefreshToken: encRefresh, EncryptedAccessToken: encAccess,
		ExpiresAt: tok.Expiry, GrantedScopes: granted,
	}); err != nil {
		log.Printf("ERROR: oauth store account %s user=%d: %v", fs.Vendor, fs.UserID, err)
		writeAuthError(w, http.StatusInternalServerError, "internal", "store connected account")
		return
	}
	http.SetCookie(w, b.setFlowCookie("", -1)) // clear the flow cookie
	dest := fs.ReturnTo
	if dest == "" {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// refreshSkew refreshes a token this long before its actual expiry so a
// just-resolved token does not expire mid-request.
const refreshSkew = 60 * time.Second

// EnsureFreshToken returns a currently-valid access token for (user, vendor),
// refreshing via the refresh-token grant when the cached token is expired or
// within refreshSkew of expiry, and persisting the rotated token. The returned
// string is the PLAINTEXT access token — the caller (resolver) hands it to the
// proxy as the bearer to inject; it never enters the sandbox.
func (b *OAuthBroker) EnsureFreshToken(ctx context.Context, userID int64, vendor string) (string, error) {
	acct, err := b.Store.GetConnectedAccount(ctx, userID, vendor)
	if err != nil {
		return "", err // includes store.ErrConnectedAccountNotFound
	}
	if b.now().Add(refreshSkew).Before(acct.ExpiresAt) {
		pt, err := b.Vault.Decrypt(acct.EncryptedAccessToken)
		if err != nil {
			return "", fmt.Errorf("decrypt cached access token: %w", err)
		}
		return string(pt), nil
	}
	// Expired/near-expiry → refresh.
	ac, err := b.Store.GetAuthConfig(ctx, vendor)
	if err != nil {
		return "", fmt.Errorf("auth config for refresh %s: %w", vendor, err)
	}
	conf, err := b.oauthConfigFor(ac, acct.GrantedScopes)
	if err != nil {
		return "", err
	}
	refreshPT, err := b.Vault.Decrypt(acct.EncryptedRefreshToken)
	if err != nil {
		return "", fmt.Errorf("decrypt refresh token: %w", err)
	}
	// TokenSource performs the refresh_token grant on demand.
	src := conf.TokenSource(ctx, &oauth2.Token{RefreshToken: string(refreshPT)})
	newTok, err := src.Token()
	if err != nil {
		return "", fmt.Errorf("refresh token grant %s: %w", vendor, err)
	}
	encAccess, err := b.Vault.Encrypt([]byte(newTok.AccessToken))
	if err != nil {
		return "", fmt.Errorf("encrypt refreshed access token: %w", err)
	}
	if err := b.Store.UpdateConnectedAccountTokens(ctx, userID, vendor, encAccess, newTok.Expiry); err != nil {
		// A failed cache update is non-fatal to THIS request (we still have a
		// valid token); log and proceed so a transient write error doesn't
		// break egress.
		log.Printf("WARN: persist refreshed token %s user=%d: %v", vendor, userID, err)
	}
	return newTok.AccessToken, nil
}

// StartHandler — GET /api/connections/oauth/start?vendor=…: redirect the user
// to the vendor authorize endpoint with state + PKCE and the scope union
// (vendor default_scopes ∪ the required manifest scopes the API layer passes).
// userID binds the flow to the initiating user; returnTo is where the callback
// sends the browser afterward (an in-app path).
func (b *OAuthBroker) StartHandler(w http.ResponseWriter, r *http.Request, userID int64, requiredScopes []string, returnTo string) {
	vendor := r.URL.Query().Get("vendor")
	if vendor == "" {
		writeAuthError(w, http.StatusBadRequest, "oauth", "missing vendor")
		return
	}
	ac, err := b.Store.GetAuthConfig(r.Context(), vendor)
	if err != nil {
		if errors.Is(err, store.ErrAuthConfigNotFound) {
			writeAuthError(w, http.StatusNotFound, "oauth", "no auth config for vendor (ask an admin to configure it)")
			return
		}
		writeAuthError(w, http.StatusInternalServerError, "internal", "load auth config")
		return
	}
	scopes := unionScopes(ac.DefaultScopes, requiredScopes)
	conf, err := b.oauthConfigFor(ac, scopes)
	if err != nil {
		log.Printf("ERROR: oauth start config %s: %v", vendor, err)
		writeAuthError(w, http.StatusInternalServerError, "internal", "build oauth config")
		return
	}
	state, err := randB64(16)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "entropy unavailable")
		return
	}
	pkce := oauth2.GenerateVerifier()
	signed, err := b.signFlow(oauthFlowState{
		State: state, Verifier: pkce, Vendor: vendor, UserID: userID,
		ReturnTo: returnTo, Scopes: scopes,
		Expires: b.now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "sign connect flow")
		return
	}
	http.SetCookie(w, b.setFlowCookie(signed, 600))
	authURL := conf.AuthCodeURL(state,
		oauth2.AccessTypeOffline, // request a refresh token
		oauth2.S256ChallengeOption(pkce),
		oauth2.SetAuthURLParam("prompt", "consent")) // force re-consent for incremental scopes
	http.Redirect(w, r, authURL, http.StatusFound)
}
