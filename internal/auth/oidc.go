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
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/gigmcp/gigmcp/internal/config"
	"github.com/gigmcp/gigmcp/internal/store"
)

// RolesClaim is Zitadel's project-roles ID-token claim: a map of
// role-key → {orgID: orgDomain}. Membership of the configured admin role key
// maps to gigmcp role "admin".
const RolesClaim = "urn:zitadel:iam:org:project:roles"

// flowCookie carries state+nonce+PKCE verifier between login and callback.
const flowCookie = "gig_oidc_flow"

// idTokenCookie holds the raw, Zitadel-signed id_token captured at login. It is
// used solely as the id_token_hint for RP-initiated (single) logout. It is
// scoped to Path "/api/auth/logout" so the browser only ever transmits it to
// the logout endpoint — never anywhere else, minimizing exposure. The value is
// already a signed JWT, so it needs no additional HMAC from us.
const idTokenCookie = "gig_idt"

// Authenticator drives the OIDC authorization-code+PKCE flow and issues
// opaque DB sessions. Zitadel is the sole IdP (generic OIDC client; social
// login is federated inside Zitadel).
type Authenticator struct {
	Store      store.Store
	verifier   *oidc.IDTokenVerifier
	oauth      oauth2.Config
	adminRole  string
	sessionTTL time.Duration
	secure     bool // Secure cookie flag: true iff GIG_PUBLIC_URL is https
	// endSessionEndpoint is the IdP's RP-initiated logout endpoint, discovered
	// from the OIDC discovery document. OPTIONAL per the OIDC spec — an empty
	// string means the provider does not support RP-initiated logout, in which
	// case LogoutHandler falls back to local-only logout.
	endSessionEndpoint string
	// postLogoutRedirectURL is where the IdP returns the browser after a
	// successful RP-initiated logout (GIG_OIDC_POST_LOGOUT_REDIRECT_URL). Empty
	// means we omit post_logout_redirect_uri and let the IdP use its default.
	postLogoutRedirectURL string
	// hmacKey signs the transient flow cookie. Random per process: in-flight
	// logins do NOT survive a gateway restart (acceptable — users just retry),
	// and are replica-local; this assumes a single gateway instance (SQLite
	// single-listener architecture).
	hmacKey []byte
}

// NewAuthenticator runs OIDC discovery against cfg.OIDCIssuer and builds the
// flow. Call only when cfg.OIDCEnabled().
func NewAuthenticator(ctx context.Context, cfg config.Config, st store.Store) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.OIDCIssuer, err)
	}
	// Pull end_session_endpoint out of the same discovery document. It is
	// OPTIONAL in OIDC discovery: an empty string is valid and simply means the
	// provider does not advertise RP-initiated logout (handled in LogoutHandler).
	var disc struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}
	if err := provider.Claims(&disc); err != nil {
		return nil, fmt.Errorf("oidc discovery claims: %w", err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &Authenticator{
		Store:    st,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret, // empty for PKCE public clients
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.OIDCRedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		adminRole:             cfg.OIDCAdminRole,
		sessionTTL:            cfg.SessionTTL,
		secure:                strings.HasPrefix(cfg.PublicURL, "https://"),
		endSessionEndpoint:    disc.EndSessionEndpoint,
		postLogoutRedirectURL: cfg.OIDCPostLogoutRedirectURL,
		hmacKey:               key,
	}, nil
}

// flowState is the signed payload of the 10-minute flow cookie — no DB row
// for pending logins. The flow cookie is stateless, so a valid
// signed cookie can be replayed within the 10-minute window; the auth code
// it carries is single-use at the IdP, bounding actual exploit to a
// narrow race with no persistent account gain.
type flowState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"` // PKCE code verifier
	Expires  int64  `json:"expires"`  // unix seconds
}

func randB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Authenticator) signFlow(fs flowState) (string, error) {
	payload, err := json.Marshal(fs)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, a.hmacKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (a *Authenticator) verifyFlow(v string) (flowState, error) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return flowState{}, errors.New("malformed flow cookie")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return flowState{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return flowState{}, err
	}
	mac := hmac.New(sha256.New, a.hmacKey)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return flowState{}, errors.New("bad flow cookie signature")
	}
	var fs flowState
	if err := json.Unmarshal(payload, &fs); err != nil {
		return flowState{}, err
	}
	if time.Now().Unix() > fs.Expires {
		return flowState{}, errors.New("login flow expired")
	}
	return fs, nil
}

func (a *Authenticator) setFlowCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: flowCookie, Value: value, Path: "/api/auth", MaxAge: maxAge,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	}
}

// LoginHandler — GET /api/auth/login: 302 to the IdP's authorize endpoint
// with state + nonce + PKCE S256 challenge; the verifier travels only in the
// signed flow cookie.
func (a *Authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randB64(16)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "entropy unavailable")
		return
	}
	nonce, err := randB64(16)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "entropy unavailable")
		return
	}
	pkce := oauth2.GenerateVerifier()
	signed, err := a.signFlow(flowState{
		State: state, Nonce: nonce, Verifier: pkce,
		Expires: time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "sign login flow")
		return
	}
	http.SetCookie(w, a.setFlowCookie(signed, 600))
	opts := []oauth2.AuthCodeOption{oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)}
	// ?prompt=create deep-links to the IdP registration page, so the UI can offer a
	// separate "Sign up" link distinct from "Log in". Any other prompt value is ignored.
	if r.URL.Query().Get("prompt") == "create" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "create"))
	}
	http.Redirect(w, r, a.oauth.AuthCodeURL(state, opts...), http.StatusFound)
}

// CallbackHandler — GET /api/auth/callback: state check, code exchange
// (PKCE verifier), ID-token verification (signature, issuer, audience,
// nonce), role mapping, JIT user upsert, session issuance, 302 "/".
func (a *Authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		writeAuthError(w, http.StatusBadRequest, "oidc", "missing login flow cookie (login again)")
		return
	}
	fs, err := a.verifyFlow(c.Value)
	if err != nil {
		log.Printf("WARN: oidc flow-cookie verify: %v", err)
		writeAuthError(w, http.StatusBadRequest, "oidc", "invalid or expired login flow (try logging in again)")
		return
	}
	// I2: RFC 6749 §4.1.2.1 — provider may return error= instead of code=.
	if provErr := r.URL.Query().Get("error"); provErr != "" {
		log.Printf("WARN: oidc provider returned error=%q description=%q", provErr, r.URL.Query().Get("error_description"))
		writeAuthError(w, http.StatusUnauthorized, "oidc", "login was cancelled or rejected by the identity provider")
		return
	}
	if r.URL.Query().Get("state") != fs.State {
		writeAuthError(w, http.StatusBadRequest, "oidc", "state mismatch")
		return
	}
	tok, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(fs.Verifier))
	if err != nil {
		log.Printf("WARN: oidc code exchange: %v", err)
		writeAuthError(w, http.StatusBadGateway, "oidc", "code exchange failed")
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		writeAuthError(w, http.StatusBadGateway, "oidc", "token response had no id_token")
		return
	}
	idt, err := a.verifier.Verify(r.Context(), rawID)
	if err != nil {
		log.Printf("WARN: oidc id_token verify: %v", err)
		writeAuthError(w, http.StatusUnauthorized, "oidc", "id_token verification failed")
		return
	}
	if idt.Nonce != fs.Nonce {
		writeAuthError(w, http.StatusUnauthorized, "oidc", "nonce mismatch")
		return
	}
	var claims struct {
		Email string         `json:"email"`
		Name  string         `json:"name"`
		Roles map[string]any `json:"urn:zitadel:iam:org:project:roles"`
	}
	if err := idt.Claims(&claims); err != nil {
		writeAuthError(w, http.StatusBadGateway, "oidc", "parse id_token claims")
		return
	}
	role := MapRole(claims.Roles, a.adminRole)
	// Guard: MapRole must only ever produce "admin" or "user". If a future
	// mapping change produces anything else, fail loudly at login with a clear
	// log rather than silently hitting the DB CHECK constraint as a 500.
	if role != "admin" && role != "user" {
		log.Printf("ERROR: MapRole produced unexpected role %q for subject %s; rejecting login", role, idt.Subject)
		writeAuthError(w, http.StatusInternalServerError, "internal", "invalid role mapping")
		return
	}
	user, err := a.Store.UpsertUserByOIDC(r.Context(), idt.Issuer, idt.Subject, claims.Email, claims.Name, role)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "provision user")
		return
	}
	sessionToken, err := NewSessionToken()
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "entropy unavailable")
		return
	}
	if err := a.Store.CreateSession(r.Context(), HashToken(sessionToken), user.ID, time.Now().Add(a.sessionTTL)); err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "create session")
		return
	}
	http.SetCookie(w, a.setFlowCookie("", -1)) // clear the flow cookie
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: sessionToken, Path: "/",
		MaxAge:   int(a.sessionTTL / time.Second),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
	// Stash the raw id_token for use as the id_token_hint on RP-initiated
	// logout. Scoped to the logout path only — see idTokenCookie's doc comment.
	http.SetCookie(w, &http.Cookie{
		Name: idTokenCookie, Value: rawID, Path: "/api/auth/logout",
		MaxAge:   int(a.sessionTTL / time.Second),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
	uid := user.ID
	if err := a.Store.AppendAudit(r.Context(), store.AuditEvent{
		Kind: "auth", UserID: &uid, Decision: "login", Detail: user.Email,
	}); err != nil {
		log.Printf("WARN: audit login: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// LogoutHandler — POST /api/auth/logout: delete the session row and clear both
// the session and id_token cookies. When the IdP advertises an
// end_session_endpoint and we still hold the id_token, it ALSO returns an
// RP-initiated logout URL as JSON so the frontend can navigate the browser to
// Zitadel and end the IdP session too (single logout). Without that — no
// end_session endpoint, no id_token, or a malformed endpoint — it falls back to
// the previous behavior and returns 204 (the frontend then redirects locally).
func (a *Authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		hash := HashToken(c.Value)
		if sess, err := a.Store.GetSession(r.Context(), hash); err == nil {
			uid := sess.UserID
			if err := a.Store.AppendAudit(r.Context(), store.AuditEvent{
				Kind: "auth", UserID: &uid, Decision: "logout",
			}); err != nil {
				log.Printf("WARN: audit logout: %v", err)
			}
		}
		if err := a.Store.DeleteSession(r.Context(), hash); err != nil {
			log.Printf("WARN: delete session: %v", err)
		}
	}
	// Read the id_token before clearing its cookie — it's the id_token_hint.
	var idToken string
	if c, err := r.Cookie(idTokenCookie); err == nil {
		idToken = c.Value
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
	// Clear the id_token cookie. Path MUST match the one it was set with
	// ("/api/auth/logout"), or the browser will not remove it.
	http.SetCookie(w, &http.Cookie{
		Name: idTokenCookie, Value: "", Path: "/api/auth/logout", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
	// Build the RP-initiated logout URL when we can. Any failure falls through
	// to the local-only 204 below.
	if a.endSessionEndpoint != "" && idToken != "" {
		if u, err := url.Parse(a.endSessionEndpoint); err != nil {
			log.Printf("WARN: parse end_session_endpoint %q: %v", a.endSessionEndpoint, err)
		} else {
			q := u.Query()
			q.Set("id_token_hint", idToken)
			if a.postLogoutRedirectURL != "" {
				q.Set("post_logout_redirect_uri", a.postLogoutRedirectURL)
			}
			// Some providers require client_id alongside the hint.
			q.Set("client_id", a.oauth.ClientID)
			u.RawQuery = q.Encode()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if err := json.NewEncoder(w).Encode(map[string]string{"logout_url": u.String()}); err != nil {
				log.Printf("WARN: write logout url: %v", err)
			}
			return
		}
	}
	// Local-only logout: the provider advertises no end_session_endpoint, the
	// id_token cookie was absent/expired, or the endpoint failed to parse. The
	// gateway session is gone but the IdP session may persist — log it so an
	// operator can tell "still logged into Zitadel" from a gateway bug.
	if a.endSessionEndpoint == "" {
		log.Printf("INFO: logout: no end_session_endpoint advertised; local-only logout")
	} else if idToken == "" {
		log.Printf("INFO: logout: no id_token cookie; local-only logout")
	}
	w.WriteHeader(http.StatusNoContent)
}

// MapRole maps the Zitadel roles claim to a gigmcp role: "admin" iff the
// claim map contains the configured admin role key. Refreshed every login —
// roles are a cache of IdP state, never edited locally.
func MapRole(roles map[string]any, adminRole string) string {
	if _, ok := roles[adminRole]; ok {
		return "admin"
	}
	return "user"
}
