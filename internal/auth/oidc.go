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
		adminRole:  cfg.OIDCAdminRole,
		sessionTTL: cfg.SessionTTL,
		secure:     strings.HasPrefix(cfg.PublicURL, "https://"),
		hmacKey:    key,
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
	uid := user.ID
	if err := a.Store.AppendAudit(r.Context(), store.AuditEvent{
		Kind: "auth", UserID: &uid, Decision: "login", Detail: user.Email,
	}); err != nil {
		log.Printf("WARN: audit login: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// LogoutHandler — POST /api/auth/logout: delete the session row, clear the
// cookie. Local logout only (RP-initiated Zitadel logout is a follow-up).
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
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
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
