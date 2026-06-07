// Package auth owns gigmcp authentication: opaque session + profile tokens,
// the OIDC login flow (oidc.go), the session/impersonation middleware, and
// RBAC. The Go gateway is the sole auth authority (DESIGN #18); Next.js only
// forwards the cookie.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gigmcp/gigmcp/internal/store"
)

// SessionCookie is the browser session cookie name.
const SessionCookie = "gig_session"

// NewSessionToken returns a fresh opaque session token: 32 random bytes,
// base64url unpadded (43 chars). Only its SHA-256 is stored.
func NewSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewProfileToken returns a fresh profile bearer token: "gig_" + 32 random
// bytes base64url. The prefix makes leaked tokens greppable. Plaintext is
// shown once at create/rotate; only the SHA-256 is stored.
func NewProfileToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "gig_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the hex SHA-256 of a token — the at-rest form for both
// session and profile tokens.
func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

type ctxKey int

const (
	realUserKey ctxKey = iota
	effectiveUserKey
	sessionHashKey
	impersonatingKey
)

// RealUser returns the authenticated user (the admin, during impersonation).
func RealUser(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(realUserKey).(store.User)
	return u, ok
}

// EffectiveUser returns the user requests should resolve against (the
// impersonation target while view-as is active, else the real user).
func EffectiveUser(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(effectiveUserKey).(store.User)
	return u, ok
}

// IsImpersonating reports whether view-as mode is active on this request.
func IsImpersonating(ctx context.Context) bool {
	v, _ := ctx.Value(impersonatingKey).(bool)
	return v
}

// SessionTokenHash returns the hash of the current session token (used by
// the impersonation handlers to stamp the session row, and by logout).
func SessionTokenHash(ctx context.Context) (string, bool) {
	h, ok := ctx.Value(sessionHashKey).(string)
	return h, ok
}

// writeAuthError mirrors internal/api's {"error":{"code","message"}}
// envelope. Deliberately duplicated (a handful of lines) so auth does not
// import api and api can import auth.
func writeAuthError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	}); err != nil {
		log.Printf("WARN: write auth error: %v", err)
	}
}

// stopImpersonationPath is the one mutation allowed while impersonating.
const stopImpersonationPath = "/api/admin/impersonate"

// NOTE: an impersonating admin CANNOT switch targets without stopping first.
// POST /api/admin/impersonate is itself a mutation, so the guard below blocks
// it while view-as is active (the admin must DELETE first). This is intentional
// — do not "fix" it.

// impersonationSafeMethod reports whether method is read-only (GET or HEAD).
// OPTIONS is excluded — /api serves no CORS preflight today.
func impersonationSafeMethod(method string) bool {
	return method == http.MethodGet || method == http.MethodHead
}

// SessionMiddleware authenticates by the gig_session cookie, loads the real
// and effective users into the context, and enforces the view-as rule:
// while impersonating, every non-GET/HEAD request is 403 except
// DELETE /api/admin/impersonate (DESIGN #20: view-as is read-only).
func SessionMiddleware(st store.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil || c.Value == "" {
			writeAuthError(w, http.StatusUnauthorized, "unauthenticated", "missing session cookie")
			return
		}
		hash := HashToken(c.Value)
		sess, err := st.GetSession(r.Context(), hash)
		if err != nil {
			if errors.Is(err, store.ErrSessionNotFound) {
				writeAuthError(w, http.StatusUnauthorized, "unauthenticated", "invalid or expired session")
			} else {
				log.Printf("ERROR: get session: %v", err)
				writeAuthError(w, http.StatusInternalServerError, "internal", "internal error")
			}
			return
		}
		real, err := st.GetUser(r.Context(), sess.UserID)
		if err != nil {
			if errors.Is(err, store.ErrUserNotFound) {
				writeAuthError(w, http.StatusUnauthorized, "unauthenticated", "invalid session")
			} else {
				log.Printf("ERROR: get session user %d: %v", sess.UserID, err)
				writeAuthError(w, http.StatusInternalServerError, "internal", "internal error")
			}
			return
		}
		effective := real
		impersonating := false
		if sess.ImpersonatingUserID != nil && sess.ImpersonationExpiresAt != nil &&
			time.Now().Before(*sess.ImpersonationExpiresAt) {
			target, err := st.GetUser(r.Context(), *sess.ImpersonatingUserID)
			if err == nil {
				effective = target
				impersonating = true
			} else if errors.Is(err, store.ErrUserNotFound) {
				log.Printf("WARN: impersonation target %d gone; proceeding as real user", *sess.ImpersonatingUserID)
				// proceed un-impersonated (effective = real, impersonating = false)
			} else {
				log.Printf("ERROR: get impersonation target %d: %v", *sess.ImpersonatingUserID, err)
				writeAuthError(w, http.StatusInternalServerError, "internal", "internal error")
				return
			}
		}
		if impersonating && !impersonationSafeMethod(r.Method) &&
			!(r.Method == http.MethodDelete && r.URL.Path == stopImpersonationPath) {
			writeAuthError(w, http.StatusForbidden, "impersonating",
				"mutations are blocked while impersonating (view-as is read-only)")
			return
		}
		ctx := context.WithValue(r.Context(), realUserKey, real)
		ctx = context.WithValue(ctx, effectiveUserKey, effective)
		ctx = context.WithValue(ctx, sessionHashKey, hash)
		ctx = context.WithValue(ctx, impersonatingKey, impersonating)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin gates a handler on the REAL user's role, so an admin keeps
// admin endpoints while impersonating (needed to stop view-as) and a
// non-admin can never gain them.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := RealUser(r.Context())
		if !ok || u.Role != "admin" {
			writeAuthError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
