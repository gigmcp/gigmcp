// Package api is the REST control plane (spec §5): JSON endpoints behind the
// session middleware, mounted under /api/ on the gateway's single mux. It
// imports auth and registry, never gateway (ProfileInvalidator decouples it
// from the ProfileHost).
package api

import (
	"net/http"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// ProfileInvalidator tears down a profile's MCP runtime after a mutation.
// Implemented by *gateway.ProfileHost (declared locally to avoid an
// api→gateway import). May be nil in tests.
type ProfileInvalidator interface {
	Invalidate(profileID int64)
}

// Server holds the control-plane dependencies.
type Server struct {
	Store    store.Store
	Vault    *vault.Vault
	Auth     *auth.Authenticator // nil = OIDC unconfigured (auth routes unmounted)
	Profiles ProfileInvalidator
}

// invalidate is a nil-safe ProfileInvalidator call.
func (s *Server) invalidate(profileID int64) {
	if s.Profiles != nil {
		s.Profiles.Invalidate(profileID)
	}
}

// Routes builds the /api mux: /api/auth/* is unauthenticated (it IS the
// authentication); everything else runs behind SessionMiddleware. Go 1.22+
// ServeMux precedence makes the specific auth patterns win over "/api/".
func (s *Server) Routes() *http.ServeMux {
	authed := http.NewServeMux()
	authed.HandleFunc("GET /api/me", s.handleMe)

	mux := http.NewServeMux()
	if s.Auth != nil {
		mux.HandleFunc("GET /api/auth/login", s.Auth.LoginHandler)
		mux.HandleFunc("GET /api/auth/callback", s.Auth.CallbackHandler)
		mux.HandleFunc("POST /api/auth/logout", s.Auth.LogoutHandler)
	}
	mux.Handle("/api/", auth.SessionMiddleware(s.Store, authed))
	return mux
}
