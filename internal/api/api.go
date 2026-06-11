// Package api is the REST control plane: JSON endpoints behind the
// session middleware, mounted under /api/ on the gateway's single mux. It
// imports auth and registry, never gateway (ProfileInvalidator decouples it
// from the ProfileHost).
package api

import (
	"net/http"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/registry"
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
	Store     store.Store
	Vault     *vault.Vault
	Auth      *auth.Authenticator // nil = OIDC unconfigured (auth routes unmounted)
	Broker    *auth.OAuthBroker   // nil = OAuth connect routes return 501
	Installer registry.Installer  // nil = fall back to Store.ListServers for GET /api/servers; install/uninstall return 501 (nil-guarded in handlers)
	Registry  IndexFetcher        // nil = registry unconfigured; GET /api/registry/servers returns 501 (nil-guarded in handler)
	Profiles  ProfileInvalidator

	regCache indexCache // 5-minute memo of the verified registry index (registry.go)
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
	authed.HandleFunc("GET /api/overview", s.handleOverview)
	authed.HandleFunc("GET /api/apps", s.handleListApps)
	authed.HandleFunc("GET /api/apps/{name}", s.handleGetApp)
	authed.Handle("PUT /api/apps/{name}/tools/{tool}", auth.RequireAdmin(http.HandlerFunc(s.handleSetAppTool)))
	authed.HandleFunc("GET /api/profiles", s.handleListProfiles)
	authed.HandleFunc("POST /api/profiles", s.handleCreateProfile)
	authed.HandleFunc("GET /api/profiles/{id}", s.handleGetProfile)
	authed.HandleFunc("PATCH /api/profiles/{id}", s.handlePatchProfile)
	authed.HandleFunc("DELETE /api/profiles/{id}", s.handleDeleteProfile)
	authed.HandleFunc("PUT /api/profiles/{id}/servers", s.handlePutProfileServers)
	authed.HandleFunc("POST /api/profiles/{id}/token", s.handleRotateProfileToken)
	authed.HandleFunc("GET /api/credentials", s.handleListCredentials)
	authed.HandleFunc("PUT /api/credentials/{server}", s.handlePutCredential)
	authed.HandleFunc("DELETE /api/credentials/{server}", s.handleDeleteCredential)
	authed.HandleFunc("GET /api/servers", s.handleListServers)
	authed.HandleFunc("GET /api/registry/servers", s.handleRegistryServers)
	authed.Handle("POST /api/servers/install", auth.RequireAdmin(http.HandlerFunc(s.handleInstallServer)))
	authed.Handle("DELETE /api/servers/{name}", auth.RequireAdmin(http.HandlerFunc(s.handleUninstallServer)))
	authed.Handle("GET /api/users", auth.RequireAdmin(http.HandlerFunc(s.handleListUsers)))
	authed.Handle("POST /api/admin/impersonate", auth.RequireAdmin(http.HandlerFunc(s.handleStartImpersonation)))
	authed.Handle("DELETE /api/admin/impersonate", auth.RequireAdmin(http.HandlerFunc(s.handleStopImpersonation)))
	authed.HandleFunc("GET /api/audit", s.handleListAudit)
	authed.Handle("GET /api/auth-configs", auth.RequireAdmin(http.HandlerFunc(s.handleListAuthConfigs)))
	authed.Handle("PUT /api/auth-configs/{vendor}", auth.RequireAdmin(http.HandlerFunc(s.handlePutAuthConfig)))
	authed.Handle("DELETE /api/auth-configs/{vendor}", auth.RequireAdmin(http.HandlerFunc(s.handleDeleteAuthConfig)))
	authed.HandleFunc("GET /api/connections", s.handleListConnections)
	authed.HandleFunc("GET /api/connections/oauth/start", s.handleOAuthStart)
	authed.HandleFunc("GET /api/connections/oauth/callback", s.handleOAuthCallback)
	authed.HandleFunc("DELETE /api/connections/{vendor}", s.handleDisconnect)

	mux := http.NewServeMux()
	if s.Auth != nil {
		mux.HandleFunc("GET /api/auth/login", s.Auth.LoginHandler)
		mux.HandleFunc("GET /api/auth/callback", s.Auth.CallbackHandler)
		mux.HandleFunc("POST /api/auth/logout", s.Auth.LogoutHandler)
	}
	mux.Handle("/api/", auth.SessionMiddleware(s.Store, envelopeMux(authed)))
	return mux
}
