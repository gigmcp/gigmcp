package main

import (
	"net/http"

	"github.com/gigmcp/gigmcp/internal/api"
	"github.com/gigmcp/gigmcp/internal/auth"
	gw "github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/registry"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// buildMux assembles the single :8080 mux:
//
//	/mcp/p/     → ProfileHost (per-profile bearer tokens)
//	/api/       → REST control plane (OIDC sessions; a descriptive 404 when
//	              OIDC is unconfigured)
//
// The canonical MCP client endpoint is /mcp/p/<slug>. The legacy
// single-tenant "/mcp" path and the "/" catch-all were retired at the auth
// cutover; everything else (including "/") 404s via ServeMux's default
// not-found behavior.
//
// NOTE: ServeMux paths are case-sensitive — /API/* is NOT matched by "/api/"
// and 404s. The web-container proxy must pass lowercase paths.
//
// Kept as the one run() helper so future run() additions merge cleanly.
func buildMux(
	st store.Store,
	v *vault.Vault,
	authn *auth.Authenticator, // nil = OIDC unconfigured, /api answers control_plane_disabled
	broker *auth.OAuthBroker, // nil = OAuth connect routes return 501
	installer registry.Installer, // may be nil (list falls back to store, mutates 502)
	regClient *registry.Client, // nil = registry unconfigured (/api/registry/servers → 501)
	profiles *gw.ProfileHost,
) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/mcp/p/", profiles.Handler())
	if authn != nil {
		apiSrv := &api.Server{Store: st, Vault: v, Auth: authn, Broker: broker, Installer: installer, Profiles: profiles}
		if regClient != nil {
			// Assign only when non-nil so the api.Server nil-guard sees a nil
			// interface, not a typed-nil *registry.Client.
			apiSrv.Registry = regClient
		}
		mux.Handle("/api/", apiSrv.Routes())
	} else {
		// When OIDC is not configured the control-plane API is disabled.
		// Return a descriptive 404 so operators know which env vars to set,
		// rather than returning an opaque default 404.
		mux.Handle("/api/", disabledAPIHandler())
	}
	return mux
}

// disabledAPIHandler returns a handler that responds 404 with a JSON body
// explaining which environment variables enable the control plane.
func disabledAPIHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error":{"code":"control_plane_disabled","message":"control plane disabled: set GIG_OIDC_ISSUER, GIG_OIDC_CLIENT_ID, GIG_OIDC_REDIRECT_URL"}}` + "\n"))
	})
}
