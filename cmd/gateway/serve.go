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
//	/mcp        → legacy aggregator + RequireBearer (transitional until cutover)
//	/mcp/p/     → ProfileHost (per-profile bearer tokens)
//	/api/       → REST control plane (only when OIDC is configured)
//	/           → legacy fallback (same handler as /mcp — preserves the README
//	              documented endpoint "http://localhost:8080" until cutover)
//
// Go 1.22+ ServeMux uses path-specificity: "/mcp/p/" and "/api/" are more
// specific than "/mcp" (exact) which in turn takes precedence over "/" (the
// catch-all). Verify with the serve_test.go routing assertions.
//
// NOTE: ServeMux paths are case-sensitive — /API/* is NOT matched by "/api/"
// and falls to the "/" catch-all (legacy handler). The web-container proxy
// must pass lowercase paths; uppercase paths will silently hit legacy.
//
// T18 cutover note: /mcp is an exact-match pattern; /mcp/ and all sub-paths
// ride the "/" catch-all today. At Task 18 both "/mcp" and "/" are removed;
// the canonical client endpoint becomes /mcp/p/<slug>.
//
// At Task 18 cutover: "/mcp" and "/" mounts are BOTH removed, the canonical
// client endpoint becomes /mcp/p/<slug>, and README.md must be updated
// (see Task 18 Step 3a).
//
// Kept as the one run() helper so future run() additions merge cleanly.
func buildMux(
	st store.Store,
	v *vault.Vault,
	authn *auth.Authenticator, // nil = OIDC unconfigured, /api unmounted
	installer registry.Installer, // may be nil (list falls back to store, mutates 502)
	profiles *gw.ProfileHost,
	legacy http.Handler,
) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/mcp", legacy)
	// "/" is the catch-all fallback: it catches the bare "http://localhost:8080"
	// that the README documents (claude mcp add … http://localhost:8080).
	// /mcp/p/ and /api/ take precedence by ServeMux specificity, so this
	// fallback only fires for paths not otherwise matched, keeping backward
	// compatibility until Task 18 cutover.
	mux.Handle("/", legacy)
	mux.Handle("/mcp/p/", profiles.Handler())
	if authn != nil {
		apiSrv := &api.Server{Store: st, Vault: v, Auth: authn, Installer: installer, Profiles: profiles}
		mux.Handle("/api/", apiSrv.Routes())
	} else {
		// When OIDC is not configured the control-plane API is disabled.
		// Return a descriptive 404 so operators know which env vars to set,
		// rather than falling through to the "/" catch-all legacy handler.
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
