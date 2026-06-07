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

// buildMux assembles the single :8080 mux (spec §2):
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
// At Task 18 cutover: "/mcp" and "/" mounts are BOTH removed, the canonical
// client endpoint becomes /mcp/p/<slug>, and README.md must be updated
// (see Task 18 Step 3a).
//
// Kept as the one run() helper so the registry workstream's run() additions
// merge cleanly (handoff §6.2).
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
		// Mount a 404 handler so /api/* requests get a clean 404 rather than
		// falling through to the "/" catch-all legacy handler.
		mux.Handle("/api/", http.NotFoundHandler())
	}
	return mux
}
