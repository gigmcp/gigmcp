package api

import (
	"errors"
	"log"
	"net/http"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// appAuthType derives the connect-flow auth type from a manifest's first
// injection. No credentials declared → "none" (credential-less / public-API
// app). The dashboard maps this to the badge + connect block.
func appAuthType(rec store.ManifestRecord) string {
	if len(rec.Injections) == 0 {
		return "none"
	}
	if t := rec.Injections[0].Type; t != "" {
		return t
	}
	// A manifest with an injection but no declared type is treated as api_key
	// (a header/format injection with a static secret) — the safe P1 default.
	return "api_key"
}

// appSummaryJSON is one card in GET /api/apps.
type appSummaryJSON struct {
	Name        string `json:"name"`         // slug
	DisplayName string `json:"display_name"` // manifest branding; falls back to the slug when unbranded
	Category    string `json:"category"`     // manifest branding; "" when the manifest omits it
	AuthType    string `json:"auth_type"`    // oauth2 | api_key | basic | custom_env | none
	Connected   bool   `json:"connected"`    // user has a credential for this app
	Version     string `json:"version"`
}

// appDetailJSON is GET /api/apps/{name}.
type appDetailJSON struct {
	Name         string        `json:"name"`
	DisplayName  string        `json:"display_name"`
	Category     string        `json:"category"`
	Description  string        `json:"description"` // manifest branding; "" when the manifest omits it
	AuthType     string        `json:"auth_type"`
	Provider     string        `json:"provider"`
	Vendor       string        `json:"vendor"` // canonical OAuth grouping key; == Provider for un-backfilled manifests
	Scopes       []string      `json:"scopes"`
	Connected    bool          `json:"connected"`
	Version      string        `json:"version"`
	AllowedHosts []string      `json:"allowed_hosts"`
	Tools        []appToolJSON `json:"tools"`
	InjectHeader string        `json:"inject_header"` // for the api_key/basic connect form hint
	InjectFormat string        `json:"inject_format"`
	Placeholder  string        `json:"placeholder"`
}

type appToolJSON struct {
	Name    string `json:"name"`
	Default bool   `json:"default"` // informational: the manifest's curated-default flag
	Enabled bool   `json:"enabled"` // effective state: exposed unless an admin disabled it
}

// handleListApps — GET /api/apps: installed apps for everyone, each annotated
// with its auth type and whether the effective user has connected it.
func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	ctx := r.Context()
	srvs, err := s.Store.ListServers(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "list apps")
		return
	}
	creds, err := s.Store.ListCredentialsByTenant(ctx, store.UserTenant(user.ID))
	if err != nil {
		log.Printf("ERROR: handleListApps ListCredentialsByTenant user=%d: %v", user.ID, err)
		writeErr(w, http.StatusInternalServerError, codeInternal, "list apps")
		return
	}
	connected := make(map[string]bool, len(creds))
	for _, c := range creds {
		connected[c.Server] = true
	}

	out := make([]appSummaryJSON, 0, len(srvs))
	for _, srv := range srvs {
		authType := "none"
		version := ""
		displayName := srv.Name // fall back to the slug when unbranded
		category := ""
		if rec, err := s.Store.GetManifest(ctx, srv.Name); err == nil {
			authType = appAuthType(rec)
			version = rec.Version
			if rec.DisplayName != "" {
				displayName = rec.DisplayName
			}
			category = rec.Category
		} else if !errors.Is(err, store.ErrManifestNotFound) {
			log.Printf("WARN: handleListApps GetManifest %s: %v", srv.Name, err)
		}
		out = append(out, appSummaryJSON{
			Name: srv.Name, DisplayName: displayName, Category: category,
			AuthType: authType, Connected: connected[srv.Name], Version: version,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

// handleGetApp — GET /api/apps/{name}: detail for one installed app.
func (s *Server) handleGetApp(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	name := r.PathValue("name")
	if msg := validateServerName(name); msg != "" {
		writeErr(w, http.StatusBadRequest, codeInvalid, msg)
		return
	}
	ctx := r.Context()

	rec, err := s.Store.GetManifest(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrManifestNotFound) {
			writeErr(w, http.StatusNotFound, codeNotFound, "app not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, codeInternal, "load app")
		return
	}

	// Tools are enabled by default; an admin-disabled set subtracts from that.
	disabled, err := s.Store.ListDisabledTools(ctx, name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "load app")
		return
	}
	dset := make(map[string]bool, len(disabled))
	for _, d := range disabled {
		dset[d] = true
	}
	tools := make([]appToolJSON, 0, len(rec.Tools))
	for _, tl := range rec.Tools {
		tools = append(tools, appToolJSON{Name: tl.Name, Default: tl.Default, Enabled: !dset[tl.Name]})
	}
	hosts := rec.AllowedHosts
	if hosts == nil {
		hosts = []string{}
	}

	var inj store.Injection
	if len(rec.Injections) > 0 {
		inj = rec.Injections[0]
	}

	_, credErr := s.Store.GetCredential(ctx, name, store.UserTenant(user.ID))
	connected := credErr == nil

	scopes := inj.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	// Canonical OAuth vendor; fall back to the per-connector provider for
	// un-backfilled manifests so the connect block always has a grouping key.
	vendor := inj.Vendor
	if vendor == "" {
		vendor = inj.Provider
	}

	// Persisted branding; fall back to the slug for an un-backfilled display name.
	displayName := rec.DisplayName
	if displayName == "" {
		displayName = name
	}

	writeJSON(w, http.StatusOK, appDetailJSON{
		Name: name, DisplayName: displayName, Category: rec.Category, Description: rec.Description,
		AuthType: appAuthType(rec), Provider: inj.Provider, Vendor: vendor, Scopes: scopes,
		Connected: connected, Version: rec.Version, AllowedHosts: hosts, Tools: tools,
		InjectHeader: inj.Header, InjectFormat: inj.Format, Placeholder: inj.Placeholder,
	})
}

// handleSetAppTool — PUT /api/apps/{name}/tools/{tool}: admin-only per-app
// toggle. Body {"enabled": bool}. enabled=false disables the tool for the app
// (persists across re-install); enabled=true re-enables it. The route is
// wrapped in auth.RequireAdmin, so RBAC is enforced before this runs.
func (s *Server) handleSetAppTool(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if msg := validateServerName(name); msg != "" {
		writeErr(w, http.StatusBadRequest, codeInvalid, msg)
		return
	}
	tool := r.PathValue("tool")
	ctx := r.Context()

	rec, err := s.Store.GetManifest(ctx, name)
	if err != nil {
		if errors.Is(err, store.ErrManifestNotFound) {
			writeErr(w, http.StatusNotFound, codeNotFound, "app not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, codeInternal, "load app")
		return
	}

	// Only tools declared by the app's manifest may be toggled — disabling an
	// arbitrary string would silently strand a row that never matches a tool.
	known := false
	for _, tl := range rec.Tools {
		if tl.Name == tool {
			known = true
			break
		}
	}
	if !known {
		writeErr(w, http.StatusBadRequest, codeInvalid, "unknown tool for app")
		return
	}

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !decodeJSON(w, r, &body, 64<<10) {
		return
	}

	if err := s.Store.SetToolEnabled(ctx, name, tool, body.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "set tool state")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
