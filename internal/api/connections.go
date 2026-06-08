package api

import (
	"net/http"
	"regexp"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

var connVendorRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
var connServerRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type connectedAccountJSON struct {
	Vendor        string   `json:"vendor"`
	GrantedScopes []string `json:"granted_scopes"`
	ExpiresAt     int64    `json:"expires_at"` // unix seconds
}

// handleListConnections — GET /api/connections: the user's OAuth connections,
// metadata only (vendor, granted scopes, expiry). No token ciphertext.
func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	accts, err := s.Store.ListConnectedAccountsByUser(r.Context(), user.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "list connections")
		return
	}
	out := []connectedAccountJSON{}
	for _, a := range accts {
		scopes := a.GrantedScopes
		if scopes == nil {
			scopes = []string{}
		}
		out = append(out, connectedAccountJSON{Vendor: a.Vendor, GrantedScopes: scopes, ExpiresAt: a.ExpiresAt.Unix()})
	}
	writeJSON(w, http.StatusOK, out)
}

// requiredScopesForVendor returns the union of oauth2 scopes across the user's
// installed apps whose canonical vendor (Injection.Vendor, falling back to
// Injection.Provider when empty) matches vendor.
// Starting point: at least the named app's scopes (passed via ?server=).
func (s *Server) requiredScopesForVendor(r *http.Request, vendor, server string) []string {
	var required []string
	add := func(rec store.ManifestRecord) {
		if len(rec.Injections) > 0 {
			inj := rec.Injections[0]
			v := inj.Vendor
			if v == "" {
				v = inj.Provider
			}
			if inj.Type == "oauth2" && v == vendor {
				required = append(required, inj.Scopes...)
			}
		}
	}
	if server != "" {
		if rec, err := s.Store.GetManifest(r.Context(), server); err == nil {
			add(rec)
		}
	}
	// Union across all installed manifests for the same vendor (covers
	// incremental consent when other apps need wider scopes).
	if recs, err := s.Store.ListManifests(r.Context()); err == nil {
		for _, rec := range recs {
			add(rec)
		}
	}
	return required
}

// handleOAuthStart — GET /api/connections/oauth/start?vendor=&server=:
// compute the scope union and delegate to the broker.
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	if s.Broker == nil {
		writeErr(w, http.StatusNotImplemented, "oauth_disabled", "OAuth broker is not configured")
		return
	}
	user, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	vendor := r.URL.Query().Get("vendor")
	server := r.URL.Query().Get("server")
	if !connVendorRe.MatchString(vendor) {
		writeErr(w, http.StatusBadRequest, codeInvalid, "invalid vendor")
		return
	}
	if server != "" && !connServerRe.MatchString(server) {
		writeErr(w, http.StatusBadRequest, codeInvalid, "invalid server")
		return
	}
	required := s.requiredScopesForVendor(r, vendor, server)
	returnTo := "/connected-accounts"
	if server != "" {
		returnTo = "/servers/" + server
	}
	s.audit(r, "oauth_connect_start", "vendor="+vendor, nil)
	s.Broker.StartHandler(w, r, user.ID, required, returnTo)
}

// handleOAuthCallback — GET /api/connections/oauth/callback: delegate to broker.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if s.Broker == nil {
		writeErr(w, http.StatusNotImplemented, "oauth_disabled", "OAuth broker is not configured")
		return
	}
	s.Broker.CallbackHandler(w, r)
}

// handleDisconnect — DELETE /api/connections/{vendor}: remove the user's
// connection for a vendor.
func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	vendor := r.PathValue("vendor")
	if !connVendorRe.MatchString(vendor) {
		writeErr(w, http.StatusBadRequest, codeInvalid, "invalid vendor")
		return
	}
	if err := s.Store.DeleteConnectedAccount(r.Context(), user.ID, vendor); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "disconnect")
		return
	}
	s.audit(r, "oauth_disconnect", "vendor="+vendor, nil)
	w.WriteHeader(http.StatusNoContent)
}
