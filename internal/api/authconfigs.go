package api

import (
	"log"
	"net/http"
	"regexp"

	"github.com/gigmcp/gigmcp/internal/store"
)

// vendorRe validates the {vendor} path segment (lowercase slug).
var vendorRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type authConfigPutBody struct {
	AuthorizeURL  string   `json:"authorize_url"`
	TokenURL      string   `json:"token_url"`
	ClientID      string   `json:"client_id"`
	ClientSecret  string   `json:"client_secret"`
	DefaultScopes []string `json:"default_scopes"`
	PKCE          bool     `json:"pkce"`
	Mode          string   `json:"mode"`
}

type authConfigJSON struct {
	Vendor        string   `json:"vendor"`
	AuthorizeURL  string   `json:"authorize_url"`
	TokenURL      string   `json:"token_url"`
	ClientID      string   `json:"client_id"`
	DefaultScopes []string `json:"default_scopes"`
	PKCE          bool     `json:"pkce"`
	Mode          string   `json:"mode"`
	HasSecret     bool     `json:"has_secret"`
}

// handlePutAuthConfig — PUT /api/auth-configs/{vendor} (admin): vault-encrypt
// the client secret and upsert.
func (s *Server) handlePutAuthConfig(w http.ResponseWriter, r *http.Request) {
	vendor := r.PathValue("vendor")
	if !vendorRe.MatchString(vendor) {
		writeErr(w, http.StatusBadRequest, codeInvalid, "vendor must match ^[a-z0-9][a-z0-9_-]{0,63}$")
		return
	}
	var b authConfigPutBody
	if !decodeJSON(w, r, &b, 16<<10) {
		return
	}
	if b.AuthorizeURL == "" || b.TokenURL == "" || b.ClientID == "" {
		writeErr(w, http.StatusBadRequest, codeInvalid, "authorize_url, token_url and client_id are required")
		return
	}
	// SSRF guard: the gateway makes server-side requests to these BYO endpoints
	// (token exchange + refresh). Validate both before storing.
	if err := validateExternalHTTPSURL(b.AuthorizeURL); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalid, "authorize_url: "+err.Error())
		return
	}
	if err := validateExternalHTTPSURL(b.TokenURL); err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalid, "token_url: "+err.Error())
		return
	}
	if b.Mode != "managed" && b.Mode != "byo" {
		writeErr(w, http.StatusBadRequest, codeInvalid, "mode must be 'managed' or 'byo'")
		return
	}
	var enc []byte
	if b.ClientSecret != "" {
		var err error
		enc, err = s.Vault.Encrypt([]byte(b.ClientSecret))
		if err != nil {
			log.Printf("ERROR: encrypt client secret vendor=%s: %v", vendor, err)
			writeErr(w, http.StatusInternalServerError, codeInternal, "encrypt client secret")
			return
		}
	} else {
		// Preserve any existing secret on a metadata-only update.
		if cur, err := s.Store.GetAuthConfig(r.Context(), vendor); err == nil {
			enc = cur.EncryptedClientSecret
		}
	}
	if enc == nil {
		enc = []byte{} // NOT NULL column; empty is allowed for PKCE public clients
	}
	if err := s.Store.PutAuthConfig(r.Context(), store.AuthConfig{
		Vendor: vendor, AuthorizeURL: b.AuthorizeURL, TokenURL: b.TokenURL,
		ClientID: b.ClientID, EncryptedClientSecret: enc,
		DefaultScopes: b.DefaultScopes, PKCE: b.PKCE, Mode: b.Mode,
	}); err != nil {
		log.Printf("ERROR: PutAuthConfig vendor=%s: %v", vendor, err)
		writeErr(w, http.StatusInternalServerError, codeInternal, "store auth config")
		return
	}
	s.audit(r, "auth_config_put", "vendor="+vendor, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleListAuthConfigs — GET /api/auth-configs (admin): metadata only.
func (s *Server) handleListAuthConfigs(w http.ResponseWriter, r *http.Request) {
	cfgs, err := s.Store.ListAuthConfigs(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "list auth configs")
		return
	}
	out := []authConfigJSON{}
	for _, c := range cfgs {
		scopes := c.DefaultScopes
		if scopes == nil {
			scopes = []string{}
		}
		out = append(out, authConfigJSON{
			Vendor: c.Vendor, AuthorizeURL: c.AuthorizeURL, TokenURL: c.TokenURL,
			ClientID: c.ClientID, DefaultScopes: scopes, PKCE: c.PKCE, Mode: c.Mode,
			HasSecret: c.ClientID != "",
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeleteAuthConfig — DELETE /api/auth-configs/{vendor} (admin).
func (s *Server) handleDeleteAuthConfig(w http.ResponseWriter, r *http.Request) {
	vendor := r.PathValue("vendor")
	if !vendorRe.MatchString(vendor) {
		writeErr(w, http.StatusBadRequest, codeInvalid, "invalid vendor")
		return
	}
	if err := s.Store.DeleteAuthConfig(r.Context(), vendor); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "delete auth config")
		return
	}
	s.audit(r, "auth_config_delete", "vendor="+vendor, nil)
	w.WriteHeader(http.StatusNoContent)
}
