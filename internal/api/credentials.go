package api

import (
	"net/http"
	"strconv"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// credentialPutBody — PUT /api/credentials/{server}.
//
// TRANSITIONAL FIELDS: inject_header, inject_format, placeholder and
// allowed_hosts populate the credential-row columns only until the registry
// workstream's manifest sourcing lands (spec §5, §10 seam "credentials
// columns"); then the body shrinks to {secret} and these inputs disappear.
type credentialPutBody struct {
	Secret       string   `json:"secret"`
	InjectHeader string   `json:"inject_header"`
	InjectFormat string   `json:"inject_format"`
	Placeholder  string   `json:"placeholder"`
	AllowedHosts []string `json:"allowed_hosts"`
}

type credentialJSON struct {
	Server       string   `json:"server"`
	InjectHeader string   `json:"inject_header"`
	InjectFormat string   `json:"inject_format"`
	Placeholder  string   `json:"placeholder"`
	AllowedHosts []string `json:"allowed_hosts"`
}

// tenantOf is the credential tenant key: the owning user ID as a decimal
// string (spec §1 decision 10 / §3).
func tenantOf(u store.User) string { return strconv.FormatInt(u.ID, 10) }

// handlePutCredential — PUT /api/credentials/{server}: vault-encrypt and
// upsert. Write-only: the plaintext secret is never returned after this.
func (s *Server) handlePutCredential(w http.ResponseWriter, r *http.Request) {
	server := r.PathValue("server")
	var body credentialPutBody
	// Secret may be long (e.g. service-account JSON); cap at 64 KiB.
	if !decodeJSON(w, r, &body, 64<<10) {
		return
	}
	if body.Secret == "" {
		writeErr(w, http.StatusBadRequest, codeInvalid, "body must include a non-empty secret")
		return
	}
	user, _ := auth.EffectiveUser(r.Context()) // mutations are blocked while impersonating, so effective == real
	enc, err := s.Vault.Encrypt([]byte(body.Secret))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "encrypt secret")
		return
	}
	if err := s.Store.PutCredential(r.Context(), store.Credential{
		Server:       server,
		Tenant:       tenantOf(user),
		EncryptedKey: enc,
		InjectHeader: body.InjectHeader,
		InjectFormat: body.InjectFormat,
		Placeholder:  body.Placeholder,
		AllowedHosts: body.AllowedHosts,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "store credential")
		return
	}
	s.audit(r, "credential_put", "server="+server, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleListCredentials — GET /api/credentials: metadata only, never the
// secret (the store method strips ciphertext; this handler strips the rest).
func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.EffectiveUser(r.Context())
	creds, err := s.Store.ListCredentialsByTenant(r.Context(), tenantOf(user))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "list credentials")
		return
	}
	out := []credentialJSON{}
	for _, c := range creds {
		hosts := c.AllowedHosts
		if hosts == nil {
			hosts = []string{}
		}
		out = append(out, credentialJSON{
			Server:       c.Server,
			InjectHeader: c.InjectHeader,
			InjectFormat: c.InjectFormat,
			Placeholder:  c.Placeholder,
			AllowedHosts: hosts,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeleteCredential — DELETE /api/credentials/{server}.
func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	server := r.PathValue("server")
	user, _ := auth.EffectiveUser(r.Context())
	if err := s.Store.DeleteCredential(r.Context(), server, tenantOf(user)); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "delete credential")
		return
	}
	s.audit(r, "credential_delete", "server="+server, nil)
	w.WriteHeader(http.StatusNoContent)
}
