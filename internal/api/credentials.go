package api

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"unicode/utf8"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// credentialPutBody — PUT /api/credentials/{server}.
//
// TRANSITIONAL FIELDS: inject_header, inject_format, placeholder and
// allowed_hosts populate the credential-row columns only until the registry
// workstream's manifest sourcing lands; then the body shrinks to {secret}
// and these inputs disappear.
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

// serverNameRe validates the {server} path segment. Credentials may
// legitimately be created before the server is installed in the registry, so
// we only reject obviously garbage names — no existence check.
var serverNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// injectHeaderRe validates inject_header values (HTTP header name characters).
var injectHeaderRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

// allowedHostRe validates a single allowed_hosts entry: optional wildcard
// prefix, then lowercase hostname chars only (no whitespace/newlines, which
// would corrupt the store's newline-join encoding).
var allowedHostRe = regexp.MustCompile(`^(\*\.)?[a-z0-9.-]+$`)

// validateServerName returns an error string if the server name is invalid.
func validateServerName(name string) string {
	if !serverNameRe.MatchString(name) {
		return "server name must match ^[a-z0-9][a-z0-9_-]{0,63}$"
	}
	return ""
}

// validateCredentialBody returns (field, message) if any transitional field is
// invalid, or ("", "") if all are valid.
func validateCredentialBody(b *credentialPutBody) (field, msg string) {
	if b.InjectHeader != "" {
		if utf8.RuneCountInString(b.InjectHeader) > 64 {
			return "inject_header", "inject_header must be at most 64 characters"
		}
		if !injectHeaderRe.MatchString(b.InjectHeader) {
			return "inject_header", "inject_header must match ^[A-Za-z0-9-]+$"
		}
	}
	if len(b.AllowedHosts) > 64 {
		return "allowed_hosts", "allowed_hosts must have at most 64 entries"
	}
	for i, h := range b.AllowedHosts {
		if h == "" {
			return "allowed_hosts", fmt.Sprintf("allowed_hosts[%d] must not be empty", i)
		}
		if utf8.RuneCountInString(h) > 253 {
			return "allowed_hosts", fmt.Sprintf("allowed_hosts[%d] must be at most 253 characters", i)
		}
		// Reject any whitespace or newline (newline corrupts the store's newline-join encoding).
		for _, c := range h {
			if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
				return "allowed_hosts", fmt.Sprintf("allowed_hosts[%d] must not contain whitespace or newlines", i)
			}
		}
		if !allowedHostRe.MatchString(h) {
			return "allowed_hosts", fmt.Sprintf("allowed_hosts[%d] must match ^(\\*\\.)?[a-z0-9.-]+$", i)
		}
	}
	if b.InjectFormat != "" {
		if utf8.RuneCountInString(b.InjectFormat) > 256 {
			return "inject_format", "inject_format must be at most 256 characters"
		}
		// Must contain {token} so the proxy can substitute the real secret.
		if !regexp.MustCompile(`\{token\}`).MatchString(b.InjectFormat) {
			return "inject_format", "inject_format must contain {token}"
		}
	}
	if b.Placeholder != "" {
		runes := utf8.RuneCountInString(b.Placeholder)
		if runes < 8 {
			return "placeholder", "placeholder must be at least 8 characters"
		}
		if runes > 256 {
			return "placeholder", "placeholder must be at most 256 characters"
		}
	}
	return "", ""
}

// handlePutCredential — PUT /api/credentials/{server}: vault-encrypt and
// upsert. Write-only: the plaintext secret is never returned after this.
func (s *Server) handlePutCredential(w http.ResponseWriter, r *http.Request) {
	server := r.PathValue("server")
	if msg := validateServerName(server); msg != "" {
		writeErr(w, http.StatusBadRequest, codeInvalid, msg)
		return
	}
	var body credentialPutBody
	// Secret may be long (e.g. service-account JSON); cap at 64 KiB.
	if !decodeJSON(w, r, &body, 64<<10) {
		return
	}
	if body.Secret == "" {
		writeErr(w, http.StatusBadRequest, codeInvalid, "body must include a non-empty secret")
		return
	}
	if field, msg := validateCredentialBody(&body); field != "" {
		writeErr(w, http.StatusBadRequest, codeInvalid, field+": "+msg)
		return
	}
	user, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	enc, err := s.Vault.Encrypt([]byte(body.Secret))
	if err != nil {
		log.Printf("ERROR: handlePutCredential Vault.Encrypt server=%s: %v", server, err)
		writeErr(w, http.StatusInternalServerError, codeInternal, "encrypt secret")
		return
	}
	if err := s.Store.PutCredential(r.Context(), store.Credential{
		Server:       server,
		Tenant:       store.UserTenant(user.ID),
		EncryptedKey: enc,
		InjectHeader: body.InjectHeader,
		InjectFormat: body.InjectFormat,
		Placeholder:  body.Placeholder,
		AllowedHosts: body.AllowedHosts,
	}); err != nil {
		log.Printf("ERROR: handlePutCredential PutCredential server=%s user=%d: %v", server, user.ID, err)
		writeErr(w, http.StatusInternalServerError, codeInternal, "store credential")
		return
	}
	s.audit(r, "credential_put", "server="+server, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleListCredentials — GET /api/credentials: metadata only, never the
// secret (the store method strips ciphertext; this handler strips the rest).
func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	creds, err := s.Store.ListCredentialsByTenant(r.Context(), store.UserTenant(user.ID))
	if err != nil {
		log.Printf("ERROR: handleListCredentials ListCredentialsByTenant user=%d: %v", user.ID, err)
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
	if msg := validateServerName(server); msg != "" {
		writeErr(w, http.StatusBadRequest, codeInvalid, msg)
		return
	}
	user, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	deleted, err := s.Store.DeleteCredential(r.Context(), server, store.UserTenant(user.ID))
	if err != nil {
		log.Printf("ERROR: handleDeleteCredential DeleteCredential server=%s user=%d: %v", server, user.ID, err)
		writeErr(w, http.StatusInternalServerError, codeInternal, "delete credential")
		return
	}
	detail := "server=" + server
	if !deleted {
		detail += " noop=true"
	}
	s.audit(r, "credential_delete", detail, nil)
	w.WriteHeader(http.StatusNoContent)
}
