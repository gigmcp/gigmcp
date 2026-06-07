package api

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// slugRe: lowercase DNS-ish, 2–63 chars, no leading hyphen.
var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type profileJSON struct {
	ID       int64    `json:"id"`
	Slug     string   `json:"slug"`
	Name     string   `json:"name"`
	UserID   int64    `json:"user_id"`
	Endpoint string   `json:"endpoint"`
	Servers  []string `json:"servers"`
	Token    string   `json:"token,omitempty"` // plaintext, ONLY on create/rotate
}

func (s *Server) toProfileJSON(r *http.Request, p store.Profile) (profileJSON, error) {
	servers, err := s.Store.GetProfileServers(r.Context(), p.ID)
	if err != nil {
		return profileJSON{}, err
	}
	if servers == nil {
		servers = []string{}
	}
	return profileJSON{
		ID: p.ID, Slug: p.Slug, Name: p.Name, UserID: p.UserID,
		Endpoint: "/mcp/p/" + p.Slug, Servers: servers,
	}, nil
}

// writeProfile consolidates the toProfileJSON+writeJSON tail shared by
// create/get/patch/rotate handlers. token is set on the returned JSON when
// non-empty (create/rotate).
func (s *Server) writeProfile(w http.ResponseWriter, r *http.Request, status int, p store.Profile, token string) {
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "load profile servers")
		return
	}
	pj.Token = token
	writeJSON(w, status, pj)
}

// audit writes a synchronous admin audit row from a handler. The kind is
// always store.AuditKindAdmin so handlers cannot typo it.
func (s *Server) audit(r *http.Request, decision, detail string, profileID *int64) {
	var uid *int64
	if u, ok := auth.RealUser(r.Context()); ok {
		id := u.ID
		uid = &id
	}
	if err := s.Store.AppendAudit(r.Context(), store.AuditEvent{
		Kind: store.AuditKindAdmin, UserID: uid, ProfileID: profileID, Decision: decision, Detail: detail,
	}); err != nil {
		log.Printf("WARN: audit %s/%s: %v", store.AuditKindAdmin, decision, err)
	}
}

// loadOwnedProfile fetches {id} and enforces owner-or-admin; foreign profiles
// read as 404 to avoid leaking existence. Any non-ErrProfileNotFound store
// error is logged and mapped to 500.
func (s *Server) loadOwnedProfile(w http.ResponseWriter, r *http.Request) (store.Profile, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, codeInvalid, "invalid profile id")
		return store.Profile{}, false
	}
	p, err := s.Store.GetProfileByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrProfileNotFound) {
			writeErr(w, http.StatusNotFound, codeNotFound, "profile not found")
		} else {
			log.Printf("ERROR: GetProfileByID %d: %v", id, err)
			writeErr(w, http.StatusInternalServerError, codeInternal, "load profile")
		}
		return store.Profile{}, false
	}
	effective, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return store.Profile{}, false
	}
	real, _ := auth.RealUser(r.Context())
	if p.UserID != effective.ID && real.Role != "admin" {
		writeErr(w, http.StatusNotFound, codeNotFound, "profile not found")
		return store.Profile{}, false
	}
	return p, true
}

// handleListProfiles — GET /api/profiles: own; admins see all. Fails 401 if
// EffectiveUser is missing so filter=0 (all-profiles) is never used by accident.
func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	effective, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	filter := effective.ID
	if effective.Role == "admin" {
		filter = 0
	}
	profiles, err := s.Store.ListProfiles(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "list profiles")
		return
	}
	out := []profileJSON{}
	for _, p := range profiles {
		pj, err := s.toProfileJSON(r, p)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, codeInternal, "load profile servers")
			return
		}
		out = append(out, pj)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCreateProfile — POST /api/profiles {name, slug}: creates and returns
// the bearer token PLAINTEXT EXACTLY ONCE.
func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if !decodeJSON(w, r, &body, 64<<10) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if len(name) == 0 || len(name) > 128 {
		writeErr(w, http.StatusBadRequest, codeInvalid, "name must be 1–128 characters")
		return
	}
	if !slugRe.MatchString(body.Slug) {
		writeErr(w, http.StatusBadRequest, codeInvalid, "slug must match ^[a-z0-9][a-z0-9-]{1,62}$")
		return
	}
	owner, _ := auth.EffectiveUser(r.Context())
	tok, err := auth.NewProfileToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "entropy unavailable")
		return
	}
	p, err := s.Store.CreateProfile(r.Context(), body.Slug, name, owner.ID, auth.HashToken(tok))
	if err != nil {
		// The store contract guarantees ErrSlugTaken for any UNIQUE slug
		// violation regardless of backend; no raw-message fallbacks needed.
		if errors.Is(err, store.ErrSlugTaken) {
			writeErr(w, http.StatusConflict, codeConflict, "slug already in use")
			return
		}
		writeErr(w, http.StatusInternalServerError, codeInternal, "create profile")
		return
	}
	pid := p.ID
	s.audit(r, "profile_create", fmt.Sprintf("slug=%s", p.Slug), &pid)
	s.writeProfile(w, r, http.StatusCreated, p, tok)
}

// handleGetProfile — GET /api/profiles/{id}: detail incl. endpoint URL and
// servers; NEVER the token.
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	s.writeProfile(w, r, http.StatusOK, p, "")
}

// handlePatchProfile — PATCH /api/profiles/{id} {name}.
func (s *Server) handlePatchProfile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &body, 64<<10) {
		return
	}
	name := strings.TrimSpace(body.Name)
	if len(name) == 0 || len(name) > 128 {
		writeErr(w, http.StatusBadRequest, codeInvalid, "name must be 1–128 characters")
		return
	}
	if err := s.Store.UpdateProfileName(r.Context(), p.ID, name); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "rename profile")
		return
	}
	pid := p.ID
	s.audit(r, "profile_rename", name, &pid)
	p.Name = name
	s.writeProfile(w, r, http.StatusOK, p, "")
}

// handleDeleteProfile — DELETE /api/profiles/{id}: cascades profile_servers
// and tears down the runtime.
func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteProfile(r.Context(), p.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "delete profile")
		return
	}
	s.invalidate(p.ID)
	pid := p.ID
	s.audit(r, "profile_delete", fmt.Sprintf("slug=%s", p.Slug), &pid)
	w.WriteHeader(http.StatusNoContent)
}

// handlePutProfileServers — PUT /api/profiles/{id}/servers {servers[]}:
// replace-all; every name must be an installed server; invalidates the runtime.
func (s *Server) handlePutProfileServers(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	var body struct {
		Servers []string `json:"servers"`
	}
	if !decodeJSON(w, r, &body, 64<<10) {
		return
	}
	installed, err := s.Store.ListServers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "list servers")
		return
	}
	known := map[string]bool{}
	for _, srv := range installed {
		known[srv.Name] = true
	}
	for _, n := range body.Servers {
		if !known[n] {
			writeErr(w, http.StatusBadRequest, codeInvalid, "unknown server: "+n)
			return
		}
	}
	if err := s.Store.SetProfileServers(r.Context(), p.ID, body.Servers); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "set profile servers")
		return
	}
	s.invalidate(p.ID)
	pid := p.ID
	s.audit(r, "profile_servers", strings.Join(body.Servers, ","), &pid)
	s.writeProfile(w, r, http.StatusOK, p, "")
}

// handleRotateProfileToken — POST /api/profiles/{id}/token: returns the new
// plaintext once. Rotation does NOT invalidate the runtime.
func (s *Server) handleRotateProfileToken(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	tok, err := auth.NewProfileToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "entropy unavailable")
		return
	}
	if err := s.Store.SetProfileToken(r.Context(), p.ID, auth.HashToken(tok)); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "rotate token")
		return
	}
	pid := p.ID
	s.audit(r, "profile_token_rotate", "", &pid)
	s.writeProfile(w, r, http.StatusOK, p, tok)
}
