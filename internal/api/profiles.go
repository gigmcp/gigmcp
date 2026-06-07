package api

import (
	"encoding/json"
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

// slugRe: lowercase DNS-ish, 2–63 chars, no leading hyphen (spec Task rule).
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

// audit writes a synchronous admin/auth audit row from a handler.
func (s *Server) audit(r *http.Request, kind, decision, detail string, profileID *int64) {
	var uid *int64
	if u, ok := auth.RealUser(r.Context()); ok {
		id := u.ID
		uid = &id
	}
	if err := s.Store.AppendAudit(r.Context(), store.AuditEvent{
		Kind: kind, UserID: uid, ProfileID: profileID, Decision: decision, Detail: detail,
	}); err != nil {
		log.Printf("WARN: audit %s/%s: %v", kind, decision, err)
	}
}

// loadOwnedProfile fetches {id} and enforces owner-or-admin; foreign profiles
// read as 404 to avoid leaking existence.
func (s *Server) loadOwnedProfile(w http.ResponseWriter, r *http.Request) (store.Profile, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, codeNotFound, "invalid profile id")
		return store.Profile{}, false
	}
	p, err := s.Store.GetProfileByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, codeNotFound, "profile not found")
		return store.Profile{}, false
	}
	effective, _ := auth.EffectiveUser(r.Context())
	real, _ := auth.RealUser(r.Context())
	if p.UserID != effective.ID && real.Role != "admin" {
		writeErr(w, http.StatusNotFound, codeNotFound, "profile not found")
		return store.Profile{}, false
	}
	return p, true
}

// handleListProfiles — GET /api/profiles: own; admins see all.
func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	effective, _ := auth.EffectiveUser(r.Context())
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be {name, slug}")
		return
	}
	if !slugRe.MatchString(body.Slug) {
		writeErr(w, http.StatusBadRequest, "bad_request", "slug must match ^[a-z0-9][a-z0-9-]{1,62}$")
		return
	}
	owner, _ := auth.EffectiveUser(r.Context())
	tok, err := auth.NewProfileToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "entropy unavailable")
		return
	}
	p, err := s.Store.CreateProfile(r.Context(), body.Slug, body.Name, owner.ID, auth.HashToken(tok))
	if err != nil {
		// ErrSlugTaken is the canonical error from the SQLite store.
		// For Postgres compatibility we also check the raw error message.
		if errors.Is(err, store.ErrSlugTaken) ||
			strings.Contains(err.Error(), "UNIQUE") ||
			strings.Contains(err.Error(), "duplicate key") {
			writeErr(w, http.StatusConflict, "conflict", "slug already in use")
			return
		}
		writeErr(w, http.StatusInternalServerError, codeInternal, "create profile")
		return
	}
	pid := p.ID
	s.audit(r, "admin", "profile_create", fmt.Sprintf("slug=%s", p.Slug), &pid)
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "load profile")
		return
	}
	pj.Token = tok
	writeJSON(w, http.StatusCreated, pj)
}

// handleGetProfile — GET /api/profiles/{id}: detail incl. endpoint URL and
// servers; NEVER the token.
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "load profile servers")
		return
	}
	writeJSON(w, http.StatusOK, pj)
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be {name}")
		return
	}
	if err := s.Store.UpdateProfileName(r.Context(), p.ID, body.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "rename profile")
		return
	}
	pid := p.ID
	s.audit(r, "admin", "profile_rename", body.Name, &pid)
	p.Name = body.Name
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "load profile")
		return
	}
	writeJSON(w, http.StatusOK, pj)
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
	s.audit(r, "admin", "profile_delete", fmt.Sprintf("slug=%s", p.Slug), &pid)
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be {servers: [names]}")
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
			writeErr(w, http.StatusBadRequest, "bad_request", "unknown server: "+n)
			return
		}
	}
	if err := s.Store.SetProfileServers(r.Context(), p.ID, body.Servers); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "set profile servers")
		return
	}
	s.invalidate(p.ID)
	pid := p.ID
	s.audit(r, "admin", "profile_servers", strings.Join(body.Servers, ","), &pid)
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "load profile")
		return
	}
	writeJSON(w, http.StatusOK, pj)
}

// handleRotateProfileToken — POST /api/profiles/{id}/token: returns the new
// plaintext once. Rotation does NOT invalidate the runtime (spec §6).
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
	s.audit(r, "admin", "profile_token_rotate", "", &pid)
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "load profile")
		return
	}
	pj.Token = tok
	writeJSON(w, http.StatusOK, pj)
}
