package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// handleListUsers — GET /api/users (admin): read-only list — roles come from
// the IdP, there is no local user editing.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "list users")
		return
	}
	out := []userJSON{}
	for _, u := range users {
		out = append(out, toUserJSON(u))
	}
	writeJSON(w, http.StatusOK, out)
}

// maxImpersonationTTL bounds view-as sessions (DESIGN #20).
const maxImpersonationTTL = 60 * time.Minute

// handleStartImpersonation — POST /api/admin/impersonate {user_id, ttl_minutes}.
func (s *Server) handleStartImpersonation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID     int64 `json:"user_id"`
		TTLMinutes int   `json:"ttl_minutes"`
	}
	if !decodeJSON(w, r, &body, 64<<10) {
		return
	}
	if body.UserID == 0 {
		writeErr(w, http.StatusBadRequest, codeInvalid, "body must be {user_id, ttl_minutes}")
		return
	}
	real, _ := auth.RealUser(r.Context())
	if body.UserID == real.ID {
		writeErr(w, http.StatusBadRequest, codeInvalid, "cannot impersonate yourself")
		return
	}
	target, err := s.Store.GetUser(r.Context(), body.UserID)
	if err != nil {
		writeErr(w, http.StatusNotFound, codeNotFound, "user not found")
		return
	}
	ttl := time.Duration(body.TTLMinutes) * time.Minute
	if ttl <= 0 || ttl > maxImpersonationTTL {
		ttl = maxImpersonationTTL
	}
	hash, ok := auth.SessionTokenHash(r.Context())
	if !ok {
		writeErr(w, http.StatusInternalServerError, codeInternal, "no session in context")
		return
	}
	if err := s.Store.SetImpersonation(r.Context(), hash, target.ID, time.Now().Add(ttl)); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "set impersonation")
		return
	}
	// Attributed to the TARGET so it shows in their own audit view (DESIGN #20);
	// the detail names both parties.
	tid := target.ID
	if err := s.Store.AppendAudit(r.Context(), s.impersonationEvent(real.Email, target.Email, "impersonate_start", &tid)); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "audit impersonation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleStopImpersonation — DELETE /api/admin/impersonate (exact path, no trailing slash).
// This exact path is the auth middleware carve-out for mutations during impersonation.
func (s *Server) handleStopImpersonation(w http.ResponseWriter, r *http.Request) {
	hash, ok := auth.SessionTokenHash(r.Context())
	if !ok {
		writeErr(w, http.StatusInternalServerError, codeInternal, "no session in context")
		return
	}
	if err := s.Store.ClearImpersonation(r.Context(), hash); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "clear impersonation")
		return
	}
	real, _ := auth.RealUser(r.Context())
	effective, _ := auth.EffectiveUser(r.Context())
	var tid *int64
	if effective.ID != real.ID {
		v := effective.ID
		tid = &v
	}
	if err := s.Store.AppendAudit(r.Context(), s.impersonationEvent(real.Email, effective.Email, "impersonate_stop", tid)); err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "audit impersonation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// impersonationEvent builds the loud DESIGN-#20 audit row naming both parties.
// Attributed to targetID (the impersonated user) so it appears in their audit view.
func (s *Server) impersonationEvent(adminEmail, targetEmail, decision string, targetID *int64) store.AuditEvent {
	return store.AuditEvent{
		Kind:     store.AuditKindAdmin,
		UserID:   targetID,
		Decision: decision,
		Detail:   fmt.Sprintf("admin=%s target=%s", adminEmail, targetEmail),
	}
}
