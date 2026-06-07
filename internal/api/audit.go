package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
)

type auditEventJSON struct {
	ID        int64     `json:"id"`
	TS        time.Time `json:"ts"`
	Kind      string    `json:"kind"`
	UserID    *int64    `json:"user_id"`
	ProfileID *int64    `json:"profile_id"`
	Server    string    `json:"server"`
	Host      string    `json:"host"`
	Decision  string    `json:"decision"`
	Detail    string    `json:"detail"`
}

// handleListAudit — GET /api/audit?before=&limit=&user_id=
// Keyset pagination newest-first. Non-admins (and admins while impersonating)
// are FORCED to their effective user's events; pure admins may filter freely.
//
// Audit filtering semantics (T10 controller addition):
//   - Non-admin: always sees only their own events (real user ID).
//   - Admin while impersonating: sees the target's events (EffectiveUser ID).
//     This matches the intent of view-as: the impersonating admin sees the
//     target's perspective, including their audit history.
//   - Admin not impersonating: sees all events; optional user_id query param filters.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	real, _ := auth.RealUser(r.Context())
	effective, _ := auth.EffectiveUser(r.Context())
	var userFilter int64
	switch {
	case auth.IsImpersonating(r.Context()):
		// View-as: filter by EffectiveUser (the target) — admin sees the
		// target's audit events, matching the view-as semantics.
		userFilter = effective.ID
	case real.Role != "admin":
		// Non-admin: forced to their own events regardless of query params.
		userFilter = real.ID
	default:
		// Pure admin: optional filter via ?user_id=.
		userFilter, _ = strconv.ParseInt(q.Get("user_id"), 10, 64)
	}
	events, err := s.Store.ListAudit(r.Context(), before, limit, userFilter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "list audit")
		return
	}
	out := []auditEventJSON{}
	var next int64
	for _, e := range events {
		out = append(out, auditEventJSON{
			ID: e.ID, TS: e.TS, Kind: e.Kind, UserID: e.UserID, ProfileID: e.ProfileID,
			Server: e.Server, Host: e.Host, Decision: e.Decision, Detail: e.Detail,
		})
		next = e.ID
	}
	if len(events) < limit {
		next = 0 // no further pages
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out, "next_before": next})
}
