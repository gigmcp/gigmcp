package api

import (
	"net/http"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

type userJSON struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

func toUserJSON(u store.User) userJSON {
	return userJSON{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Role: u.Role}
}

// handleMe — GET /api/me: the effective user, plus both identities while
// impersonating (the dashboard banner is driven by this).
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	effective, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "no user in context")
		return
	}
	resp := struct {
		User          userJSON  `json:"user"`
		Impersonating bool      `json:"impersonating"`
		RealUser      *userJSON `json:"real_user,omitempty"`
	}{User: toUserJSON(effective), Impersonating: auth.IsImpersonating(r.Context())}
	if resp.Impersonating {
		if real, ok := auth.RealUser(r.Context()); ok {
			rj := toUserJSON(real)
			resp.RealUser = &rj
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
