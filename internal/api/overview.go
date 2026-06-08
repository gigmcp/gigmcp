package api

import (
	"log"
	"net/http"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// overviewHeatmapDays is the trailing window for the activity heatmap.
// ~half a year: comfortably more cells than fit even an ultra-wide monitor,
// so the frontend always has enough history to fill the row and clip the rest.
const overviewHeatmapDays = 182

type overviewResponse struct {
	ToolCalls   int64              `json:"tool_calls"`
	Apps        int64              `json:"apps"`
	Connected   int64              `json:"connected"`
	Profiles    int64              `json:"profiles"`
	MostUsedApp string             `json:"most_used_app"`
	Heatmap     []store.HeatmapDay `json:"heatmap"`
}

// handleOverview — GET /api/overview: the audit-derived dashboard summary for
// the EFFECTIVE user. "Tool calls" is the egress-event count (no per-tool-call
// audit kind exists in P1). Apps = installed servers; Connected = the user's
// connected accounts (credentials); Profiles = the user's profiles.
func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, codeUnauthenticated, "authentication required")
		return
	}
	ctx := r.Context()

	stats, err := s.Store.AuditStats(ctx, user.ID, overviewHeatmapDays, time.Now().UTC())
	if err != nil {
		log.Printf("ERROR: handleOverview AuditStats user=%d: %v", user.ID, err)
		writeErr(w, http.StatusInternalServerError, codeInternal, "overview stats")
		return
	}

	resp := overviewResponse{
		ToolCalls: stats.ToolCalls, MostUsedApp: stats.MostUsedApp, Heatmap: stats.Heatmap,
	}

	// Apps = installed servers (registry-wide; install is admin-gated but the
	// installed set is visible to everyone, matching the Apps page).
	if srvs, err := s.Store.ListServers(ctx); err == nil {
		resp.Apps = int64(len(srvs))
	} else {
		log.Printf("WARN: handleOverview ListServers: %v", err)
	}

	// Connected = the user's connected accounts (vault credentials, metadata only).
	if creds, err := s.Store.ListCredentialsByTenant(ctx, store.UserTenant(user.ID)); err == nil {
		resp.Connected = int64(len(creds))
	} else {
		log.Printf("WARN: handleOverview ListCredentialsByTenant user=%d: %v", user.ID, err)
	}

	// Profiles = the user's profiles.
	if profs, err := s.Store.ListProfiles(ctx, user.ID); err == nil {
		resp.Profiles = int64(len(profs))
	} else {
		log.Printf("WARN: handleOverview ListProfiles user=%d: %v", user.ID, err)
	}

	writeJSON(w, http.StatusOK, resp)
}
