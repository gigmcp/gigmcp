package api

import (
	"log"
	"net/http"

	"github.com/gigmcp/gigmcp/internal/store"
)

type serverJSON struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func toServerJSON(srvs []store.Server) []serverJSON {
	out := []serverJSON{}
	for _, s := range srvs {
		out = append(out, serverJSON{ID: s.ID, Name: s.Name})
	}
	return out
}

// handleListServers — GET /api/servers via Installer.List; when Installer is
// nil it falls back to the store's installed-server list.
func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	var srvs []store.Server
	var err error
	if s.Installer == nil {
		srvs, err = s.Store.ListServers(r.Context())
	} else {
		srvs, err = s.Installer.List(r.Context())
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, codeInternal, "list servers")
		return
	}
	writeJSON(w, http.StatusOK, toServerJSON(srvs))
}

// handleInstallServer — POST /api/servers/install {ref} (admin).
func (s *Server) handleInstallServer(w http.ResponseWriter, r *http.Request) {
	if s.Installer == nil {
		writeErr(w, http.StatusNotImplemented, codeInternal, "installer unavailable")
		return
	}
	var body struct {
		Ref string `json:"ref"`
	}
	if !decodeJSON(w, r, &body, 64<<10) {
		return
	}
	if body.Ref == "" {
		writeErr(w, http.StatusBadRequest, codeInvalid, "body must be {ref}")
		return
	}
	srv, err := s.Installer.Install(r.Context(), body.Ref)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "install_failed", err.Error())
		return
	}
	s.audit(r, "server_install", "ref="+body.Ref, nil)
	writeJSON(w, http.StatusCreated, serverJSON{ID: srv.ID, Name: srv.Name})
}

// handleUninstallServer — DELETE /api/servers/{name} (admin).
// After Installer.Uninstall succeeds: removes profile_servers rows and
// invalidates affected profile runtimes (CONTROLLER ADDITION from T10 review).
func (s *Server) handleUninstallServer(w http.ResponseWriter, r *http.Request) {
	if s.Installer == nil {
		writeErr(w, http.StatusNotImplemented, codeInternal, "installer unavailable")
		return
	}
	name := r.PathValue("name")
	if err := s.Installer.Uninstall(r.Context(), name); err != nil {
		writeErr(w, http.StatusBadGateway, "uninstall_failed", err.Error())
		return
	}
	// Remove the server from all profiles and invalidate their runtimes.
	affected, err := s.Store.RemoveServerFromProfiles(r.Context(), name)
	if err != nil {
		// Non-fatal: the uninstall succeeded; log and continue.
		// If cleanup fails, profile_servers may reference an uninstalled server;
		// T14/T15 (resolver/ProfileHost) MUST fail closed (skip unknown servers).
		// Operator can re-run DELETE (idempotent) to retry cleanup.
		log.Printf("WARN: RemoveServerFromProfiles(%q): %v — operator retry: DELETE /api/servers/%s", name, err, name)
	}
	for _, id := range affected {
		s.invalidate(id)
	}
	s.audit(r, "server_uninstall", "name="+name, nil)
	w.WriteHeader(http.StatusNoContent)
}
