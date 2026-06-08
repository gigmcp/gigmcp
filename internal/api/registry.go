package api

import (
	"context"
	"log"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gigmcp/registry/schema"
)

// IndexFetcher fetches the signed, verified registry index. Implemented by
// *registry.Client (FetchIndex verifies the ed25519 signature over the raw
// index bytes before parsing). Nil on Server means no registry is configured
// and GET /api/registry/servers answers 501 registry_disabled.
type IndexFetcher interface {
	FetchIndex(ctx context.Context) (*schema.Index, error)
}

// registryCacheTTL bounds how often the gateway re-fetches the registry
// index. Dashboard catalog searches within the window are served from memory
// instead of hammering the index URL (a GitHub release asset in production).
const registryCacheTTL = 5 * time.Minute

// indexCache memoizes the verified registry index for registryCacheTTL.
// The mutex is held across the fetch, which also serializes concurrent
// cold-cache requests into a single upstream fetch.
type indexCache struct {
	mu        sync.Mutex
	index     *schema.Index
	fetchedAt time.Time
}

// cachedIndex returns the memoized index, re-fetching after registryCacheTTL.
// A failed re-fetch is not cached: the next request retries.
func (s *Server) cachedIndex(ctx context.Context) (*schema.Index, error) {
	c := &s.regCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.index != nil && time.Since(c.fetchedAt) < registryCacheTTL {
		return c.index, nil
	}
	ix, err := s.Registry.FetchIndex(ctx)
	if err != nil {
		return nil, err
	}
	c.index, c.fetchedAt = ix, time.Now()
	return ix, nil
}

// registryServerJSON is one catalog entry in GET /api/registry/servers.
type registryServerJSON struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Latest      string `json:"latest"`
}

// handleRegistryServers — GET /api/registry/servers: the installable-server
// catalog from the signed registry index (any role; install itself stays
// admin-only). Description comes from the latest manifest in the index (empty
// when that manifest omits it, or when the latest version is absent from the
// Versions map).
func (s *Server) handleRegistryServers(w http.ResponseWriter, r *http.Request) {
	if s.Registry == nil {
		writeErr(w, http.StatusNotImplemented, "registry_disabled",
			"no registry configured: set GIG_REGISTRY_INDEX_URL and GIG_REGISTRY_PUBKEY")
		return
	}
	ix, err := s.cachedIndex(r.Context())
	if err != nil {
		// Detail goes to the log, not the (any-role) client.
		log.Printf("WARN: registry catalog: %v", err)
		writeErr(w, http.StatusBadGateway, "registry_unavailable", "registry index unavailable")
		return
	}
	servers := make([]registryServerJSON, 0, len(ix.Servers))
	for name, srv := range ix.Servers {
		description := ""
		// Nil-guard: Latest may point at a version absent from Versions.
		if m := srv.Versions[srv.Latest]; m != nil {
			description = m.Description
		}
		servers = append(servers, registryServerJSON{Name: name, Description: description, Latest: srv.Latest})
	}
	sort.Slice(servers, func(i, j int) bool { return servers[i].Name < servers[j].Name })
	writeJSON(w, http.StatusOK, map[string]any{"servers": servers})
}
