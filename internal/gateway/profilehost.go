package gateway

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SpawnFunc launches one backend MCP server for a profile runtime. In
// production it closes over SpawnEgressBackend (cmd/gateway wiring); tests
// substitute in-memory backends.
type SpawnFunc func(ctx context.Context, srv store.Server, tenant string) (*EgressBackend, error)

// profileRuntime is one profile's live aggregator + sandbox cleanups.
type profileRuntime struct {
	handler  http.Handler
	cleanups []func()
}

// ProfileHost serves the per-profile MCP endpoints at /mcp/p/{slug}
// (spec §6). Runtimes are LAZY (DESIGN #5): the first authorized request to
// a profile spawns its bundle (each server with Tenant = the profile ID) and
// builds the aggregator; later requests reuse it. Invalidate tears a runtime
// down after bundle edits or deletion (token rotation does NOT invalidate).
//
// Idle reaping is out of v1 scope: the sandbox count is bounded by
// profiles × servers (documented limitation).
type ProfileHost struct {
	Store   store.Store
	Spawn   SpawnFunc
	Version string

	mu       sync.Mutex
	runtimes map[int64]*profileRuntime
}

// Handler routes /mcp/p/{slug}. No method in the pattern: streamable HTTP
// uses POST, GET and DELETE on the same URL.
func (h *ProfileHost) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/p/{slug}", h.serve)
	return mux
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (h *ProfileHost) serve(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		unauthorized(w)
		return
	}
	// Per-request token check is load-bearing for rotation/revocation: every
	// request re-hashes the bearer and looks it up in the DB. Never add a
	// session-id shortcut that bypasses this check — a rotated token must be
	// rejected immediately, not after a cached window.
	//
	// Hash-then-index-lookup needs no constant-time comparison: the attacker
	// does not control the stored hash, and the timing of a B-tree lookup on
	// SHA-256(token) reveals nothing useful about the token bytes (unlike
	// comparing a raw secret, where prefix-match timing leaks).
	p, err := h.Store.GetProfileBySlugAndTokenHash(r.Context(), r.PathValue("slug"), auth.HashToken(tok))
	if err != nil {
		unauthorized(w)
		return
	}
	rt, err := h.getOrCreate(p)
	if err != nil {
		log.Printf("profile %q runtime: %v", p.Slug, err)
		http.Error(w, "backend unavailable", http.StatusBadGateway)
		return
	}
	// In-flight streams survive rotation: once a runtime is obtained the MCP
	// session continues until the client disconnects or the stream completes.
	// Hard revocation (bundle-edit or profile DELETE) goes through Invalidate,
	// which tears down the runtime; the next request gets a fresh spawn.
	rt.handler.ServeHTTP(w, r)
}

// getOrCreate returns the profile's runtime, lazily spawning it.
func (h *ProfileHost) getOrCreate(p store.Profile) (*profileRuntime, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.runtimes == nil {
		h.runtimes = map[int64]*profileRuntime{}
	}
	if rt, ok := h.runtimes[p.ID]; ok {
		return rt, nil
	}

	// Sandboxes outlive the triggering request: Background, not r.Context().
	ctx := context.Background()
	names, err := h.Store.GetProfileServers(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	all, err := h.Store.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]store.Server, len(all))
	for _, s := range all {
		byName[s.Name] = s
	}

	tenant := strconv.FormatInt(p.ID, 10)
	var backends []Backend
	var cleanups []func()
	fail := func(err error) (*profileRuntime, error) {
		for _, c := range cleanups {
			c()
		}
		return nil, err
	}
	for _, name := range names {
		srv, ok := byName[name]
		if !ok {
			// Stale reference: a server was uninstalled but the profile_servers
			// row was not cleaned up (uninstall cleanup is best-effort). Skip
			// this server rather than aborting the whole profile — the profile
			// stays usable with its remaining servers. If no servers remain we
			// will fall through to the zero-backends New() path.
			log.Printf("profile %d: skipping unknown server %q (uninstalled?)", p.ID, name)
			continue
		}
		eb, err := h.Spawn(ctx, srv, tenant)
		if err != nil {
			// Spawn failure is unrecoverable for this server; clean up what we
			// have and surface the error. The profile stays un-cached so the
			// next request retries.
			return fail(fmt.Errorf("spawn %q: %w", name, err))
		}
		cleanups = append(cleanups, eb.Cleanup)

		// Build Expose map from manifest (DESIGN #11 default subset). Servers
		// without a manifest (legacy GIG_ECHO_BIN) expose all tools (nil map).
		var expose map[string]bool
		if rec, merr := h.Store.GetManifest(ctx, name); merr == nil {
			expose = map[string]bool{}
			for _, tl := range rec.Tools {
				if tl.Default {
					expose[tl.Name] = true
				}
			}
		}
		backends = append(backends, Backend{Name: srv.Name, Session: eb.Session, Expose: expose})
	}
	agg, err := New(ctx, h.Version, backends)
	if err != nil {
		return fail(err)
	}
	rt := &profileRuntime{
		handler:  mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return agg }, nil),
		cleanups: cleanups,
	}
	h.runtimes[p.ID] = rt
	return rt, nil
}

// Invalidate tears down one profile's runtime (bundle change or delete);
// the next request rebuilds it lazily. Implements api.ProfileInvalidator.
func (h *ProfileHost) Invalidate(profileID int64) {
	h.mu.Lock()
	rt := h.runtimes[profileID]
	delete(h.runtimes, profileID)
	h.mu.Unlock()
	if rt == nil {
		return
	}
	for _, c := range rt.cleanups {
		c()
	}
}

// Close tears down all runtimes (gateway shutdown).
func (h *ProfileHost) Close() {
	h.mu.Lock()
	rts := h.runtimes
	h.runtimes = nil
	h.mu.Unlock()
	for _, rt := range rts {
		for _, c := range rt.cleanups {
			c()
		}
	}
}
