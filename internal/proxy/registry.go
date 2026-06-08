package proxy

import "sync"

// Identity is the tenant a sandbox connection belongs to.
type Identity struct {
	Server string
	Tenant string
}

// Registry maps a sandbox's source IP to its Identity. The mapping is
// authoritative (the gateway allocates the IP) and the source IP is
// unforgeable from inside the sandbox (its netns can only source its own /30).
type Registry struct {
	mu sync.RWMutex
	m  map[string]Identity
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{m: map[string]Identity{}} }

// Bind records ip → identity (called at sandbox spawn).
func (r *Registry) Bind(ip string, id Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[ip] = id
}

// Unbind removes a mapping (called at sandbox reap).
func (r *Registry) Unbind(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, ip)
}

// Lookup resolves an IP to its identity.
func (r *Registry) Lookup(ip string) (Identity, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.m[ip]
	return id, ok
}
