package gateway

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
)

// auditRecord is the hot-path payload; the DB write (and the profile→owner
// join) happens on the writer goroutine, never on the egress path.
type auditRecord struct {
	server   string
	tenant   string
	host     string
	decision string
	detail   string
}

// AuditingResolver decorates a proxy.CredentialResolver with persistent
// egress auditing (spec §7) — ZERO edits to the no-touch proxy package.
// Writes go through a buffered channel to a single writer goroutine so audit
// can never block the egress hot path; on overflow events are dropped and
// counted, never blocking.
//
// It mirrors the proxy's host-allowlist semantics (exact case-insensitive
// match, or "*.suffix" wildcard suffix match — see internal/proxy/proxy.go
// allowed()) to RECORD the decision the proxy is about to make. This is an
// intentional, documented duplication: the registry workstream's lint CI
// must mirror the same rule.
//
// Lifecycle: Close() flushes pending events and stops the writer; Resolve
// remains safe (and silently drops) after Close.
type AuditingResolver struct {
	Inner proxy.CredentialResolver
	Store store.Store

	ch      chan auditRecord
	done    chan struct{}
	mu      sync.Mutex
	closed  bool
	dropped int64 // accessed via atomic after mu guards the closed flag
}

// NewAuditingResolver starts the writer goroutine (buffer: 256 events).
func NewAuditingResolver(inner proxy.CredentialResolver, st store.Store) *AuditingResolver {
	a := &AuditingResolver{
		Inner: inner, Store: st,
		ch:   make(chan auditRecord, 256),
		done: make(chan struct{}),
	}
	go a.writer()
	return a
}

func (a *AuditingResolver) writer() {
	defer close(a.done)
	for rec := range a.ch {
		e := store.AuditEvent{
			Kind: store.AuditKindEgress, Server: rec.server, Host: rec.host,
			Decision: rec.decision, Detail: rec.detail,
		}
		// Profile→owner join off the hot path: numeric tenants naming a
		// profile are attributed to (profile, owning user).
		if pid, err := strconv.ParseInt(rec.tenant, 10, 64); err == nil {
			if p, perr := a.Store.GetProfileByID(context.Background(), pid); perr == nil {
				id := pid
				e.ProfileID = &id
				uid := p.UserID
				e.UserID = &uid
			}
		}
		if err := a.Store.AppendAudit(context.Background(), e); err != nil {
			log.Printf("WARN: egress audit write: %v", err)
		}
	}
}

// Resolve delegates to Inner and records the outcome
// (resolved | denied | error). The inner result is returned unchanged.
func (a *AuditingResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	cred, err := a.Inner.Resolve(id, host)
	rec := auditRecord{server: id.Server, tenant: id.Tenant, host: host}
	switch {
	case err != nil:
		rec.decision = "error"
		rec.detail = err.Error()
	case hostAllowed(host, cred.AllowedHosts):
		rec.decision = "resolved"
	default:
		rec.decision = "denied"
		rec.detail = "host not in allowlist"
	}
	a.mu.Lock()
	if !a.closed {
		select {
		case a.ch <- rec:
		default:
			atomic.AddInt64(&a.dropped, 1)
			log.Printf("WARN: egress audit channel full; dropped event(s)")
		}
	} else {
		atomic.AddInt64(&a.dropped, 1)
	}
	a.mu.Unlock()
	return cred, err
}

// Dropped returns how many events were dropped on overflow or after Close.
func (a *AuditingResolver) Dropped() int64 {
	return atomic.LoadInt64(&a.dropped)
}

// Close flushes pending events and stops the writer. Idempotent.
func (a *AuditingResolver) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	a.mu.Unlock()
	close(a.ch)
	<-a.done
}

// hostAllowed mirrors internal/proxy's allowed() exactly (see the type
// comment for why the duplication is intentional).
func hostAllowed(host string, list []string) bool {
	for _, h := range list {
		if strings.EqualFold(host, h) {
			return true
		}
		if strings.HasPrefix(h, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(h[1:])) {
			return true
		}
	}
	return false
}
