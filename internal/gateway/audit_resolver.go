package gateway

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

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
// egress auditing — ZERO edits to the no-touch proxy package.
// Writes go through a buffered channel to a single writer goroutine so audit
// can never block the egress hot path; on overflow events are dropped and
// counted, never blocking.
//
// It calls proxy.HostAllowed — the single source of truth for host-allowlist
// matching — to RECORD the decision the proxy is about to make, so the
// decorator and the proxy can never disagree about the egress boundary.
//
// Lifecycle: Close() MUST be called on shutdown or the writer goroutine
// leaks. T16 (cmd/gateway wiring) is responsible for wiring this into the
// server's graceful-shutdown path. Resolve remains safe (and silently drops)
// after Close.
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
		// Profile→owner join off the hot path via the shared resolveTenant
		// helper; each store call gets a 5 s deadline so a slow DB can never
		// wedge the writer goroutine permanently.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, profileID, userID := resolveTenant(ctx, a.Store, rec.tenant)
		cancel()
		e.ProfileID = profileID
		e.UserID = userID

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		err := a.Store.AppendAudit(ctx, e)
		cancel()
		if err != nil {
			n := atomic.AddInt64(&a.dropped, 1)
			if n%1000 == 1 {
				log.Printf("WARN: egress audit write dropped (%d total): %v", n, err)
			}
		}
	}
}

// Resolve delegates to Inner and records the outcome
// (resolved | denied | error). The inner result is returned unchanged.
//
// The decision is derived SOLELY from Inner's returned (cred, err), so it
// mirrors the real resolver by construction — including the credential-less,
// manifest-backed case (public-API "sealed" servers): Inner returns a
// no-secret Credential carrying the manifest's AllowedHosts with err==nil, so
// the HostAllowed branch below records "resolved" for entitled hosts and
// "denied" otherwise, never "error". This keeps the decorator and the resolver
// from disagreeing without re-querying the store here.
func (a *AuditingResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	cred, err := a.Inner.Resolve(id, host)
	rec := auditRecord{server: id.Server, tenant: id.Tenant, host: host}
	switch {
	case err != nil:
		rec.decision = "error"
		rec.detail = err.Error()
	case proxy.HostAllowed(host, cred.AllowedHosts):
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
			n := atomic.AddInt64(&a.dropped, 1)
			if n%1000 == 1 {
				log.Printf("WARN: egress audit channel full; %d event(s) dropped", n)
			}
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
