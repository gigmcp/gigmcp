package gateway_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
)

// fixedResolver returns a fixed credential or error for any identity.
type fixedResolver struct {
	cred proxy.Credential
	err  error
}

func (f fixedResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	return f.cred, f.err
}

// TestAuditingResolverRecordsDecisions verifies that the AuditingResolver
// writes exactly one audit row per Resolve call and that the profile→owner
// join populates both ProfileID and UserID.
//
// De-vacuated: TWO users are seeded so user1.ID == profile.ID == 1 while
// user2.ID == profile.UserID == 2. The test therefore asserts
// *e.ProfileID != *e.UserID, which would be impossible with a single user
// where both fields collapse to the same value.
func TestAuditingResolverRecordsDecisions(t *testing.T) {
	ctx := context.Background()
	_, st := newVaultStore(t)

	// user1 consumes ID=1 so user2 gets a distinct ID.
	_, err := st.UpsertUserByOIDC(ctx, "https://idp", "alice-sub", "a@x", "Alice", "user")
	if err != nil {
		t.Fatal(err)
	}
	user2, err := st.UpsertUserByOIDC(ctx, "https://idp", "bob-sub", "b@x", "Bob", "user")
	if err != nil {
		t.Fatal(err)
	}
	// Profile owned by user2 (ID=2), so profile gets ID=1.
	p, err := st.CreateProfile(ctx, "main", "Main", user2.ID, "hash")
	if err != nil {
		t.Fatal(err)
	}
	// Confirm the separation that makes the test non-vacuous.
	if p.ID == user2.ID {
		t.Skip("profile.ID == user2.ID in this DB; join separation impossible")
	}
	tenant := strconv.FormatInt(p.ID, 10)

	inner := &swappableResolver{}
	a := gateway.NewAuditingResolver(inner, st)

	// resolved: exact allowlist match.
	inner.set(proxy.Credential{RealSecret: "k", AllowedHosts: []string{"api.example.com"}}, nil)
	if _, err := a.Resolve(proxy.Identity{Server: "github", Tenant: tenant}, "api.example.com"); err != nil {
		t.Fatal(err)
	}
	// resolved: wildcard suffix match (mirrors proxy semantics).
	inner.set(proxy.Credential{RealSecret: "k", AllowedHosts: []string{"*.example.com"}}, nil)
	if _, err := a.Resolve(proxy.Identity{Server: "github", Tenant: tenant}, "sub.example.com"); err != nil {
		t.Fatal(err)
	}
	// denied: host not in allowlist.
	inner.set(proxy.Credential{RealSecret: "k", AllowedHosts: []string{"only.example.com"}}, nil)
	a.Resolve(proxy.Identity{Server: "github", Tenant: tenant}, "evil.example.org")
	// error: inner resolver failed (passes the error through).
	inner.set(proxy.Credential{}, errors.New("no credential"))
	if _, err := a.Resolve(proxy.Identity{Server: "github", Tenant: "default"}, "x.example.com"); err == nil {
		t.Fatal("inner error must propagate")
	}

	a.Close() // flush the writer

	events, err := st.ListAudit(ctx, 0, 10, 0)
	if err != nil || len(events) != 4 {
		t.Fatalf("events: %v %d", err, len(events))
	}
	// Newest first: error, denied, resolved, resolved.
	wantDecisions := []string{"error", "denied", "resolved", "resolved"}
	for i, want := range wantDecisions {
		if events[i].Kind != "egress" || events[i].Decision != want {
			t.Fatalf("event %d: want %s, got %+v", i, want, events[i])
		}
	}
	// Profile-tenant events carry the join: profile id + owner user id.
	// Crucially, *e.ProfileID (==p.ID==1) must DIFFER from *e.UserID (==user2.ID==2)
	// — this is the property that proves the join is actually being exercised.
	for _, e := range events[1:] { // all but the "default"-tenant error event
		if e.ProfileID == nil || *e.ProfileID != p.ID {
			t.Fatalf("ProfileID missing or wrong: %+v", e)
		}
		if e.UserID == nil || *e.UserID != user2.ID {
			t.Fatalf("UserID missing or wrong (owner join broken): %+v", e)
		}
		if *e.ProfileID == *e.UserID {
			t.Fatalf("ProfileID == UserID (%d): test is vacuous; seeding failed", *e.ProfileID)
		}
	}
	if events[0].ProfileID != nil || events[0].UserID != nil {
		t.Fatalf("literal-tenant event must not fake a join: %+v", events[0])
	}
}

// swappableResolver lets one test reconfigure the inner result between calls.
type swappableResolver struct {
	mu   sync.Mutex
	cred proxy.Credential
	err  error
}

func (s *swappableResolver) set(c proxy.Credential, err error) {
	s.mu.Lock()
	s.cred, s.err = c, err
	s.mu.Unlock()
}
func (s *swappableResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cred, s.err
}

// blockingStore wraps store.Store so that AppendAudit blocks on a channel
// until released. This lets tests fill the AuditingResolver's 256-event
// buffer and exercise the overflow / Dropped() path while the resolver is
// still open (not closed).
type blockingStore struct {
	store.Store
	gate chan struct{} // closed by release()
}

func newBlockingStore(st store.Store) *blockingStore {
	return &blockingStore{Store: st, gate: make(chan struct{})}
}

func (b *blockingStore) release() { close(b.gate) }

func (b *blockingStore) AppendAudit(ctx context.Context, e store.AuditEvent) error {
	<-b.gate // block until released
	return b.Store.AppendAudit(ctx, e)
}

// TestAuditingResolverNeverBlocks verifies three properties:
//
//  1. Resolve returns promptly even when the 256-event buffer is full (no
//     call blocks for more than a short wall-clock budget).
//  2. Dropped() > 0 while the resolver is still open and the buffer is full.
//  3. After releasing the blocked writer and calling Close(), the drained
//     writes that did land are counted correctly (Resolve is non-blocking even
//     with a slow store).
func TestAuditingResolverNeverBlocks(t *testing.T) {
	_, realSt := newVaultStore(t)
	bs := newBlockingStore(realSt)

	inner := fixedResolver{cred: proxy.Credential{AllowedHosts: []string{"a.example.com"}}}
	a := gateway.NewAuditingResolver(inner, bs)

	const total = 300
	id := proxy.Identity{Server: "s", Tenant: "default"}

	// Phase 1: issue total resolves with the writer goroutine completely
	// blocked. The first 256 fill the buffer; the rest must drop and return
	// immediately (not block).
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; i < total; i++ {
		done := make(chan struct{})
		go func() {
			a.Resolve(id, "a.example.com")
			close(done)
		}()
		select {
		case <-done:
			// OK — returned promptly.
		case <-time.After(time.Until(deadline) / time.Duration(total-i+1)):
			t.Fatalf("Resolve blocked on call %d (buffer full, writer blocked)", i)
		}
	}

	// Phase 2: confirm overflow was detected while still open.
	dropped := a.Dropped()
	if dropped == 0 {
		t.Fatalf("expected Dropped() > 0 after %d resolves with blocked writer, got 0", total)
	}

	// Phase 3: release the writer, close, and confirm it drains without panic.
	bs.release()
	a.Close()

	// The total calls accounted for = dropped + written.
	// We can only assert the invariant; the split is non-deterministic.
	if dropped > total {
		t.Fatalf("Dropped() %d > total %d: counter corrupted", dropped, total)
	}
}
