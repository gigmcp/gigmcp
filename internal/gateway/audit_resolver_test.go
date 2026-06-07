package gateway_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/proxy"
)

// fixedResolver returns a fixed credential or error for any identity.
type fixedResolver struct {
	cred proxy.Credential
	err  error
}

func (f fixedResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	return f.cred, f.err
}

func TestAuditingResolverRecordsDecisions(t *testing.T) {
	ctx := context.Background()
	_, st := newVaultStore(t)
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "alice", "a@x", "Alice", "user")
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, "main", "Main", u.ID, "hash")
	if err != nil {
		t.Fatal(err)
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
	for _, e := range events[1:] { // all but the "default"-tenant error event
		if e.ProfileID == nil || *e.ProfileID != p.ID || e.UserID == nil || *e.UserID != u.ID {
			t.Fatalf("profile/user join missing: %+v", e)
		}
	}
	if events[0].ProfileID != nil || events[0].UserID != nil {
		t.Fatalf("literal-tenant event must not fake a join: %+v", events[0])
	}
}

// swappableResolver lets one test reconfigure the inner result between calls.
type swappableResolver struct {
	cred proxy.Credential
	err  error
}

func (s *swappableResolver) set(c proxy.Credential, err error) { s.cred, s.err = c, err }
func (s *swappableResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	return s.cred, s.err
}

func TestAuditingResolverNeverBlocks(t *testing.T) {
	_, st := newVaultStore(t)
	inner := fixedResolver{cred: proxy.Credential{AllowedHosts: []string{"a.example.com"}}}
	a := gateway.NewAuditingResolver(inner, st)
	a.Close() // closed writer: subsequent Resolves must not panic or block
	for i := 0; i < 10; i++ {
		if _, err := a.Resolve(proxy.Identity{Server: "s", Tenant: "default"}, "a.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	// All 10 events went to the closed/nil sink and must be counted as dropped.
	if got := a.Dropped(); got != 10 {
		t.Fatalf("expected 10 dropped events, got %d", got)
	}
}
