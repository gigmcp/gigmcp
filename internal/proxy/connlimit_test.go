package proxy

import "testing"

// TestConnLimiterCapsAndReleases verifies the per-identity CONNECT limiter:
// acquisitions succeed up to the cap, the (cap+1)th is rejected, and releasing a
// slot frees room for another acquire.
func TestConnLimiterCapsAndReleases(t *testing.T) {
	const cap = 3
	l := newConnLimiter(cap)
	id := Identity{Server: "srv", Tenant: "t1"}

	for i := 0; i < cap; i++ {
		if !l.acquire(id) {
			t.Fatalf("acquire %d/%d should succeed", i+1, cap)
		}
	}
	// Over the cap: rejected.
	if l.acquire(id) {
		t.Fatalf("acquire beyond cap %d must be rejected", cap)
	}
	// Releasing one slot frees room for exactly one more.
	l.release(id)
	if !l.acquire(id) {
		t.Fatalf("acquire after release should succeed")
	}
	if l.acquire(id) {
		t.Fatalf("acquire should be rejected again once back at cap")
	}
}

// TestConnLimiterPerIdentityIndependent verifies one identity hitting its cap
// does not starve a different identity.
func TestConnLimiterPerIdentityIndependent(t *testing.T) {
	l := newConnLimiter(1)
	a := Identity{Server: "srv", Tenant: "a"}
	b := Identity{Server: "srv", Tenant: "b"}

	if !l.acquire(a) {
		t.Fatal("a's first acquire should succeed")
	}
	if l.acquire(a) {
		t.Fatal("a's second acquire should be rejected (cap=1)")
	}
	if !l.acquire(b) {
		t.Fatal("b must be unaffected by a hitting its cap")
	}
}

// TestConnLimiterReleaseCleansUpMap ensures releasing the last slot removes the
// key so the limiter's map cannot grow unboundedly across many short identities.
func TestConnLimiterReleaseCleansUpMap(t *testing.T) {
	l := newConnLimiter(2)
	id := Identity{Server: "srv", Tenant: "ephemeral"}
	l.acquire(id)
	l.acquire(id)
	l.release(id)
	l.release(id)
	l.mu.Lock()
	_, present := l.count[id]
	l.mu.Unlock()
	if present {
		t.Fatalf("fully-released identity should be deleted from the map")
	}
}
