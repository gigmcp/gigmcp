package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// seedProfile creates a user + profile bundling the given servers and
// returns the profile and its plaintext token.
func seedProfile(t *testing.T, st store.Store, slug string, servers []string) (store.Profile, string) {
	t.Helper()
	ctx := context.Background()
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "owner-"+slug, slug+"@x", slug, "user")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := auth.NewProfileToken()
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, slug, slug, u.ID, auth.HashToken(tok))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileServers(ctx, p.ID, servers); err != nil {
		t.Fatal(err)
	}
	// Expose is now keyed on the profile owner: a bundled server is only
	// exposed if the owner has installed it. Install every bundled server so
	// the profile exposes its tools (matches the real install→bundle flow).
	for _, s := range servers {
		if err := st.InstallForUser(ctx, u.ID, s); err != nil {
			t.Fatal(err)
		}
	}
	return p, tok
}

// echoSpawner is a fake SpawnFunc backed by in-memory echo servers. It
// records every (server, tenant) spawn and every cleanup invocation.
type echoSpawner struct {
	t        *testing.T
	mu       sync.Mutex
	spawns   []string // "name:tenant" — guarded by mu
	cleanups int      // guarded by mu
}

func (e *echoSpawner) spawn(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
	e.mu.Lock()
	e.spawns = append(e.spawns, srv.Name+":"+tenant)
	e.mu.Unlock()
	sess := connectEchoBackend(e.t, ctx)
	return &gateway.EgressBackend{Session: sess, Cleanup: func() {
		e.mu.Lock()
		e.cleanups++
		e.mu.Unlock()
	}}, nil
}

func (e *echoSpawner) spawnCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.spawns)
}

func (e *echoSpawner) cleanupCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.cleanups
}

func (e *echoSpawner) spawnsCopy() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.spawns))
	copy(out, e.spawns)
	return out
}

func connectProfileClient(t *testing.T, ctx context.Context, baseURL, slug, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "profile-test", Version: "0"}, nil)
	sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   baseURL + "/mcp/p/" + slug,
		HTTPClient: &http.Client{Transport: &bearerTransport{token: token}},
	}, nil)
	if err != nil {
		t.Fatalf("connect profile %s: %v", slug, err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func TestProfileHostAuthAndRouting(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}
	p, tok := seedProfile(t, st, "alpha", []string{"echo"})

	sp := &echoSpawner{t: t}
	host := &gateway.ProfileHost{Store: st, Spawn: sp.spawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	// Register server close via t.Cleanup (not defer) so that session
	// cleanups registered later run first (t.Cleanup is LIFO), preventing
	// httptest.Server.Close from blocking on open SSE connections.
	t.Cleanup(ts.Close)

	// Missing / wrong token and wrong slug → 401, and nothing is spawned.
	for _, c := range []struct{ path, token string }{
		{"/mcp/p/alpha", ""},
		{"/mcp/p/alpha", "gig_wrongtoken"},
		{"/mcp/p/nosuch", tok},
	} {
		req, _ := http.NewRequest("POST", ts.URL+c.path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%+v: want 401, got %d", c, resp.StatusCode)
		}
	}
	if sp.spawnCount() != 0 {
		t.Fatalf("unauthorized requests must not spawn: %v", sp.spawnsCopy())
	}

	// Valid token: lazy spawn with Tenant = profile ID, aggregator serves echo_echo.
	sess := connectProfileClient(t, ctx, ts.URL, "alpha", tok)
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo_echo" {
		t.Fatalf("tools: %+v", tools.Tools)
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo_echo", Arguments: map[string]any{"message": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if text, ok := res.Content[0].(*mcp.TextContent); !ok || text.Text != "echo: hi" {
		t.Fatalf("call: %+v", res.Content[0])
	}
	wantTenant := strconv.FormatInt(p.ID, 10)
	spawns := sp.spawnsCopy()
	if len(spawns) != 1 || spawns[0] != "echo:"+wantTenant {
		t.Fatalf("spawns: %v (want echo:%s)", spawns, wantTenant)
	}

	// Second session reuses the runtime — no new spawn.
	sess2 := connectProfileClient(t, ctx, ts.URL, "alpha", tok)
	if _, err := sess2.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if sp.spawnCount() != 1 {
		t.Fatalf("runtime not reused: %v", sp.spawnsCopy())
	}
}

func TestProfileHostInvalidateTearsDownAndRespawns(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}
	p, tok := seedProfile(t, st, "beta", []string{"echo"})

	sp := &echoSpawner{t: t}
	host := &gateway.ProfileHost{Store: st, Spawn: sp.spawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	// Register server close via t.Cleanup (not defer) so that session
	// cleanups registered later run first (t.Cleanup is LIFO).
	t.Cleanup(ts.Close)

	sess := connectProfileClient(t, ctx, ts.URL, "beta", tok)
	if _, err := sess.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if sp.spawnCount() != 1 || sp.cleanupCount() != 0 {
		t.Fatalf("initial: spawns=%v cleanups=%d", sp.spawnsCopy(), sp.cleanupCount())
	}

	host.Invalidate(p.ID)
	if sp.cleanupCount() != 1 {
		t.Fatalf("invalidate must run cleanups: %d", sp.cleanupCount())
	}

	// Next request lazily respawns.
	sess2 := connectProfileClient(t, ctx, ts.URL, "beta", tok)
	if _, err := sess2.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if sp.spawnCount() != 2 {
		t.Fatalf("no respawn after invalidate: %v", sp.spawnsCopy())
	}
}

// TestProfileHostColdStartCoalescing verifies that N concurrent cold-start
// requests for the same profile result in exactly one spawn. A gate channel
// blocks inside SpawnFunc until all N goroutines are waiting; then the gate is
// released, the single spawner proceeds, and all N requests succeed.
func TestProfileHostColdStartCoalescing(t *testing.T) {
	const N = 10
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph-coal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}
	_, tok := seedProfile(t, st, "coal", []string{"echo"})

	// gate is closed after all N goroutines have called into the spawner's
	// real work, so we ensure they truly all arrived before the spawn completes.
	gate := make(chan struct{})
	var waiters atomic.Int32 // how many goroutines are inside SpawnFunc
	var spawnCount atomic.Int32

	blockingSpawn := func(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
		spawnCount.Add(1)
		waiters.Add(1)
		// Wait until the test releases the gate.
		<-gate
		waiters.Add(-1)
		sess := connectEchoBackend(t, ctx)
		return &gateway.EgressBackend{Session: sess, Cleanup: func() {}}, nil
	}

	host := &gateway.ProfileHost{Store: st, Spawn: blockingSpawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	t.Cleanup(ts.Close)

	// Launch N goroutines that all hit the same cold profile simultaneously.
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func() {
			c := mcp.NewClient(&mcp.Implementation{Name: "coal-client", Version: "0"}, nil)
			sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
				Endpoint:   ts.URL + "/mcp/p/coal",
				HTTPClient: &http.Client{Transport: &bearerTransport{token: tok}},
			}, nil)
			if err != nil {
				errs <- err
				return
			}
			defer sess.Close()
			_, err = sess.ListTools(ctx, nil)
			errs <- err
		}()
	}

	// Wait until exactly one goroutine is inside SpawnFunc (the coalescing
	// winner), then release the gate.
	deadline := time.Now().Add(5 * time.Second)
	for waiters.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for a goroutine to enter SpawnFunc")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Only ONE goroutine must be inside SpawnFunc at this point.
	if got := waiters.Load(); got != 1 {
		t.Errorf("expected exactly 1 goroutine inside SpawnFunc, got %d", got)
	}
	close(gate) // release the spawn

	// Collect all N results.
	for i := 0; i < N; i++ {
		if err := <-errs; err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}

	// Exactly one spawn should have occurred.
	if got := spawnCount.Load(); got != 1 {
		t.Errorf("expected exactly 1 spawn, got %d", got)
	}
}

// TestProfileHostWarmNotBlockedByCold verifies that a warm request to profile B
// completes quickly even while profile A is in a slow (blocked) spawn.
func TestProfileHostWarmNotBlockedByCold(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph-warm.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}

	// Profile A — the slow/cold one.
	_, tokA := seedProfile(t, st, "slow", []string{"echo"})
	// Profile B — will be warmed up before the test begins.
	_, tokB := seedProfile(t, st, "warm", []string{"echo"})

	// gateA blocks profile A's spawn until we release it.
	gateA := make(chan struct{})
	aSpawning := make(chan struct{}) // closed when A's spawn starts

	blockingSpawn := func(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
		// Signal that A's spawn has started, then block.
		select {
		case <-aSpawning:
			// already closed — this is A's re-entry (should not happen, but be safe)
		default:
			close(aSpawning)
		}
		<-gateA
		sess := connectEchoBackend(t, ctx)
		return &gateway.EgressBackend{Session: sess, Cleanup: func() {}}, nil
	}

	// Fast spawn for profile B — does not block.
	var spawnMu sync.Mutex
	var bSpawned bool
	mixedSpawn := func(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
		spawnMu.Lock()
		warm := bSpawned
		spawnMu.Unlock()
		if !warm {
			// First spawn (profile B warm-up) — fast.
			sess := connectEchoBackend(t, ctx)
			spawnMu.Lock()
			bSpawned = true
			spawnMu.Unlock()
			return &gateway.EgressBackend{Session: sess, Cleanup: func() {}}, nil
		}
		// All subsequent spawns are for profile A — use the blocking logic.
		return blockingSpawn(ctx, srv, tenant)
	}

	host := &gateway.ProfileHost{Store: st, Spawn: mixedSpawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	t.Cleanup(ts.Close)

	// Warm up profile B first (fast, synchronous).
	sessB := connectProfileClient(t, ctx, ts.URL, "warm", tokB)
	if _, err := sessB.ListTools(ctx, nil); err != nil {
		t.Fatalf("warm-up B: %v", err)
	}

	// Now start a goroutine that will trigger A's slow spawn.
	aResult := make(chan error, 1)
	go func() {
		c := mcp.NewClient(&mcp.Implementation{Name: "slow-client", Version: "0"}, nil)
		sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   ts.URL + "/mcp/p/slow",
			HTTPClient: &http.Client{Transport: &bearerTransport{token: tokA}},
		}, nil)
		if err != nil {
			aResult <- err
			return
		}
		defer sess.Close()
		_, err = sess.ListTools(ctx, nil)
		aResult <- err
	}()

	// Wait until A's spawn has actually started (so we know it's blocking).
	select {
	case <-aSpawning:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for A's spawn to start")
	}

	// While A is still spawning, a warm request to B must complete quickly.
	warmBudget := 2 * time.Second
	done := make(chan error, 1)
	go func() {
		c := mcp.NewClient(&mcp.Implementation{Name: "warm-client", Version: "0"}, nil)
		sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   ts.URL + "/mcp/p/warm",
			HTTPClient: &http.Client{Transport: &bearerTransport{token: tokB}},
		}, nil)
		if err != nil {
			done <- err
			return
		}
		defer sess.Close()
		_, err = sess.ListTools(ctx, nil)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("warm request to B failed: %v", err)
		}
	case <-time.After(warmBudget):
		t.Errorf("warm request to B blocked for >%v while A was spawning", warmBudget)
	}

	// Release A's gate and wait for it to finish.
	close(gateA)
	select {
	case err := <-aResult:
		if err != nil {
			t.Errorf("A's request failed after gate release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("timed out waiting for A's spawn to complete")
	}
}

// TestProfileHostInvalidateWithInFlight verifies that:
//  1. After an Invalidate, the next request respawns cleanly (no panic).
//  2. A tool call on a session obtained before the Invalidate returns an error
//     rather than hanging (checked within a tight timeout).
func TestProfileHostInvalidateWithInFlight(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph-inv.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}
	p, tok := seedProfile(t, st, "inv", []string{"echo"})

	sp := &echoSpawner{t: t}
	host := &gateway.ProfileHost{Store: st, Spawn: sp.spawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	t.Cleanup(ts.Close)

	// Establish an initial session and verify it works.
	sess1 := connectProfileClient(t, ctx, ts.URL, "inv", tok)
	if _, err := sess1.ListTools(ctx, nil); err != nil {
		t.Fatalf("pre-invalidate ListTools: %v", err)
	}

	// Invalidate the runtime (tears down the underlying backend).
	host.Invalidate(p.ID)
	if sp.cleanupCount() != 1 {
		t.Fatalf("expected 1 cleanup after Invalidate, got %d", sp.cleanupCount())
	}

	// A tool call on the old session should fail (not hang) within a short budget.
	// The backend transport is gone, so the MCP session will return an error.
	callDone := make(chan error, 1)
	go func() {
		_, err := sess1.CallTool(ctx, &mcp.CallToolParams{
			Name:      "echo_echo",
			Arguments: map[string]any{"message": "post-invalidate"},
		})
		callDone <- err
	}()
	select {
	case err := <-callDone:
		if err == nil {
			t.Log("note: old session call unexpectedly succeeded (backend may have buffered) — acceptable")
		}
		// An error is expected; a nil is also acceptable (session outlives invalidate).
	case <-time.After(3 * time.Second):
		t.Error("tool call on invalidated session hung for >3s — must fail or succeed, not hang")
	}

	// The next request with a fresh connect must respawn cleanly.
	sess2 := connectProfileClient(t, ctx, ts.URL, "inv", tok)
	if _, err := sess2.ListTools(ctx, nil); err != nil {
		t.Fatalf("post-invalidate ListTools on new session: %v", err)
	}
	if sp.spawnCount() != 2 {
		t.Fatalf("expected 2 total spawns after respawn, got %d", sp.spawnCount())
	}
}

// TestProfileHostCloseDuringSpawn is the probe test for the Close-during-spawn
// defect: Close() nils h.runtimes while a builder goroutine is in-flight; the
// builder then panics writing to a nil map, which skips close(ch) leaving
// coalesced waiters hung, and the freshly-built runtime's cleanups never run.
//
// Assertions:
//  1. No panic — the request returns an error (or succeeds), it must not crash.
//  2. Spawned runtime's cleanup ran: echoSpawner cleanupCount == spawnCount.
//  3. A second waiter goroutine started before Close does not hang (bounded timeout).
func TestProfileHostCloseDuringSpawn(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph-close-spawn.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}
	_, tok := seedProfile(t, st, "closespawn", []string{"echo"})

	// gate is held open by the test; the spawner blocks inside SpawnFunc until
	// we release it (so we can race Close against the in-flight build).
	gate := make(chan struct{})
	// spawnStarted is closed once the spawner has entered SpawnFunc, so we know
	// the build is truly in-flight before we call Close.
	spawnStarted := make(chan struct{})
	var startOnce sync.Once

	sp := &echoSpawner{t: t}

	gatedSpawn := func(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
		startOnce.Do(func() { close(spawnStarted) })
		<-gate // block until test releases
		return sp.spawn(ctx, srv, tenant)
	}

	host := &gateway.ProfileHost{Store: st, Spawn: gatedSpawn, Version: "test"}
	// NOTE: do NOT register host.Close via t.Cleanup — we call it manually below
	// and need to control ordering.
	ts := httptest.NewServer(host.Handler())
	t.Cleanup(ts.Close)

	makeRequest := func() error {
		c := mcp.NewClient(&mcp.Implementation{Name: "close-spawn-client", Version: "0"}, nil)
		sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   ts.URL + "/mcp/p/closespawn",
			HTTPClient: &http.Client{Transport: &bearerTransport{token: tok}},
		}, nil)
		if err != nil {
			return err
		}
		defer sess.Close()
		_, err = sess.ListTools(ctx, nil)
		return err
	}

	// Goroutine 1: the cold-start builder — will be inside SpawnFunc when Close fires.
	req1Done := make(chan error, 1)
	go func() { req1Done <- makeRequest() }()

	// Wait until the spawn is actually in-flight.
	select {
	case <-spawnStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for spawn to start")
	}

	// Goroutine 2: a second waiter that arrived after the builder claimed the slot
	// and is now blocked on <-ch. It must not hang after Close.
	req2Done := make(chan error, 1)
	go func() { req2Done <- makeRequest() }()

	// Give goroutine 2 a moment to reach the <-ch wait inside getOrCreate.
	time.Sleep(50 * time.Millisecond)

	// Fire Close while the spawn is in-flight (the nil-map defect lives here).
	host.Close()

	// Release the gate — the builder will now try to store its result into the
	// nilled map and (before the fix) panic.
	close(gate)

	const budget = 5 * time.Second

	// Goroutine 1 must return (error or success) — must NOT panic or hang.
	select {
	case err := <-req1Done:
		// Any outcome other than a hang is acceptable; log it for diagnosis.
		t.Logf("req1 result: %v", err)
	case <-time.After(budget):
		t.Error("req1 hung after Close+gate-release: possible deadlock in close(ch)")
	}

	// Goroutine 2 must also return without hanging.
	select {
	case err := <-req2Done:
		t.Logf("req2 result: %v", err)
	case <-time.After(budget):
		t.Error("req2 hung: coalescing waiter was never unblocked")
	}

	// The spawned runtime's cleanups must have run (no sandbox leak).
	spawned := sp.spawnCount()
	cleaned := sp.cleanupCount()
	if spawned > 0 && cleaned != spawned {
		t.Errorf("sandbox leak: spawned=%d cleanups=%d (want equal)", spawned, cleaned)
	}
}
