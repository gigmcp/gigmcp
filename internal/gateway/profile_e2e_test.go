//go:build linux

package gateway_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/netmgr"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/sandbox"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestProfileScopedEgressE2E proves the multi-tenant path end to end:
// (a) profile A's token cannot reach profile B's endpoint,
// (b) egress through each profile injects ITS OWNER's credential,
// (c) audit rows exist for both tenants.
func TestProfileScopedEgressE2E(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("profile E2E requires Linux + NET_ADMIN — run `make test`")
	}
	ctx := context.Background()

	// 1. Upstream TLS server recording Authorization headers.
	var mu sync.Mutex
	var sawAuth []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()
	upstreamInfo, err := gateway.NewTLSServerInfo(upstream.URL, &upstream.TLS.Certificates[0])
	if err != nil {
		t.Fatal(err)
	}

	// 2. Static binaries.
	fetchBin := buildBin(t, "cmd/fetch-mcp")
	bootstrapBin := buildBin(t, "cmd/bootstrap")

	// 3. Vault + store.
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pe2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "fetch", fetchBin); err != nil {
		t.Fatal(err)
	}

	// 4. Two users with DIFFERENT credentials (tenant = user ID), one profile each.
	seed := func(sub, slug, secret string) (store.Profile, string) {
		t.Helper()
		u, err := st.UpsertUserByOIDC(ctx, "https://idp", sub, sub+"@x", sub, "user")
		if err != nil {
			t.Fatal(err)
		}
		enc, err := v.Encrypt([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.PutCredential(ctx, store.Credential{
			Server: "fetch", Tenant: strconv.FormatInt(u.ID, 10), EncryptedKey: enc,
			InjectHeader: "Authorization", InjectFormat: "Bearer {token}",
			Placeholder: "PLACEHOLDER", AllowedHosts: []string{upstreamInfo.Host},
		}); err != nil {
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
		if err := st.SetProfileServers(ctx, p.ID, []string{"fetch"}); err != nil {
			t.Fatal(err)
		}
		// Expose is keyed on the profile owner: install the bundled server so
		// it is exposed for this owner's profile.
		if err := st.InstallForUser(ctx, u.ID, "fetch"); err != nil {
			t.Fatal(err)
		}
		return p, tok
	}
	profA, tokA := seed("alice", "alice-main", "REALKEY_A")
	profB, tokB := seed("bob", "bob-main", "REALKEY_B")

	// 5. Proxy with the auditing resolver.
	reg := proxy.NewRegistry()
	auditing := gateway.NewAuditingResolver(&gateway.CredResolver{Store: st, Vault: v}, st)
	// idempotent; guards goroutine leak on mid-test t.Fatal — explicit ordered Close below still runs first on the happy path
	t.Cleanup(auditing.Close)
	p, err := proxy.New(reg, auditing, proxy.WithDialControl(proxy.AllowLoopbackDialControl()))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(upstreamInfo.Certificate)
	p.SetUpstreamRoots(pool)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port
	p.SetAddr(ln.Addr().String())
	go p.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, p.CACertPEM(), 0644); err != nil {
		t.Fatal(err)
	}
	// distinct CIDR avoids veth/IP collision with egress_e2e_test.go (10.88) and registry_e2e_test.go (10.97)
	alloc := netmgr.NewAllocator("10.99.0.0/16")

	// 6. ProfileHost with the REAL spawner — Tenant = profile ID.
	// SpawnEgressBackend signature after Task 13: (ctx, srv, alloc, reg, proxyPort,
	// caFile, bootstrapPath, tenant, placeholder). Pass "" for placeholder so
	// SpawnEgressBackend falls back to "PLACEHOLDER" (legacy path; the fetch-mcp
	// binary reads GIG_PLACEHOLDER from the sandbox environment).
	host := &gateway.ProfileHost{
		Store: st, Version: "e2e",
		Spawn: func(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
			return gateway.SpawnEgressBackend(ctx, srv, alloc, reg, proxyPort, caFile, bootstrapBin, tenant, "")
		},
	}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	defer ts.Close()

	// (a) Cross-profile token rejection: token A against B's endpoint → 401.
	req, _ := http.NewRequest("POST", ts.URL+"/mcp/p/bob-main", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token A on profile B must 401, got %d", resp.StatusCode)
	}

	// (b) Each profile injects its OWNER's key.
	callFetch := func(slug, token string) string {
		t.Helper()
		c := mcp.NewClient(&mcp.Implementation{Name: "pe2e", Version: "0"}, nil)
		sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   ts.URL + "/mcp/p/" + slug,
			HTTPClient: &http.Client{Transport: &bearerTransport{token: token}},
		}, nil)
		if err != nil {
			t.Fatalf("connect %s: %v", slug, err)
		}
		defer sess.Close()
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "fetch_fetch", // aggregator namespaces fetch's "fetch" tool
			Arguments: map[string]any{"url": upstream.URL},
		})
		if err != nil {
			t.Fatalf("call fetch via %s: %v", slug, err)
		}
		text, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatalf("content: %+v", res.Content[0])
		}
		return text.Text
	}

	lastAuth := func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(sawAuth) == 0 {
			return ""
		}
		return sawAuth[len(sawAuth)-1]
	}

	if out := callFetch("alice-main", tokA); !strings.Contains(out, "upstream-ok") {
		t.Fatalf("fetch via A failed: %q", out)
	}
	if got := lastAuth(); got != "Bearer REALKEY_A" {
		t.Fatalf("profile A egress injected %q, want Bearer REALKEY_A", got)
	}
	if out := callFetch("bob-main", tokB); !strings.Contains(out, "upstream-ok") {
		t.Fatalf("fetch via B failed: %q", out)
	}
	if got := lastAuth(); got != "Bearer REALKEY_B" {
		t.Fatalf("profile B egress injected %q, want Bearer REALKEY_B", got)
	}

	// (c) Audit rows exist for both tenants. Close the host FIRST so no
	// late Resolve races the auditor shutdown, then flush.
	host.Close()
	auditing.Close()
	events, err := st.ListAudit(ctx, 0, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	var gotA, gotB bool
	for _, e := range events {
		if e.Kind != "egress" || e.Decision != "resolved" || e.ProfileID == nil {
			continue
		}
		if *e.ProfileID == profA.ID {
			gotA = true
		}
		if *e.ProfileID == profB.ID {
			gotB = true
		}
	}
	if !gotA || !gotB {
		t.Fatalf("missing egress audit rows: A=%v B=%v (%d events)", gotA, gotB, len(events))
	}
}
