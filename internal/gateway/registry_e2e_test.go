package gateway_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/netmgr"
	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/registry"
	"github.com/gigmcp/gigmcp/internal/sandbox"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/registry/schema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildStaticBin compiles a Go package as a CGO_ENABLED=0 static binary.
// Defined here rather than reusing buildBin from egress_e2e_test.go (which has
// a //go:build linux tag) so this file can compile on macOS for the skip path.
func buildStaticBin(t *testing.T, pkg string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), filepath.Base(pkg))
	c := exec.Command("go", "build", "-o", out, "github.com/gigmcp/gigmcp/"+pkg)
	c.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	return out
}

// fakeEchoResolver is a no-op CredentialResolver used in the registry E2E:
// the echo server makes no outbound HTTPS calls so the proxy resolver is
// never invoked. Returning an empty credential is safe here.
type fakeEchoResolver struct{}

func (fakeEchoResolver) Resolve(proxy.Identity, string) (proxy.Credential, error) {
	return proxy.Credential{}, nil
}

// TestRegistryInstallE2E proves the whole pipeline: signed index → resolve →
// pull by digest from an OCI layout → verify → extract → record → spawn in
// the real egress sandbox → tool callable through the aggregator with the
// manifest's default subset.
func TestRegistryInstallE2E(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("registry E2E requires Linux + bwrap — run: make test")
	}
	if os.Geteuid() != 0 {
		t.Skip("registry E2E requires root (uid/gid map writes) — run: make test")
	}
	ctx := context.Background()

	// 1. Build the real echo-mcp static binary and package it as an OCI image.
	t.Log("building echo-mcp...")
	echoBin := buildStaticBin(t, "cmd/echo-mcp")
	t.Logf("echoBin=%s", echoBin)
	binBytes, err := os.ReadFile(echoBin)
	if err != nil {
		t.Fatal(err)
	}
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{"app/echo": binBytes})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("OCI layout written; digest=%s", digest)

	// 2. Build a signed fixture index with one manifest pinning that digest.
	m := &schema.Manifest{
		SchemaVersion: 1, Name: "echo", Version: "0.1.0",
		Source: schema.Source{Repo: "github.com/gigmcp/gigmcp", Tag: "v0.1.0"},
		Image: schema.Image{
			Ref:        "ghcr.io/gigmcp/echo-mcp",
			Digest:     digest,
			Entrypoint: "/app/echo",
		},
		Tier: schema.TierSealed,
		Entitlements: schema.Entitlements{
			Egress: []string{"api.example.com"},
		},
		Credentials: []schema.Credential{{
			ID: "token", Type: "api_key", Provider: "example",
			Inject: schema.Inject{Header: "Authorization", Format: "Bearer {token}"},
		}},
		Tools: []schema.Tool{{Name: "echo", Default: true}},
	}
	ix, err := schema.BuildIndex([]*schema.Manifest{m}, "2026-06-06T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ix)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schema.Sign(hex.EncodeToString(priv), raw)
	if err != nil {
		t.Fatal(err)
	}
	indexDir := t.TempDir()
	idxPath := filepath.Join(indexDir, "index.json")
	if err := os.WriteFile(idxPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idxPath+".sig", []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. Install (record-only): fetch + verify index, pull by digest from the
	// OCI layout, extract binary, record server + manifest, auto-consent.
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	dataDir := t.TempDir()
	inst := &registry.IndexInstaller{
		Store:       st,
		Client:      &registry.Client{IndexURL: "file://" + idxPath, PublicKeyHex: hex.EncodeToString(pub)},
		Puller:      &oci.Puller{LayoutDir: layoutDir},
		DataDir:     dataDir,
		AutoConsent: true,
	}
	srv, err := inst.Install(ctx, "echo@0.1.0")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	t.Logf("installed: server=%q binary=%s", srv.Name, srv.Binary)

	rec, err := st.GetManifest(ctx, "echo")
	if err != nil {
		t.Fatalf("GetManifest: %v", err)
	}
	if rec.NeedsReconsent() {
		t.Fatalf("manifest record should not need reconsent after AutoConsent: %+v", rec)
	}

	// Derive the placeholder from the stored injection — this is the sentinel
	// value the proxy substitutes with the real credential.
	var placeholder string
	if len(rec.Injections) > 0 {
		placeholder = rec.Injections[0].Placeholder
	}
	t.Logf("placeholder=%q", placeholder)

	// 4. Spawn the installed binary in the egress sandbox.
	//
	// Reuse the same component assembly pattern from testharness.go /
	// egress_e2e_test.go:
	//   - proxy.NewRegistry() + fakeEchoResolver (echo makes no outbound calls)
	//   - proxy.New() + listener on 0.0.0.0:0
	//   - netmgr.NewAllocator on 10.97.0.0/16 (distinct CIDR avoids collision
	//     with egress_e2e_test.go which uses 10.88.0.0/16)
	//   - buildStaticBin bootstrap binary
	//   - SpawnEgressBackend with rec.Injections[0].Placeholder
	t.Log("building bootstrap...")
	bootstrapBin := buildStaticBin(t, "cmd/bootstrap")
	t.Logf("bootstrapBin=%s", bootstrapBin)

	reg := proxy.NewRegistry()
	p, err := proxy.New(reg, fakeEchoResolver{})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port
	p.SetAddr(ln.Addr().String())
	go p.Serve(ln)
	t.Cleanup(func() { ln.Close() })

	// Write proxy CA to a temp file — the sandbox needs it to trust the proxy.
	caFile := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(caFile, p.CACertPEM(), 0644); err != nil {
		t.Fatalf("write CA PEM: %v", err)
	}

	alloc := netmgr.NewAllocator("10.97.0.0/16")

	eb, err := gateway.SpawnEgressBackend(ctx, srv, alloc, reg, proxyPort, caFile, bootstrapBin, "default", placeholder)
	if err != nil {
		t.Fatalf("SpawnEgressBackend: %v", err)
	}
	t.Cleanup(eb.Cleanup)
	t.Logf("egress sandbox up; child pid=%d proxy port=%d", eb.ChildPID, proxyPort)

	// 5. Aggregate with the manifest's default-only subset and assert tool list.
	//
	// Build the Expose map from rec.Tools (only Default=true tools are exposed).
	expose := make(map[string]bool)
	for _, tl := range rec.Tools {
		if tl.Default {
			expose[tl.Name] = true
		}
	}
	t.Logf("expose map: %v", expose)

	gw, err := gateway.New(ctx, "e2e", []gateway.Backend{{
		Name:    "echo",
		Session: eb.Session,
		Expose:  expose,
	}})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	// connectGatewayClient is defined in gateway_test.go (same package gateway_test).
	client := connectGatewayClient(t, ctx, gw)

	tools, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo_echo" {
		names := make([]string, len(tools.Tools))
		for i, tl := range tools.Tools {
			names[i] = tl.Name
		}
		t.Fatalf("want exactly [echo_echo], got %v", names)
	}
	t.Log("tool list verified: [echo_echo]")

	// Call echo_echo through the aggregator and verify the response.
	res, err := client.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo_echo",
		Arguments: map[string]any{"message": "hi"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "echo: hi" {
		t.Fatalf("got %+v, want text %q", res.Content[0], "echo: hi")
	}
	t.Logf("echo_echo returned %q — pipeline verified", text.Text)
}
