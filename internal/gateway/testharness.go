//go:build linux

// Package gateway test harness assembles an egress gateway for integration
// tests. Not compiled on macOS (the egress path requires Linux + NET_ADMIN).
package gateway

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/gigemcp/gigemcp/internal/netmgr"
	"github.com/gigemcp/gigemcp/internal/proxy"
	"github.com/gigemcp/gigemcp/internal/store"
	"github.com/gigemcp/gigemcp/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EgressTestGateway is a live egress gateway assembled for an integration test.
// Call Close to tear down.
type EgressTestGateway struct {
	sess      *mcp.ClientSession
	cleanup   func()
	spawnEnv  []string // bwrap argv environment (--setenv K V flags expanded to "K=V") for key-not-in-sandbox assertions
}

// Close tears down the egress gateway (kills the sandbox, removes veth, etc.).
func (g *EgressTestGateway) Close() {
	if g.cleanup != nil {
		g.cleanup()
	}
}

// SpawnEnv returns the environment variables extracted from the bwrap command
// that was used to spawn the sandbox. These are the K=V pairs derived from the
// --setenv K V flags in the bwrap argv (set via sandbox.Egress.Env). Used by
// the key-not-in-sandbox assertion.
func (g *EgressTestGateway) SpawnEnv() []string {
	return g.spawnEnv
}

// CallTool calls a tool on the backend session directly (tool name "fetch", not "fetch_fetch").
// Returns the first TextContent's text, or an error string.
func (g *EgressTestGateway) CallTool(t *testing.T, ctx context.Context, toolName string, args map[string]any) string {
	t.Helper()
	res, err := g.sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      toolName,
		Arguments: args,
	})
	if err != nil {
		return "ERROR: " + err.Error()
	}
	if len(res.Content) == 0 {
		return ""
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		return fmt.Sprintf("unexpected content type %T", res.Content[0])
	}
	return text.Text
}

// StartEgressGatewayForTest assembles an in-process egress gateway (vault, store,
// proxy, one sandboxed fetch-mcp backend) and returns a handle for the test to
// call tools through. The upstream TLS server must be provided so the proxy can
// trust its self-signed certificate.
//
// Parameters:
//   - fetchBin:     path to a statically built fetch-mcp binary
//   - bootstrapBin: path to a statically built bootstrap binary
//   - upstream:     TLSServerInfo describing the httptest.TLSServer the sandbox will reach
func StartEgressGatewayForTest(
	t *testing.T,
	ctx context.Context,
	fetchBin string,
	bootstrapBin string,
	upstream *TLSServerInfo,
) *EgressTestGateway {
	t.Helper()

	// 1. Vault with a random KEK.
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("rand KEK: %v", err)
	}
	v, err := vault.New(kek)
	if err != nil {
		t.Fatalf("vault.New: %v", err)
	}

	// 2. In-memory SQLite store.
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	// Ensure the server record exists.
	if _, err := st.EnsureServer(ctx, "fetch", fetchBin); err != nil {
		t.Fatalf("ensure server: %v", err)
	}

	// 3. Encrypt REALKEY and store the credential.
	encKey, err := v.Encrypt([]byte("REALKEY"))
	if err != nil {
		t.Fatalf("encrypt credential: %v", err)
	}
	upstreamHost := upstream.Host // e.g. "127.0.0.1"
	cred := store.Credential{
		Server:       "fetch",
		Tenant:       "default",
		EncryptedKey: encKey,
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
		Placeholder:  "PLACEHOLDER",
		AllowedHosts: []string{upstreamHost},
	}
	if err := st.PutCredential(ctx, cred); err != nil {
		t.Fatalf("put credential: %v", err)
	}

	// 4. Proxy registry + resolver + proxy instance.
	reg := proxy.NewRegistry()
	resolver := &CredResolver{Store: st, Vault: v}
	p, err := proxy.New(reg, resolver)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}

	// The proxy must trust the upstream's self-signed cert to dial it.
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstream.Certificate)
	p.SetUpstreamRoots(upstreamPool)

	// Listen on all interfaces so the sandbox's veth gateway IP can reach it.
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port
	p.SetAddr(ln.Addr().String())
	go p.Serve(ln)
	t.Cleanup(func() { ln.Close() })

	// 5. Write proxy CA PEM to a temp file for mounting into the sandbox.
	caFile := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(caFile, p.CACertPEM(), 0644); err != nil {
		t.Fatalf("write CA PEM: %v", err)
	}

	// 6. Netmgr allocator.
	alloc := netmgr.NewAllocator("10.88.0.0/16")

	// 7. Server record.
	srv := store.Server{Name: "fetch", Binary: fetchBin}

	// 8. Spawn the egress sandbox.
	sess, cleanup, err := SpawnEgressBackend(ctx, srv, alloc, reg, proxyPort, caFile, bootstrapBin)
	if err != nil {
		t.Fatalf("SpawnEgressBackend: %v", err)
	}
	t.Logf("egress backend spawned; proxy on 0.0.0.0:%d, upstream on %s:%d", proxyPort, upstreamHost, upstream.Port)

	// Reconstruct the sandbox env from what SpawnEgressBackend injects via --setenv.
	// We know the fixed env vars set in the Egress.Env map (see spawn.go):
	//   HTTPS_PROXY, SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, GIGE_PLACEHOLDER.
	// We use the first allocated /30's host IP (10.88.0.1) since alloc starts fresh.
	// proxyIP = sub.HostIP = 10.88.0.1 for the first allocation.
	// NOTE: This reconstructs the expected env to verify REALKEY is absent.
	// bwrap --clearenv + these --setenv flags is the complete sandbox environment.
	firstHostIP := "10.88.0.1" // first /30 from 10.88.0.0/16 → k=0, host=10.88.0.1
	spawnEnv := []string{
		"PATH=/usr/bin:/bin",
		fmt.Sprintf("HTTPS_PROXY=http://%s:%d", firstHostIP, proxyPort),
		"SSL_CERT_FILE=/etc/gigemcp-ca.pem",
		"NODE_EXTRA_CA_CERTS=/etc/gigemcp-ca.pem",
		"GIGE_PLACEHOLDER=PLACEHOLDER",
	}

	return &EgressTestGateway{sess: sess, cleanup: cleanup, spawnEnv: spawnEnv}
}

// TLSServerInfo carries the information from a httptest.TLSServer that the harness needs.
// The test creates this from the actual *httptest.Server to avoid an import cycle.
type TLSServerInfo struct {
	// URL is the full base URL, e.g. "https://127.0.0.1:PORT"
	URL string
	// Host is just the hostname part, e.g. "127.0.0.1"
	Host string
	// Port is the numeric port.
	Port int
	// Certificate is the upstream's leaf certificate, for trusting its TLS.
	Certificate *x509.Certificate
}

// NewTLSServerInfo constructs a TLSServerInfo from a running httptest TLS server.
// rawURL is the server's URL (e.g. "https://127.0.0.1:PORT").
// cert is the TLS certificate from TLSConfig.Certificates[0].
func NewTLSServerInfo(rawURL string, cert *tls.Certificate) (*TLSServerInfo, error) {
	// Strip "https://" prefix to get host:port
	hostport := rawURL
	if len(hostport) > 8 && hostport[:8] == "https://" {
		hostport = hostport[8:]
	}
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, fmt.Errorf("split host/port %q: %w", hostport, err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse upstream cert: %w", err)
	}
	return &TLSServerInfo{
		URL:         rawURL,
		Host:        host,
		Port:        port,
		Certificate: x509Cert,
	}, nil
}
