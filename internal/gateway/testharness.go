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

	"github.com/gigmcp/gigmcp/internal/netmgr"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// EgressTestGateway is a live egress gateway assembled for an integration test.
// Call Close to tear down.
type EgressTestGateway struct {
	sess     *mcp.ClientSession
	cleanup  func()
	ChildPID int // sandbox child PID (bwrap --info-fd child); valid until Close() is called
}

// Close tears down the egress gateway (kills the sandbox, removes veth, etc.).
func (g *EgressTestGateway) Close() {
	if g.cleanup != nil {
		g.cleanup()
	}
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
	// The upstream is a loopback httptest TLS server, which the production egress
	// SSRF guard refuses — inject the permissive dialer for the e2e flow.
	p, err := proxy.New(reg, resolver, proxy.WithDialControl(proxy.AllowLoopbackDialControl()))
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
	// IMPORTANT: keep mode 0644 here so tests exercise the sandbox uid (65534)
	// reading the CA — this must match production's writeTempCA (cmd/gateway/main.go)
	// which also chmods to 0644. If the two diverge, the egress E2E tests will
	// pass while production fails with "permission denied" reading the CA cert.
	caFile := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(caFile, p.CACertPEM(), 0644); err != nil {
		t.Fatalf("write CA PEM: %v", err)
	}

	// 6. Netmgr allocator.
	alloc := netmgr.NewAllocator("10.88.0.0/16")

	// 7. Server record.
	srv := store.Server{Name: "fetch", Binary: fetchBin}

	// 8. Spawn the egress sandbox.
	eb, err := SpawnEgressBackend(ctx, srv, alloc, reg, proxyPort, caFile, bootstrapBin, "default", "")
	if err != nil {
		t.Fatalf("SpawnEgressBackend: %v", err)
	}
	t.Logf("egress backend spawned; proxy on 0.0.0.0:%d, upstream on %s:%d, child pid=%d", proxyPort, upstreamHost, upstream.Port, eb.ChildPID)

	return &EgressTestGateway{sess: eb.Session, cleanup: eb.Cleanup, ChildPID: eb.ChildPID}
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
