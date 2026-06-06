// Command gateway is the gigemcp gateway: it seeds the echo server in the
// store, spawns each stored server in an egress-isolated bubblewrap sandbox
// behind an embedded MITM proxy (vault-backed credential injection), and
// serves an aggregated, bearer-authed streamable-HTTP MCP endpoint.
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gigemcp/gigemcp/internal/config"
	gw "github.com/gigemcp/gigemcp/internal/gateway"
	"github.com/gigemcp/gigemcp/internal/netmgr"
	"github.com/gigemcp/gigemcp/internal/proxy"
	"github.com/gigemcp/gigemcp/internal/sandbox"
	"github.com/gigemcp/gigemcp/internal/store"
	"github.com/gigemcp/gigemcp/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "0.1.0"

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if !sandbox.Available() {
		return fmt.Errorf("bwrap sandboxing unavailable: gigemcp requires Linux with bubblewrap installed")
	}

	// Build vault from GIGE_MASTER_KEY (hex-encoded 32 bytes).
	if cfg.MasterKey == "" {
		return fmt.Errorf("GIGE_MASTER_KEY must be set (hex-encoded 32-byte master key)")
	}
	kek, err := hex.DecodeString(cfg.MasterKey)
	if err != nil {
		return fmt.Errorf("GIGE_MASTER_KEY must be hex-encoded: %w", err)
	}
	if len(kek) != 32 {
		return fmt.Errorf("GIGE_MASTER_KEY must decode to exactly 32 bytes, got %d", len(kek))
	}
	v, err := vault.New(kek)
	if err != nil {
		return fmt.Errorf("create vault: %w", err)
	}

	st, err := store.OpenSQLite(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Seed the echo backend.
	if _, err := st.EnsureServer(ctx, "echo", cfg.EchoBinary); err != nil {
		return fmt.Errorf("seed echo server: %w", err)
	}

	// If GIGE_DEMO_TOKEN is set, seed a demo credential for the echo server.
	if cfg.DemoToken != "" {
		if err := seedDemoCredential(ctx, st, v, cfg); err != nil {
			return fmt.Errorf("seed demo credential: %w", err)
		}
	}

	// Build the egress proxy.
	reg := proxy.NewRegistry()
	resolver := &gw.CredResolver{Store: st, Vault: v}
	egProxy, err := proxy.New(reg, resolver)
	if err != nil {
		return fmt.Errorf("create proxy: %w", err)
	}

	// Write the proxy CA cert to a temp file for mounting into sandboxes.
	caFile, err := writeTempCA(egProxy.CACertPEM())
	if err != nil {
		return fmt.Errorf("write CA file: %w", err)
	}
	defer os.Remove(caFile)

	// Start the proxy listener on all interfaces at the configured port.
	// Each sandbox's default route points to its own /30 host-side IP, which
	// is reachable because the proxy listens on 0.0.0.0.
	proxyLn, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", cfg.ProxyPort))
	if err != nil {
		return fmt.Errorf("listen proxy on :%d: %w", cfg.ProxyPort, err)
	}
	go func() {
		if err := egProxy.Serve(proxyLn); err != nil {
			log.Printf("proxy serve error: %v", err)
		}
	}()
	log.Printf("egress proxy listening on 0.0.0.0:%d", cfg.ProxyPort)

	// Set system roots in production (nil = stdlib default).
	egProxy.SetUpstreamRoots(nil)

	// Subnet allocator for per-sandbox /30s.
	alloc := netmgr.NewAllocator("10.88.0.0/16")

	servers, err := st.ListServers(ctx)
	if err != nil {
		return fmt.Errorf("list servers: %w", err)
	}

	var backends []gw.Backend
	var cleanups []func()
	for _, srv := range servers {
		sess, cleanup, err := gw.SpawnEgressBackend(ctx, srv, alloc, reg, cfg.ProxyPort, caFile, cfg.BootstrapPath)
		if err != nil {
			return fmt.Errorf("spawn egress backend %q: %w", srv.Name, err)
		}
		cleanups = append(cleanups, cleanup)
		backends = append(backends, gw.Backend{Name: srv.Name, Session: sess})
		log.Printf("backend %q running in egress sandbox", srv.Name)
	}
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()

	gwServer, err := gw.New(ctx, version, backends)
	if err != nil {
		return err
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return gwServer }, nil)
	log.Printf("gigemcp %s listening on %s (%d backend(s))", version, cfg.Listen, len(backends))
	return http.ListenAndServe(cfg.Listen, gw.RequireBearer(cfg.BearerToken, handler))
}

// seedDemoCredential encrypts GIGE_DEMO_TOKEN and stores it for the echo server
// so the stack works out-of-the-box without extra setup.
func seedDemoCredential(ctx context.Context, st store.Store, v *vault.Vault, cfg config.Config) error {
	encrypted, err := v.Encrypt([]byte(cfg.DemoToken))
	if err != nil {
		return err
	}
	allowed := []string{"api.example.com"}
	if cfg.DemoAllow != "" {
		allowed = strings.Split(cfg.DemoAllow, ",")
		for i, h := range allowed {
			allowed[i] = strings.TrimSpace(h)
		}
	}
	return st.PutCredential(ctx, store.Credential{
		Server:       "echo",
		Tenant:       "default",
		EncryptedKey: encrypted,
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
		Placeholder:  "PLACEHOLDER",
		AllowedHosts: allowed,
	})
}

// writeTempCA writes PEM bytes to a temp file and returns its path.
func writeTempCA(pem []byte) (string, error) {
	f, err := os.CreateTemp("", "gigemcp-ca-*.pem")
	if err != nil {
		return "", err
	}
	if _, err := f.Write(pem); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
