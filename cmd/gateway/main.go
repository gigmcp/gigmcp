// Command gateway is the gigmcp gateway: it seeds the echo backend only if
// GIG_ECHO_BIN is set (legacy/dev fallback), installs GIG_INSTALL refs from
// the signed registry index, spawns each stored server in an egress-isolated
// bubblewrap sandbox behind an embedded MITM proxy (vault-backed credential
// injection), and serves an aggregated, bearer-authed streamable-HTTP MCP
// endpoint.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/config"
	gw "github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/netmgr"
	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/registry"
	"github.com/gigmcp/gigmcp/internal/sandbox"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
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
		return fmt.Errorf("bwrap sandboxing unavailable: gigmcp requires Linux with bubblewrap installed")
	}

	// Belt-and-suspenders FORWARD-drop: ip_forward=1 is the default in the
	// container, so sandboxes could otherwise reach each other or the internet
	// directly. Route isolation (unique /30 per sandbox, only route = proxy) is
	// the primary control; this is defense-in-depth. Best-effort: a warning is
	// logged on failure but the gateway does NOT crash — route isolation remains.
	applyForwardDrop()

	// Build vault from GIG_MASTER_KEY (hex-encoded 32 bytes).
	if cfg.MasterKey == "" {
		return fmt.Errorf("GIG_MASTER_KEY must be set (hex-encoded 32-byte master key)")
	}
	kek, err := hex.DecodeString(cfg.MasterKey)
	if err != nil {
		return fmt.Errorf("GIG_MASTER_KEY must be hex-encoded: %w", err)
	}
	if len(kek) != 32 {
		return fmt.Errorf("GIG_MASTER_KEY must decode to exactly 32 bytes, got %d", len(kek))
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

	// Legacy dev fallback: seed the echo backend only if GIG_ECHO_BIN is set.
	if cfg.EchoBinary != "" {
		if _, err := st.EnsureServer(ctx, "echo", cfg.EchoBinary); err != nil {
			return fmt.Errorf("seed echo server: %w", err)
		}
	}

	// Registry-driven install of the configured boot set (GIG_INSTALL).
	if err := installFromIndex(ctx, st, cfg); err != nil {
		return err
	}

	// If GIG_DEMO_TOKEN is set, seed a demo credential for the echo server.
	if cfg.DemoToken != "" {
		if err := seedDemoCredential(ctx, st, v, cfg); err != nil {
			return fmt.Errorf("seed demo credential: %w", err)
		}
	}

	// Build the egress proxy.
	reg := proxy.NewRegistry()
	resolver := gw.NewAuditingResolver(&gw.CredResolver{Store: st, Vault: v}, st)
	// NOTE: defer resolver.Close() (and defer profiles.Close()) are best-effort
	// flushes only — http.ListenAndServe blocks until process death, so these
	// defers only run on a clean return (e.g. early startup error). Audit writes
	// must never rely on Close() being called for correctness.
	defer resolver.Close()
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

	backends, cleanups, err := spawnInstalled(ctx, st, servers, alloc, reg, cfg, caFile)
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range cleanups {
			c()
		}
	}()

	profiles := &gw.ProfileHost{
		Store:   st,
		Version: version,
		Spawn: func(ctx context.Context, srv store.Server, tenant string) (*gw.EgressBackend, error) {
			// placeholder is sourced from the manifest at spawn time (same as
			// spawnInstalled does); for profile runtimes we pass "" here and
			// let SpawnEgressBackend fall back to "PLACEHOLDER" for legacy
			// servers — manifest-installed servers already carry the placeholder
			// in the sandbox env from the registry installer.
			return gw.SpawnEgressBackend(ctx, srv, alloc, reg, cfg.ProxyPort, caFile, cfg.BootstrapPath, tenant, "")
		},
	}
	defer profiles.Close()

	var authn *auth.Authenticator
	if cfg.OIDCEnabled() {
		bootCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		authn, err = auth.NewAuthenticator(bootCtx, cfg, st)
		cancel()
		if err != nil {
			return fmt.Errorf("oidc setup: %w", err)
		}
		log.Printf("OIDC configured (issuer %s) — /api control plane enabled", cfg.OIDCIssuer)
	} else {
		log.Printf("WARN: GIG_OIDC_* not configured — /api control plane disabled (legacy /mcp still served)")
	}

	gwServer, err := gw.New(ctx, version, backends)
	if err != nil {
		return err
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return gwServer }, nil)
	log.Printf("gigmcp %s listening on %s (%d backend(s))", version, cfg.Listen, len(backends))
	legacy := gw.RequireBearer(cfg.BearerToken, handler)
	return http.ListenAndServe(cfg.Listen, buildMux(st, v, authn, newInstaller(cfg, st, false), profiles, legacy))
}

// seedDemoCredential encrypts GIG_DEMO_TOKEN and stores it for the echo server
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

// applyForwardDrop sets the iptables FORWARD chain default policy to DROP.
// This is a belt-and-suspenders measure: ip_forward=1 is on by default in the
// container, which would let sandboxes route to each other or the internet.
// Route isolation (unique /30 per sandbox, only route = proxy) is the primary
// enforcement; this adds a kernel-level fallback.
//
// Implementation: exec "iptables -P FORWARD DROP". This requires iptables to be
// installed in the container image (see Dockerfile). It is BEST-EFFORT: if the
// call fails (iptables not installed, permission denied, or running on a kernel
// without netfilter), a warning is logged and the gateway continues — route
// isolation is still enforced. Do not use this guarantee for security-critical
// decisions; treat it as defense-in-depth.
func applyForwardDrop() {
	if path, err := exec.LookPath("iptables"); err != nil {
		log.Printf("WARN: applyForwardDrop: iptables not found in PATH; FORWARD policy not set (route isolation still enforced): %v", err)
		return
	} else {
		out, err := exec.Command(path, "-P", "FORWARD", "DROP").CombinedOutput()
		if err != nil {
			log.Printf("WARN: applyForwardDrop: iptables -P FORWARD DROP failed (route isolation still enforced): %v — %s", err, out)
			return
		}
	}
	log.Printf("iptables FORWARD policy set to DROP (defense-in-depth; route isolation is primary)")
}

// writeTempCA writes PEM bytes to a temp file and returns its path.
func writeTempCA(pem []byte) (string, error) {
	f, err := os.CreateTemp("", "gigmcp-ca-*.pem")
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

// newInstaller constructs an *registry.IndexInstaller from cfg and st.
// autoConsent should be true for operator-initiated boot installs (GIG_INSTALL)
// and false for API-driven installs so the frontend consent flow gates the spawn.
func newInstaller(cfg config.Config, st store.Store, autoConsent bool) *registry.IndexInstaller {
	return &registry.IndexInstaller{
		Store:       st,
		Client:      &registry.Client{IndexURL: cfg.RegistryIndexURL, PublicKeyHex: cfg.RegistryPubKey},
		Puller:      &oci.Puller{},
		DataDir:     cfg.DataDir,
		AutoConsent: autoConsent,
	}
}

// installFromIndex installs each GIG_INSTALL ref from the signed registry
// index (record-only; spawning happens in spawnInstalled). Boot installs are
// operator-initiated, so consent is recorded at install time.
func installFromIndex(ctx context.Context, st store.Store, cfg config.Config) error {
	if cfg.Install == "" {
		return nil
	}
	inst := newInstaller(cfg, st, true)
	for _, ref := range strings.Split(cfg.Install, ",") {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if _, err := inst.Install(ctx, ref); err != nil {
			return fmt.Errorf("install %q: %w", ref, err)
		}
		log.Printf("installed %q from registry index", ref)
	}
	return nil
}

// spawnInstalled spawns every stored server, enforcing re-consent (fail
// closed) and wiring the manifest's placeholder + default tool subset.
func spawnInstalled(
	ctx context.Context,
	st store.Store,
	servers []store.Server,
	alloc *netmgr.Allocator,
	reg *proxy.Registry,
	cfg config.Config,
	caFile string,
) ([]gw.Backend, []func(), error) {
	var backends []gw.Backend
	var cleanups []func()
	for _, srv := range servers {
		placeholder := ""
		var expose map[string]bool
		rec, err := st.GetManifest(ctx, srv.Name)
		switch {
		case err == nil:
			if rec.NeedsReconsent() {
				log.Printf("backend %q requires re-consent (manifest changed); NOT spawning", srv.Name)
				continue
			}
			if len(rec.Injections) > 0 {
				placeholder = rec.Injections[0].Placeholder
			}
			expose = map[string]bool{}
			for _, tl := range rec.Tools {
				if tl.Default {
					expose[tl.Name] = true
				}
			}
		case errors.Is(err, store.ErrManifestNotFound):
			// legacy server (GIG_ECHO_BIN): no manifest, expose all tools
		default:
			for _, c := range cleanups {
				c()
			}
			return nil, nil, fmt.Errorf("manifest for %q: %w", srv.Name, err)
		}
		eb, err := gw.SpawnEgressBackend(ctx, srv, alloc, reg, cfg.ProxyPort, caFile, cfg.BootstrapPath, "default", placeholder)
		if err != nil {
			for _, c := range cleanups {
				c()
			}
			return nil, nil, fmt.Errorf("spawn egress backend %q: %w", srv.Name, err)
		}
		cleanups = append(cleanups, eb.Cleanup)
		backends = append(backends, gw.Backend{Name: srv.Name, Session: eb.Session, Expose: expose})
		log.Printf("backend %q running in egress sandbox (pid=%d)", srv.Name, eb.ChildPID)
	}
	return backends, cleanups, nil
}
