// Command gateway is the gigmcp gateway: it seeds the echo backend only if
// GIG_ECHO_BIN is set (legacy/dev fallback), installs GIG_INSTALL refs from
// the signed registry index, and serves profile-scoped streamable-HTTP MCP
// endpoints (/mcp/p/{slug}, per-profile bearer tokens) plus the OIDC-gated
// /api control plane. Server runtimes are profile-scoped and spawned lazily
// by the ProfileHost, each in an egress-isolated bubblewrap sandbox behind an
// embedded MITM proxy (vault-backed credential injection).
package main

import (
	"context"
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

	// Build vault from GIG_MASTER_KEY. ParseMasterKey fails closed if the key is
	// missing, not hex, or not exactly 32 bytes.
	kek, err := config.ParseMasterKey(cfg.MasterKey)
	if err != nil {
		return err
	}
	v, err := vault.New(kek)
	if err != nil {
		return fmt.Errorf("create vault: %w", err)
	}
	// vault.New copies the KEK internally, so wiping our slice does not affect
	// the vault. Zeroize to minimize the in-memory window for the master key
	// (defense-in-depth; no hard GC guarantee). NOTE: cfg.MasterKey is a Go
	// string (immutable) and cannot be zeroized — that residual copy remains.
	for i := range kek {
		kek[i] = 0
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
	// Install is record-only: runtimes are profile-scoped and spawned lazily
	// by the ProfileHost on first request to /mcp/p/{slug}.
	if err := installFromIndex(ctx, st, cfg); err != nil {
		return err
	}

	// Reconcile .env OAuth bootstrap into auth_configs. The DB row is the
	// source of truth: bootstrap only SEEDS a vendor that has no row yet, so an
	// operator can override the env via the admin UI without it being clobbered
	// on the next boot. Client secrets are vault-encrypted at rest.
	for vendor, b := range cfg.OAuthBootstrap {
		if _, err := st.GetAuthConfig(ctx, vendor); err == nil {
			continue // DB already has this vendor — DB wins
		}
		var enc []byte
		if b.ClientSecret != "" {
			enc, err = v.Encrypt([]byte(b.ClientSecret))
			if err != nil {
				return fmt.Errorf("encrypt bootstrap secret for %s: %w", vendor, err)
			}
		} else {
			enc = []byte{}
		}
		if err := st.PutAuthConfig(ctx, store.AuthConfig{
			Vendor: vendor, AuthorizeURL: b.AuthorizeURL, TokenURL: b.TokenURL,
			ClientID: b.ClientID, EncryptedClientSecret: enc,
			DefaultScopes: b.DefaultScopes, PKCE: b.PKCE, Mode: "byo",
		}); err != nil {
			return fmt.Errorf("seed auth config %s: %w", vendor, err)
		}
		log.Printf("seeded OAuth auth config for vendor %q from GIG_OAUTH_%s_*", vendor, strings.ToUpper(vendor))
	}

	// Build the egress proxy.
	reg := proxy.NewRegistry()
	var broker *auth.OAuthBroker
	if cfg.PublicURL != "" {
		callbackURL := strings.TrimRight(cfg.PublicURL, "/") + "/api/connections/oauth/callback"
		broker, err = auth.NewOAuthBroker(st, v, callbackURL, cfg.PublicURL)
		if err != nil {
			return fmt.Errorf("build oauth broker: %w", err)
		}
		log.Printf("OAuth broker enabled (callback %s)", callbackURL)
	} else {
		log.Printf("OAuth broker disabled: GIG_PUBLIC_URL not set (needed for an absolute callback URL)")
	}
	credResolver := &gw.CredResolver{Store: st, Vault: v}
	if broker != nil {
		credResolver.Broker = broker
	}
	resolver := gw.NewAuditingResolver(credResolver, st)
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

	profiles := &gw.ProfileHost{
		Store:   st,
		Version: version,
		Spawn: func(ctx context.Context, srv store.Server, tenant string) (*gw.EgressBackend, error) {
			// The placeholder sentinel lives ONLY in the manifests table — the
			// installer never writes it into any environment. It must be looked
			// up here and passed to SpawnEgressBackend, which sets it as
			// GIG_PLACEHOLDER inside the sandbox; the proxy matches the same
			// manifest sentinel when swapping in the real credential.
			//
			// This is also the re-consent fail-closed gate (DESIGN #7): a server
			// whose installed manifest differs from the last user-consented hash
			// is refused, so registry updates (expanded allowed_hosts,
			// injections, …) never take effect silently on the next spawn.
			placeholder := ""
			rec, err := st.GetManifest(ctx, srv.Name)
			switch {
			case err == nil:
				if rec.NeedsReconsent() {
					return nil, fmt.Errorf("server %q requires re-consent (manifest changed); refusing to spawn", srv.Name)
				}
				if len(rec.Injections) > 0 {
					placeholder = rec.Injections[0].Placeholder
				}
			case errors.Is(err, store.ErrManifestNotFound):
				// Legacy server (GIG_ECHO_BIN): no manifest; SpawnEgressBackend
				// falls back to the literal "PLACEHOLDER" sentinel, matching the
				// credential row's default.
			default:
				return nil, fmt.Errorf("manifest for %q: %w", srv.Name, err)
			}
			return gw.SpawnEgressBackend(ctx, srv, alloc, reg, cfg.ProxyPort, caFile, cfg.BootstrapPath, tenant, placeholder)
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
		log.Printf("WARN: GIG_OIDC_* not configured — /api control plane disabled (/mcp/p/{slug} profile endpoints still served)")
	}

	log.Printf("gigmcp %s listening on %s", version, cfg.Listen)
	return http.ListenAndServe(cfg.Listen, buildMux(st, v, authn, broker, newInstaller(cfg, st, false), newRegistryClient(cfg), profiles))
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
// The file is created world-readable (0644) because the CA cert is a public
// certificate (not a secret) and the bwrap sandbox runs as uid 65534, which
// must be able to read it at /etc/gigmcp-ca.pem. os.CreateTemp creates files
// at 0600, so we chmod immediately after closing.
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
	if err := os.Chmod(f.Name(), 0644); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// newInstaller constructs an *registry.IndexInstaller from cfg and st.
// autoConsent should be true for operator-initiated boot installs (GIG_INSTALL),
// which auto-consent even on UPGRADE (the deploy config is the standing
// consent), and false for API-driven installs. Either way a FIRST install is
// self-consenting (the explicit install action is the consent), so an
// API-installed server can spawn; only a manifest CHANGE to an already-consented
// server stays gated behind re-consent on the API path (DESIGN #7). See
// IndexInstaller.AutoConsent.
func newInstaller(cfg config.Config, st store.Store, autoConsent bool) *registry.IndexInstaller {
	return &registry.IndexInstaller{
		Store:       st,
		Client:      &registry.Client{IndexURL: cfg.RegistryIndexURL, PublicKeyHex: cfg.RegistryPubKey},
		Puller:      &oci.Puller{},
		DataDir:     cfg.DataDir,
		AutoConsent: autoConsent,
	}
}

// newRegistryClient builds the catalog-browsing registry client, or nil when
// GIG_REGISTRY_INDEX_URL/GIG_REGISTRY_PUBKEY are unset (the catalog endpoint
// then answers 501 registry_disabled).
func newRegistryClient(cfg config.Config) *registry.Client {
	if cfg.RegistryIndexURL == "" || cfg.RegistryPubKey == "" {
		return nil
	}
	return &registry.Client{IndexURL: cfg.RegistryIndexURL, PublicKeyHex: cfg.RegistryPubKey}
}

// installFromIndex installs each GIG_INSTALL ref from the signed registry
// index (record-only; the ProfileHost spawns lazily on first profile request).
// Boot installs are operator-initiated, so consent is recorded at install time.
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
