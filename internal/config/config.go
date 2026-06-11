// Package config reads gateway configuration from the environment
// (compose-env-first per DESIGN.md decision; secrets gain *_FILE support
// in the vault plan).
package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// masterKeyBytes is the required decoded length of GIG_MASTER_KEY (XChaCha20
// key size). 32 bytes = 64 hex characters.
const masterKeyBytes = 32

// ParseMasterKey decodes and validates the hex-encoded GIG_MASTER_KEY. It fails
// closed with an actionable error if the key is missing, not valid hex, or not
// exactly 32 bytes (64 hex chars), so a weak or malformed key can never silently
// produce a degraded vault.
func ParseMasterKey(s string) ([]byte, error) {
	const hint = "generate with: openssl rand -hex 32"
	if s == "" {
		return nil, fmt.Errorf("GIG_MASTER_KEY must be set to 64 hex chars (32 bytes); %s", hint)
	}
	if len(s) != masterKeyBytes*2 {
		return nil, fmt.Errorf("GIG_MASTER_KEY must be 64 hex chars (32 bytes), got %d chars; %s", len(s), hint)
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("GIG_MASTER_KEY must be valid hex: %w; %s", err, hint)
	}
	if len(key) != masterKeyBytes {
		return nil, fmt.Errorf("GIG_MASTER_KEY must decode to 32 bytes, got %d; %s", len(key), hint)
	}
	return key, nil
}

// OAuthVendorBootstrap is a single global OAuth vendor provider configured via
// GIG_OAUTH_<VENDOR>_* env. The DB auth_configs table is the source of truth
// when a row for the same vendor exists; bootstrap only seeds it at startup.
type OAuthVendorBootstrap struct {
	ClientID      string
	ClientSecret  string // from GIG_OAUTH_<V>_CLIENT_SECRET or _FILE
	AuthorizeURL  string
	TokenURL      string
	DefaultScopes []string
	PKCE          bool
}

// Config is the gateway's runtime configuration.
//
// Authentication surfaces: MCP clients authenticate with per-profile bearer
// tokens on /mcp/p/{slug} (minted via the control plane, stored hashed); the
// /api control plane authenticates with OIDC sessions. Neither requires a
// static gateway-wide secret, so the gateway boots with no auth-related env
// at all: profile endpoints work as soon as a profile token exists, and /api
// answers with a descriptive control_plane_disabled 404 until GIG_OIDC_* is
// configured.
type Config struct {
	Listen           string        // GIG_LISTEN, default ":8080"
	DBPath           string        // GIG_DB_PATH, default "gigmcp.db"
	EchoBinary       string        // GIG_ECHO_BIN, optional legacy/dev fallback (registry-driven install replaces seeding)
	MasterKey        string        // GIG_MASTER_KEY, required for vault (hex-encoded 32 bytes)
	ProxyPort        int           // GIG_PROXY_PORT, default 8081 (egress MITM proxy)
	BootstrapPath    string        // GIG_BOOTSTRAP_PATH, default "/usr/local/bin/bootstrap"
	RegistryIndexURL string        // GIG_REGISTRY_INDEX_URL: https:// or file:// index.json location
	RegistryPubKey   string        // GIG_REGISTRY_PUBKEY: 32-byte ed25519 hex (index trust root)
	Install          string        // GIG_INSTALL: comma-separated refs installed at boot (auto-consented)
	DataDir          string        // GIG_DATA_DIR, default "/data": extracted server binaries
	OIDCIssuer       string        // GIG_OIDC_ISSUER, e.g. http://localhost:8082; empty = control plane disabled
	OIDCClientID     string        // GIG_OIDC_CLIENT_ID
	OIDCClientSecret string        // GIG_OIDC_CLIENT_SECRET or GIG_OIDC_CLIENT_SECRET_FILE; optional (PKCE public client)
	OIDCRedirectURL  string        // GIG_OIDC_REDIRECT_URL, e.g. https://gig.example.com/api/auth/callback
	OIDCAdminRole    string        // GIG_OIDC_ADMIN_ROLE — Zitadel role mapping to "admin"; default "gigmcp-admin"
	SessionTTL       time.Duration // GIG_SESSION_TTL, default 168h
	// PublicURL is GIG_PUBLIC_URL — the https prefix turns on Secure cookies.
	// When OIDC is enabled and GIG_PUBLIC_URL is unset, PublicURL is derived
	// from OIDCRedirectURL (scheme + host, path stripped) so that Secure-cookie
	// decisions are always consistent with the redirect origin.
	PublicURL string
	// OAuthBootstrap maps lowercase vendor → its GIG_OAUTH_<VENDOR>_* provider.
	OAuthBootstrap map[string]OAuthVendorBootstrap
}

// OIDCEnabled reports whether the OIDC control plane is configured.
func (c Config) OIDCEnabled() bool { return c.OIDCIssuer != "" }

// FromEnv loads Config from environment variables.
func FromEnv() (Config, error) {
	cfg := Config{
		Listen:           envOr("GIG_LISTEN", ":8080"),
		DBPath:           envOr("GIG_DB_PATH", "gigmcp.db"),
		EchoBinary:       os.Getenv("GIG_ECHO_BIN"),
		MasterKey:        os.Getenv("GIG_MASTER_KEY"),
		ProxyPort:        envInt("GIG_PROXY_PORT", 8081),
		BootstrapPath:    envOr("GIG_BOOTSTRAP_PATH", "/usr/local/bin/bootstrap"),
		RegistryIndexURL: os.Getenv("GIG_REGISTRY_INDEX_URL"),
		RegistryPubKey:   os.Getenv("GIG_REGISTRY_PUBKEY"),
		Install:          os.Getenv("GIG_INSTALL"),
		DataDir:          envOr("GIG_DATA_DIR", "/data"),
	}
	// No auth env is required here: profile endpoints authenticate with
	// per-profile tokens (stored hashed in the DB) and the /api control plane
	// is gated on the optional GIG_OIDC_* block below. GIG_ECHO_BIN is an
	// OPTIONAL legacy/dev fallback (registry-driven install replaces seeding).
	if cfg.Install != "" && (cfg.RegistryIndexURL == "" || cfg.RegistryPubKey == "") {
		return Config{}, errors.New("GIG_INSTALL requires GIG_REGISTRY_INDEX_URL and GIG_REGISTRY_PUBKEY")
	}
	secret, err := envOrFile("GIG_OIDC_CLIENT_SECRET")
	if err != nil {
		return Config{}, err
	}
	cfg.OIDCIssuer = os.Getenv("GIG_OIDC_ISSUER")
	cfg.OIDCClientID = os.Getenv("GIG_OIDC_CLIENT_ID")
	cfg.OIDCClientSecret = secret
	cfg.OIDCRedirectURL = os.Getenv("GIG_OIDC_REDIRECT_URL")
	cfg.OIDCAdminRole = envOr("GIG_OIDC_ADMIN_ROLE", "gigmcp-admin")
	cfg.PublicURL = os.Getenv("GIG_PUBLIC_URL")
	cfg.SessionTTL = 168 * time.Hour
	if v := os.Getenv("GIG_SESSION_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return Config{}, fmt.Errorf("GIG_SESSION_TTL must be a positive duration: %q", v)
		}
		cfg.SessionTTL = d
	}
	// OIDC settings are all-or-none (the client secret is optional: Zitadel
	// PKCE public clients have none).
	oidcCore := []string{cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCRedirectURL}
	anySet, allSet := false, true
	for _, v := range oidcCore {
		if v != "" {
			anySet = true
		} else {
			allSet = false
		}
	}
	if anySet && !allSet {
		return Config{}, errors.New("GIG_OIDC_ISSUER, GIG_OIDC_CLIENT_ID and GIG_OIDC_REDIRECT_URL must be set together")
	}
	// I3: if OIDC is enabled and GIG_PUBLIC_URL was not set, derive PublicURL
	// from OIDCRedirectURL (scheme + host only) so that oidc.go's Secure-cookie
	// derivation (`strings.HasPrefix(cfg.PublicURL, "https://")`) is consistent
	// with the redirect origin even when the operator omits GIG_PUBLIC_URL.
	if cfg.OIDCEnabled() && cfg.PublicURL == "" && cfg.OIDCRedirectURL != "" {
		if u, err := url.Parse(cfg.OIDCRedirectURL); err == nil {
			cfg.PublicURL = u.Scheme + "://" + u.Host
		}
	}
	boot, err := parseOAuthBootstrap()
	if err != nil {
		return Config{}, err
	}
	cfg.OAuthBootstrap = boot
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n <= 0 {
		return def
	}
	return n
}

// envOrFile returns $key, or the trimmed contents of the file named by
// $key_FILE when the plain variable is unset. The plain variable wins.
func envOrFile(key string) (string, error) {
	if v := os.Getenv(key); v != "" {
		return v, nil
	}
	path := os.Getenv(key + "_FILE")
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s_FILE: %w", key, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// parseOAuthBootstrap scans the environment for GIG_OAUTH_<VENDOR>_* groups and
// returns one OAuthVendorBootstrap per vendor (lowercased). A group is
// all-or-none: CLIENT_ID, AUTHORIZE_URL and TOKEN_URL are required together
// (CLIENT_SECRET is optional for PKCE public clients and supports _FILE).
func parseOAuthBootstrap() (map[string]OAuthVendorBootstrap, error) {
	const prefix = "GIG_OAUTH_"
	vendors := map[string]struct{}{}
	for _, kv := range os.Environ() {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := strings.TrimPrefix(k, prefix)
		// rest is e.g. GOOGLE_CLIENT_ID; the vendor is the first segment up to
		// a known suffix. Strip the known suffixes to isolate the vendor token.
		for _, suf := range []string{"_CLIENT_ID", "_CLIENT_SECRET_FILE", "_CLIENT_SECRET", "_AUTHORIZE_URL", "_TOKEN_URL", "_DEFAULT_SCOPES", "_PKCE"} {
			if strings.HasSuffix(rest, suf) {
				vendors[strings.ToLower(strings.TrimSuffix(rest, suf))] = struct{}{}
				break
			}
		}
	}
	if len(vendors) == 0 {
		return nil, nil
	}
	out := make(map[string]OAuthVendorBootstrap, len(vendors))
	for v := range vendors {
		up := strings.ToUpper(v)
		secret, err := envOrFile(prefix + up + "_CLIENT_SECRET")
		if err != nil {
			return nil, err
		}
		b := OAuthVendorBootstrap{
			ClientID:     os.Getenv(prefix + up + "_CLIENT_ID"),
			ClientSecret: secret,
			AuthorizeURL: os.Getenv(prefix + up + "_AUTHORIZE_URL"),
			TokenURL:     os.Getenv(prefix + up + "_TOKEN_URL"),
			PKCE:         os.Getenv(prefix+up+"_PKCE") == "true",
		}
		if s := os.Getenv(prefix + up + "_DEFAULT_SCOPES"); s != "" {
			b.DefaultScopes = strings.Fields(strings.ReplaceAll(s, ",", " "))
		}
		// All-or-none: a vendor with any GIG_OAUTH_<V>_* set must have the
		// three required fields, or it is an operator misconfiguration.
		if b.ClientID == "" || b.AuthorizeURL == "" || b.TokenURL == "" {
			return nil, fmt.Errorf("GIG_OAUTH_%s_* requires CLIENT_ID, AUTHORIZE_URL and TOKEN_URL", up)
		}
		out[v] = b
	}
	return out, nil
}
