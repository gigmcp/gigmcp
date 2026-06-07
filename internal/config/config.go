// Package config reads gateway configuration from the environment
// (compose-env-first per DESIGN.md decision; secrets gain *_FILE support
// in the vault plan).
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the gateway's runtime configuration.
type Config struct {
	Listen           string // GIG_LISTEN, default ":8080"
	BearerToken      string // GIG_BEARER_TOKEN, required
	DBPath           string // GIG_DB_PATH, default "gigmcp.db"
	EchoBinary       string // GIG_ECHO_BIN, optional legacy/dev fallback (registry-driven install replaces seeding — handoff §6.D)
	MasterKey        string // GIG_MASTER_KEY, required for vault (hex-encoded 32 bytes)
	ProxyPort        int    // GIG_PROXY_PORT, default 8081 (egress MITM proxy)
	BootstrapPath    string // GIG_BOOTSTRAP_PATH, default "/usr/local/bin/bootstrap"
	DemoToken        string // GIG_DEMO_TOKEN, optional: seed a demo credential on startup
	DemoAllow        string // GIG_DEMO_ALLOW, optional: comma-separated allowed hosts for demo credential
	RegistryIndexURL string // GIG_REGISTRY_INDEX_URL: https:// or file:// index.json location
	RegistryPubKey   string // GIG_REGISTRY_PUBKEY: 32-byte ed25519 hex (index trust root)
	Install          string // GIG_INSTALL: comma-separated refs installed at boot (auto-consented)
	DataDir          string // GIG_DATA_DIR, default "/data": extracted server binaries
	OIDCIssuer       string        // GIG_OIDC_ISSUER, e.g. http://localhost:8082; empty = control plane disabled
	OIDCClientID     string        // GIG_OIDC_CLIENT_ID
	OIDCClientSecret string        // GIG_OIDC_CLIENT_SECRET or GIG_OIDC_CLIENT_SECRET_FILE; optional (PKCE public client)
	OIDCRedirectURL  string        // GIG_OIDC_REDIRECT_URL, e.g. https://gig.example.com/api/auth/callback
	OIDCAdminRole    string        // GIG_OIDC_ADMIN_ROLE — Zitadel role mapping to "admin"; default "gigmcp-admin"
	SessionTTL       time.Duration // GIG_SESSION_TTL, default 168h
	PublicURL        string        // GIG_PUBLIC_URL — https prefix turns on Secure cookies
}

// OIDCEnabled reports whether the OIDC control plane is configured.
func (c Config) OIDCEnabled() bool { return c.OIDCIssuer != "" }

// FromEnv loads Config from environment variables.
func FromEnv() (Config, error) {
	cfg := Config{
		Listen:           envOr("GIG_LISTEN", ":8080"),
		BearerToken:      os.Getenv("GIG_BEARER_TOKEN"),
		DBPath:           envOr("GIG_DB_PATH", "gigmcp.db"),
		EchoBinary:       os.Getenv("GIG_ECHO_BIN"),
		MasterKey:        os.Getenv("GIG_MASTER_KEY"),
		ProxyPort:        envInt("GIG_PROXY_PORT", 8081),
		BootstrapPath:    envOr("GIG_BOOTSTRAP_PATH", "/usr/local/bin/bootstrap"),
		DemoToken:        os.Getenv("GIG_DEMO_TOKEN"),
		DemoAllow:        os.Getenv("GIG_DEMO_ALLOW"),
		RegistryIndexURL: os.Getenv("GIG_REGISTRY_INDEX_URL"),
		RegistryPubKey:   os.Getenv("GIG_REGISTRY_PUBKEY"),
		Install:          os.Getenv("GIG_INSTALL"),
		DataDir:          envOr("GIG_DATA_DIR", "/data"),
	}
	if cfg.BearerToken == "" {
		return Config{}, errors.New("GIG_BEARER_TOKEN must be set")
	}
	// GIG_ECHO_BIN is now an OPTIONAL legacy/dev fallback (registry-driven
	// install replaces seeding — handoff §6.D).
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
