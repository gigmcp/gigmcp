// Package config reads gateway configuration from the environment
// (compose-env-first per DESIGN.md decision; secrets gain *_FILE support
// in the vault plan).
package config

import (
	"errors"
	"fmt"
	"os"
)

// Config is the gateway's runtime configuration.
type Config struct {
	Listen        string // GIG_LISTEN, default ":8080"
	BearerToken   string // GIG_BEARER_TOKEN, required
	DBPath        string // GIG_DB_PATH, default "gigmcp.db"
	EchoBinary    string // GIG_ECHO_BIN, required (skeleton's seeded backend)
	MasterKey     string // GIG_MASTER_KEY, required for vault (hex-encoded 32 bytes)
	ProxyPort     int    // GIG_PROXY_PORT, default 8081 (egress MITM proxy)
	BootstrapPath string // GIG_BOOTSTRAP_PATH, default "/usr/local/bin/bootstrap"
	DemoToken     string // GIG_DEMO_TOKEN, optional: seed a demo credential on startup
	DemoAllow     string // GIG_DEMO_ALLOW, optional: comma-separated allowed hosts for demo credential
}

// FromEnv loads Config from environment variables.
func FromEnv() (Config, error) {
	cfg := Config{
		Listen:        envOr("GIG_LISTEN", ":8080"),
		BearerToken:   os.Getenv("GIG_BEARER_TOKEN"),
		DBPath:        envOr("GIG_DB_PATH", "gigmcp.db"),
		EchoBinary:    os.Getenv("GIG_ECHO_BIN"),
		MasterKey:     os.Getenv("GIG_MASTER_KEY"),
		ProxyPort:     envInt("GIG_PROXY_PORT", 8081),
		BootstrapPath: envOr("GIG_BOOTSTRAP_PATH", "/usr/local/bin/bootstrap"),
		DemoToken:     os.Getenv("GIG_DEMO_TOKEN"),
		DemoAllow:     os.Getenv("GIG_DEMO_ALLOW"),
	}
	if cfg.BearerToken == "" {
		return Config{}, errors.New("GIG_BEARER_TOKEN must be set")
	}
	if cfg.EchoBinary == "" {
		return Config{}, errors.New("GIG_ECHO_BIN must be set")
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
