// Package config reads gateway configuration from the environment
// (compose-env-first per DESIGN.md decision; secrets gain *_FILE support
// in the vault plan).
package config

import (
	"errors"
	"os"
)

// Config is the gateway's runtime configuration.
type Config struct {
	Listen      string // GIGE_LISTEN, default ":8080"
	BearerToken string // GIGE_BEARER_TOKEN, required
	DBPath      string // GIGE_DB_PATH, default "gigemcp.db"
	EchoBinary  string // GIGE_ECHO_BIN, required (skeleton's seeded backend)
}

// FromEnv loads Config from environment variables.
func FromEnv() (Config, error) {
	cfg := Config{
		Listen:      envOr("GIGE_LISTEN", ":8080"),
		BearerToken: os.Getenv("GIGE_BEARER_TOKEN"),
		DBPath:      envOr("GIGE_DB_PATH", "gigemcp.db"),
		EchoBinary:  os.Getenv("GIGE_ECHO_BIN"),
	}
	if cfg.BearerToken == "" {
		return Config{}, errors.New("GIGE_BEARER_TOKEN must be set")
	}
	if cfg.EchoBinary == "" {
		return Config{}, errors.New("GIGE_ECHO_BIN must be set")
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
