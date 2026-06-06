package config_test

import (
	"testing"

	"github.com/gigemcp/gigemcp/internal/config"
)

func TestFromEnv(t *testing.T) {
	t.Setenv("GIGE_BEARER_TOKEN", "tok")
	t.Setenv("GIGE_ECHO_BIN", "/usr/local/bin/echo-mcp")
	t.Setenv("GIGE_LISTEN", "")
	t.Setenv("GIGE_DB_PATH", "")

	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen default: got %q", cfg.Listen)
	}
	if cfg.DBPath != "gigemcp.db" {
		t.Errorf("DBPath default: got %q", cfg.DBPath)
	}
	if cfg.BearerToken != "tok" || cfg.EchoBinary != "/usr/local/bin/echo-mcp" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}

func TestFromEnvRequiresToken(t *testing.T) {
	t.Setenv("GIGE_BEARER_TOKEN", "")
	t.Setenv("GIGE_ECHO_BIN", "/x")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error when GIGE_BEARER_TOKEN is empty")
	}
}

func TestFromEnvRequiresEchoBin(t *testing.T) {
	t.Setenv("GIGE_BEARER_TOKEN", "tok")
	t.Setenv("GIGE_ECHO_BIN", "")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error when GIGE_ECHO_BIN is empty")
	}
}
