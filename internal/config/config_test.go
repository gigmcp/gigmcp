package config_test

import (
	"testing"

	"github.com/gigmcp/gigmcp/internal/config"
)

func TestFromEnv(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_ECHO_BIN", "/usr/local/bin/echo-mcp")
	t.Setenv("GIG_LISTEN", "")
	t.Setenv("GIG_DB_PATH", "")

	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen default: got %q", cfg.Listen)
	}
	if cfg.DBPath != "gigmcp.db" {
		t.Errorf("DBPath default: got %q", cfg.DBPath)
	}
	if cfg.BearerToken != "tok" || cfg.EchoBinary != "/usr/local/bin/echo-mcp" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}

func TestFromEnvRequiresToken(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "")
	t.Setenv("GIG_ECHO_BIN", "/x")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error when GIG_BEARER_TOKEN is empty")
	}
}

func TestFromEnvRequiresEchoBin(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_ECHO_BIN", "")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error when GIG_ECHO_BIN is empty")
	}
}

func TestFromEnvNewFields(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_ECHO_BIN", "/bin/echo-mcp")
	t.Setenv("GIG_MASTER_KEY", "abc123")
	t.Setenv("GIG_PROXY_PORT", "9090")
	t.Setenv("GIG_BOOTSTRAP_PATH", "/usr/local/bin/bootstrap")
	t.Setenv("GIG_DEMO_TOKEN", "demotoken")
	t.Setenv("GIG_DEMO_ALLOW", "api.example.com")

	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.MasterKey != "abc123" {
		t.Errorf("MasterKey: got %q", cfg.MasterKey)
	}
	if cfg.ProxyPort != 9090 {
		t.Errorf("ProxyPort: got %d, want 9090", cfg.ProxyPort)
	}
	if cfg.BootstrapPath != "/usr/local/bin/bootstrap" {
		t.Errorf("BootstrapPath: got %q", cfg.BootstrapPath)
	}
	if cfg.DemoToken != "demotoken" {
		t.Errorf("DemoToken: got %q", cfg.DemoToken)
	}
	if cfg.DemoAllow != "api.example.com" {
		t.Errorf("DemoAllow: got %q", cfg.DemoAllow)
	}
}

func TestFromEnvProxyPortDefault(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_ECHO_BIN", "/bin/echo-mcp")
	t.Setenv("GIG_PROXY_PORT", "")
	t.Setenv("GIG_BOOTSTRAP_PATH", "")

	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.ProxyPort != 8081 {
		t.Errorf("ProxyPort default: got %d, want 8081", cfg.ProxyPort)
	}
	if cfg.BootstrapPath != "/usr/local/bin/bootstrap" {
		t.Errorf("BootstrapPath default: got %q", cfg.BootstrapPath)
	}
}
