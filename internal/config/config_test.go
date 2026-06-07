package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestFromEnvEchoBinOptional(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_ECHO_BIN", "")
	if _, err := config.FromEnv(); err != nil {
		t.Fatalf("GIG_ECHO_BIN is now optional; got unexpected error: %v", err)
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

func setBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_ECHO_BIN", "/bin/echo-mcp")
}

func TestOIDCDisabledByDefault(t *testing.T) {
	setBaseEnv(t)
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDCEnabled() {
		t.Fatal("OIDC must be disabled when no GIG_OIDC_* is set")
	}
	if cfg.OIDCAdminRole != "gigmcp-admin" {
		t.Fatalf("default admin role: %q", cfg.OIDCAdminRole)
	}
	if cfg.SessionTTL != 168*time.Hour {
		t.Fatalf("default session TTL: %v", cfg.SessionTTL)
	}
}

func TestOIDCPartialConfigErrors(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("GIG_OIDC_ISSUER", "https://idp.example.com")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("issuer without client-id/redirect must error (all-or-none)")
	}
}

func TestOIDCFullConfig(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("GIG_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("GIG_OIDC_CLIENT_ID", "cid")
	t.Setenv("GIG_OIDC_CLIENT_SECRET", "csec")
	t.Setenv("GIG_OIDC_REDIRECT_URL", "https://gig.example.com/api/auth/callback")
	t.Setenv("GIG_OIDC_ADMIN_ROLE", "boss")
	t.Setenv("GIG_SESSION_TTL", "24h")
	t.Setenv("GIG_PUBLIC_URL", "https://gig.example.com")
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.OIDCEnabled() || cfg.OIDCClientID != "cid" || cfg.OIDCClientSecret != "csec" ||
		cfg.OIDCAdminRole != "boss" || cfg.SessionTTL != 24*time.Hour ||
		cfg.PublicURL != "https://gig.example.com" {
		t.Fatalf("config mismatch: %+v", cfg)
	}
}

func TestOIDCClientSecretFile(t *testing.T) {
	setBaseEnv(t)
	f := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(f, []byte("filesecret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIG_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("GIG_OIDC_CLIENT_ID", "cid")
	t.Setenv("GIG_OIDC_CLIENT_SECRET_FILE", f)
	t.Setenv("GIG_OIDC_REDIRECT_URL", "https://gig.example.com/api/auth/callback")
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDCClientSecret != "filesecret" {
		t.Fatalf("want trimmed file secret, got %q", cfg.OIDCClientSecret)
	}
}

func TestBadSessionTTLErrors(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("GIG_SESSION_TTL", "not-a-duration")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("invalid GIG_SESSION_TTL must error")
	}
}

// TestPublicURLFallbackFromOIDCRedirectURL verifies I3: when OIDC is enabled
// and GIG_PUBLIC_URL is absent, PublicURL is derived from OIDCRedirectURL
// (scheme + host only).
func TestPublicURLFallbackFromOIDCRedirectURL(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("GIG_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("GIG_OIDC_CLIENT_ID", "cid")
	t.Setenv("GIG_OIDC_REDIRECT_URL", "https://gig.example.com/api/auth/callback")
	t.Setenv("GIG_PUBLIC_URL", "") // explicitly absent
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.PublicURL != "https://gig.example.com" {
		t.Fatalf("PublicURL fallback: want %q, got %q", "https://gig.example.com", cfg.PublicURL)
	}
}

// TestPublicURLExplicitNotOverridden verifies that an explicit GIG_PUBLIC_URL
// is not overridden by the OIDCRedirectURL fallback.
func TestPublicURLExplicitNotOverridden(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("GIG_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("GIG_OIDC_CLIENT_ID", "cid")
	t.Setenv("GIG_OIDC_REDIRECT_URL", "https://gig.example.com/api/auth/callback")
	t.Setenv("GIG_PUBLIC_URL", "https://explicit.example.com")
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.PublicURL != "https://explicit.example.com" {
		t.Fatalf("explicit PublicURL must not be overridden: got %q", cfg.PublicURL)
	}
}
