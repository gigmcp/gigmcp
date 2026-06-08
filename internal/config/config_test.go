package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/config"
)

func TestFromEnv(t *testing.T) {
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
	if cfg.EchoBinary != "/usr/local/bin/echo-mcp" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}

// TestFromEnvNoAuthEnvRequired pins the cutover contract: the gateway boots
// with NO auth-related environment at all. Profile endpoints authenticate
// with per-profile tokens; /api stays disabled until GIG_OIDC_* is set.
func TestFromEnvNoAuthEnvRequired(t *testing.T) {
	for _, k := range []string{
		"GIG_ECHO_BIN", "GIG_INSTALL",
		"GIG_OIDC_ISSUER", "GIG_OIDC_CLIENT_ID", "GIG_OIDC_REDIRECT_URL",
		"GIG_OIDC_CLIENT_SECRET", "GIG_OIDC_CLIENT_SECRET_FILE",
	} {
		t.Setenv(k, "")
	}
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv with empty environment must succeed: %v", err)
	}
	if cfg.OIDCEnabled() {
		t.Fatal("OIDC must be disabled with no GIG_OIDC_* set")
	}
}

func TestFromEnvEchoBinOptional(t *testing.T) {
	t.Setenv("GIG_ECHO_BIN", "")
	if _, err := config.FromEnv(); err != nil {
		t.Fatalf("GIG_ECHO_BIN is now optional; got unexpected error: %v", err)
	}
}

func TestFromEnvNewFields(t *testing.T) {
	t.Setenv("GIG_ECHO_BIN", "/bin/echo-mcp")
	t.Setenv("GIG_MASTER_KEY", "abc123")
	t.Setenv("GIG_PROXY_PORT", "9090")
	t.Setenv("GIG_BOOTSTRAP_PATH", "/usr/local/bin/bootstrap")

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
}

func TestFromEnvProxyPortDefault(t *testing.T) {
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
	// Each sub-test sets exactly two of the three core OIDC vars; all must error.
	cases := []struct {
		name   string
		issuer string
		cid    string
		redir  string
	}{
		{"issuer+client_id", "https://idp.example.com", "cid", ""},
		{"issuer+redirect", "https://idp.example.com", "", "https://gig.example.com/api/auth/callback"},
		{"client_id+redirect", "", "cid", "https://gig.example.com/api/auth/callback"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setBaseEnv(t)
			t.Setenv("GIG_OIDC_ISSUER", tc.issuer)
			t.Setenv("GIG_OIDC_CLIENT_ID", tc.cid)
			t.Setenv("GIG_OIDC_REDIRECT_URL", tc.redir)
			if _, err := config.FromEnv(); err == nil {
				t.Fatal("two-of-three OIDC vars must error (all-or-none)")
			}
		})
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

// TestEnvOrFileBothSet verifies that when both GIG_OIDC_CLIENT_SECRET and
// GIG_OIDC_CLIENT_SECRET_FILE are set, the plain env var wins.
func TestEnvOrFileBothSet(t *testing.T) {
	setBaseEnv(t)
	f := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(f, []byte("fromfile\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIG_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("GIG_OIDC_CLIENT_ID", "cid")
	t.Setenv("GIG_OIDC_CLIENT_SECRET", "fromenv")
	t.Setenv("GIG_OIDC_CLIENT_SECRET_FILE", f)
	t.Setenv("GIG_OIDC_REDIRECT_URL", "https://gig.example.com/api/auth/callback")
	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDCClientSecret != "fromenv" {
		t.Fatalf("plain env var must win over _FILE, got %q", cfg.OIDCClientSecret)
	}
}

// TestEnvOrFileMissingPath verifies that a _FILE path pointing to a missing
// file produces an error.
func TestEnvOrFileMissingPath(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("GIG_OIDC_CLIENT_SECRET_FILE", "/nonexistent/path/secret")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("missing _FILE path must error")
	}
}

func TestBadSessionTTLErrors(t *testing.T) {
	cases := []string{"not-a-duration", "-24h", "0s"}
	for _, v := range cases {
		t.Run(v, func(t *testing.T) {
			setBaseEnv(t)
			t.Setenv("GIG_SESSION_TTL", v)
			if _, err := config.FromEnv(); err == nil {
				t.Fatalf("GIG_SESSION_TTL=%q must error", v)
			}
		})
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

func TestOAuthBootstrapFromEnv(t *testing.T) {
	t.Setenv("GIG_OAUTH_GOOGLE_CLIENT_ID", "cid")
	t.Setenv("GIG_OAUTH_GOOGLE_CLIENT_SECRET", "sek")
	t.Setenv("GIG_OAUTH_GOOGLE_AUTHORIZE_URL", "https://accounts.google.com/o/oauth2/v2/auth")
	t.Setenv("GIG_OAUTH_GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token")
	t.Setenv("GIG_OAUTH_GOOGLE_DEFAULT_SCOPES", "openid email")
	t.Setenv("GIG_OAUTH_GOOGLE_PKCE", "true")

	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	g, ok := cfg.OAuthBootstrap["google"]
	if !ok {
		t.Fatalf("google bootstrap missing: %+v", cfg.OAuthBootstrap)
	}
	if g.ClientID != "cid" || g.ClientSecret != "sek" || !g.PKCE ||
		g.AuthorizeURL == "" || g.TokenURL == "" ||
		len(g.DefaultScopes) != 2 || g.DefaultScopes[1] != "email" {
		t.Fatalf("parsed bootstrap wrong: %+v", g)
	}
}

func TestOAuthBootstrapIncompleteRejected(t *testing.T) {
	// CLIENT_ID without the URLs is an operator error → all-or-none.
	t.Setenv("GIG_OAUTH_SLACK_CLIENT_ID", "cid")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("incomplete GIG_OAUTH_SLACK_* must error")
	}
}

func TestOAuthBootstrapSecretFromFile(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/sek"
	if err := os.WriteFile(p, []byte("file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIG_OAUTH_GOOGLE_CLIENT_ID", "cid")
	t.Setenv("GIG_OAUTH_GOOGLE_CLIENT_SECRET_FILE", p)
	t.Setenv("GIG_OAUTH_GOOGLE_AUTHORIZE_URL", "https://a")
	t.Setenv("GIG_OAUTH_GOOGLE_TOKEN_URL", "https://t")

	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OAuthBootstrap["google"].ClientSecret != "file-secret" {
		t.Fatalf("secret from file not trimmed/loaded: %q", cfg.OAuthBootstrap["google"].ClientSecret)
	}
}
