# Control Plane Implementation Plan — Auth, REST API, Profiles, Audit

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the single-static-token, single-tenant gateway into a multi-user control plane: Zitadel-backed OIDC login with opaque DB sessions, a Go REST API (`/api/*`) for users/profiles/credentials/servers/audit, profile-scoped MCP endpoints (`/mcp/p/{slug}`) with per-profile bearer tokens where `Tenant` = profile ID, and a persistent audit pipeline (egress decorator + synchronous API events). Implements the approved spec `docs/superpowers/specs/2026-06-06-frontend-control-plane-design.md` — **control-plane scope only: the Next.js dashboard (spec §8) and the compose `web` service are OUT of this plan; a second plan covers them.** The existing static-token path and `Tenant:"default"` E2E stay green until the explicit, gated cutover task at the end.

**Architecture:** One listener, one mux on the existing `:8080` — `/mcp` (legacy `RequireBearer`, transitional), `/mcp/p/{slug}` (per-profile aggregator, lazy-spawned sandboxes with `Tenant` = profile ID), `/api/auth/*` (OIDC code+PKCE flow against Zitadel, state/nonce/verifier in a 10-min HMAC-signed cookie), `/api/*` (REST behind session-cookie middleware + RBAC + view-as impersonation). New store files (`users`, `sessions`, `profiles`, `audit`) follow the `credentials.go` pattern with additive schema consts run in `OpenSQLite`. Credentials become per-user: `credentials.tenant` holds the owning user ID as a decimal string; the resolver joins profile → owner for the secret lookup (literal tenants like `"default"` keep working). Egress audit is an `AuditingResolver` decorator — zero edits to the no-touch `internal/proxy` package. The registry workstream's `Installer` contract lives in a new `internal/registry` package as interface + `ErrNotImplemented` stub that they replace. Roles are a per-login cache of the Zitadel project-role claim; no local passwords, no invitations.

**Tech Stack:** Go 1.26 stdlib (`net/http` ServeMux with method+wildcard patterns — no router dependency); `github.com/coreos/go-oidc/v3` (**NEW** dependency); `golang.org/x/oauth2` v0.35.0 (already indirect — promote to direct); `github.com/go-jose/go-jose/v4` (test-only, transitive dep of go-oidc — for the fake-issuer test); `modernc.org/sqlite` (existing, pure Go); existing `internal/vault` (consumed, never modified). Builds stay `CGO_ENABLED=0`.

**Critical environment facts (do not re-derive):**
- Dev machine is macOS. Store/config/auth/api/registry code is host-testable: `make test-local` or `go test ./internal/store/...` etc. Anything that spawns sandboxes (spawn.go signature change, profile egress E2E) needs the Linux container: `make test`. Linux-only tests self-skip via `sandbox.Available()` or `//go:build linux`.
- Module path is `github.com/gigmcp/gigmcp`, Go 1.26. ServeMux supports `"POST /api/profiles/{id}/token"` patterns and `r.PathValue("id")`.
- `modernc.org/sqlite` driver name is `"sqlite"`. SQLite + Postgres parity rule (DESIGN #14): no SQLite-only SQL features beyond what the existing schema already uses (`AUTOINCREMENT`, `RETURNING`, `ON CONFLICT` — all already in `sqlite.go`/`credentials.go`). Timestamps are stored as INTEGER unix seconds.
- **Shared merge files with the parallel registry workstream:** `internal/store/store.go` (interface — additive methods only), `internal/store/sqlite.go` (`OpenSQLite` — append `db.ExecContext(ctx, xSchema)` blocks, keep diffs minimal), `cmd/gateway/main.go` `run()` (additive helpers only), `internal/gateway/resolver.go` (we change *which tenant key* feeds the secret lookup; they change *where allowlist/injection metadata come from*). `store.Server` struct is read-only for us — registry owns its fields, do NOT add any.
- The `spawn.go` tenant-parameter change (Task 13) is near the stable runtime boundary — flag it for a runtime-owner sanity check per the handoff.
- Zitadel dev instance runs on host port **8082** (the gateway owns 8080). Task 1 requires a human to click through Zitadel setup once.
- The legacy E2E (`internal/gateway/e2e_test.go`, `egress_e2e_test.go`) uses `RequireBearer("sekrit", ...)` and `Tenant:"default"` — both stay green until Task 18 (gated cutover).

**Verified API cheat sheet (trust over memory — verified against the tree 2026-06-06):**
- `store.Store` current interface (`internal/store/store.go`): `EnsureServer(ctx, name, binary string) (Server, error)`; `ListServers(ctx) ([]Server, error)`; `PutCredential(ctx, Credential) error`; `GetCredential(ctx, server, tenant string) (Credential, error)`; `Close() error`. `Server{ID int64; Name, Binary string}`.
- `OpenSQLite(path string) (Store, error)` runs `schema` then `credSchema` via `db.ExecContext(ctx, ...)`; append new schema consts the same way.
- `store.Credential{Server, Tenant string; EncryptedKey []byte; InjectHeader, InjectFormat, Placeholder string; AllowedHosts []string}` — upsert key `(server, tenant)`.
- `vault.New(kek []byte) (*Vault, error)` (kek exactly 32 bytes); `(*Vault).Encrypt(plaintext []byte) ([]byte, error)`; `(*Vault).Decrypt(box []byte) ([]byte, error)`.
- `SpawnEgressBackend(ctx, srv store.Server, alloc *netmgr.Allocator, reg *proxy.Registry, proxyPort int, caFile string, bootstrapPath string) (*EgressBackend, error)`; `EgressBackend{Session *mcp.ClientSession; ChildPID int; Cleanup func()}`. Tenant is set at `reg.Bind(sub.SandboxIP.String(), proxy.Identity{Server: srv.Name, Tenant: "default"})` — spawn.go:327.
- `proxy.Identity{Server, Tenant string}`; `proxy.Credential{RealSecret, InjectHeader, InjectFormat, Placeholder string; AllowedHosts []string}`; `proxy.CredentialResolver` interface: `Resolve(id Identity, host string) (Credential, error)` (verified in `internal/proxy/proxy.go`).
- Proxy host-allowlist semantics (`internal/proxy/proxy.go` `allowed()`): exact `strings.EqualFold(host, h)` match, OR `h` starts with `"*."` and `strings.HasSuffix(strings.ToLower(host), strings.ToLower(h[1:]))` (wildcard suffix match). The audit decorator must mirror this exactly.
- `gateway.New(ctx, version string, backends []Backend) (*mcp.Server, error)`; `Backend{Name string; Session *mcp.ClientSession}`; `handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, nil)`.
- In-memory MCP test pattern: `mcp.NewInMemoryTransports()`; `internal/echo` has `echo.NewServer()`; `gateway_test.go` has `connectEchoBackend(t, ctx)` and `e2e_test.go` has `bearerTransport` — both in package `gateway_test` with no build tag, reusable from new test files in that package.
- `gateway.RequireBearer(token string, next http.Handler) http.Handler` (`internal/gateway/auth.go`); `e2e_test.go:61` uses `RequireBearer("sekrit", ...)`.
- `config.FromEnv()` requires `GIG_BEARER_TOKEN` and `GIG_ECHO_BIN`; helpers `envOr(key, def)`, `envInt(key, def)` exist.
- **go-oidc / oauth2 surface — VERIFY in the Task 1 spike, update later tasks if drift found:** `oidc.NewProvider(ctx, issuer) (*oidc.Provider, error)`; `provider.Verifier(&oidc.Config{ClientID: id}) *oidc.IDTokenVerifier`; `provider.Endpoint() oauth2.Endpoint`; `oidc.Nonce(nonce string) oauth2.AuthCodeOption`; `verifier.Verify(ctx, rawIDToken) (*oidc.IDToken, error)`; `idToken.Issuer`, `idToken.Subject`, `idToken.Nonce` fields; `idToken.Claims(&v) error`; `oidc.ScopeOpenID` const. `oauth2.GenerateVerifier() string`; `oauth2.S256ChallengeOption(verifier) oauth2.AuthCodeOption`; `oauth2.VerifierOption(verifier) oauth2.AuthCodeOption`; `conf.AuthCodeURL(state, opts...)`; `conf.Exchange(ctx, code, opts...) (*oauth2.Token, error)`; `tok.Extra("id_token").(string)`.
- **go-jose v4 (test-only) — verify with `go mod why github.com/go-jose/go-jose/v4`:** `jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: rsaPriv}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))`; `signer.Sign(payloadJSON)`; `sig.CompactSerialize()`; `jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &priv.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}}`.

---

## Deviations from spec §5

Three param-name differences between the spec (§5) and the implementation in this plan — the dashboard plan MUST follow these names, not the spec originals:

1. **Audit pagination param:** implemented as `before` (integer row ID for keyset pagination), not `cursor`. The `GET /api/audit?before=&limit=` pattern threads through `audit.go` and all audit tests.
2. **Profile servers body key:** `PUT /api/profiles/{id}/servers` body is `{"servers": [...]}`, not `{"names": [...]}`. See `profiles.go` + `TestProfileServersAndRotateAndDelete`.
3. **Audit filtering (v1 scope):** `GET /api/audit` filters by `user_id` only (non-admins are forced to their own). Admins see all records; there are no `kind` or `server` filter params in v1. The spec §7 phrase "admins see all with filters" means post-v1 additional filters; see the spec note in §7 for the amended wording.

---

## File Structure

```
docker-compose.dev.yml            # T1: dev-only Zitadel + its postgres (NEW)
cmd/
├── oidc-spike/main.go            # T1: THROWAWAY spike — deleted before commit
└── gateway/
    ├── main.go                   # T13 (pass "default"), T16 (auth/API/profile wiring), T18 (cutover)
    └── serve.go                  # T16: buildMux() — the one shared-run() helper (NEW)
internal/
├── config/
│   ├── config.go                 # T2: OIDC/session/public-URL keys (+_FILE), all-or-none validation
│   └── config_test.go            # T2 (NEW)
├── store/
│   ├── store.go                  # T3–T6, T11: additive interface methods (SHARED MERGE FILE)
│   ├── sqlite.go                 # T3–T6: append schema ExecContext blocks (SHARED MERGE FILE)
│   ├── users.go + users_test.go              # T3: users table, JIT upsert (NEW)
│   ├── sessions.go + sessions_test.go        # T4: opaque sessions, impersonation columns (NEW)
│   ├── profiles.go + profiles_test.go        # T5: profiles + profile_servers join (NEW)
│   ├── audit.go + audit_test.go              # T6: audit table, keyset-paginated read (NEW)
│   └── credentials.go + credentials_test.go  # T11: additive ListCredentialsByTenant/DeleteCredential
├── auth/
│   ├── session.go + session_test.go  # T7: tokens, hashing, session/impersonation/RBAC middleware (NEW)
│   └── oidc.go + oidc_test.go        # T8: Authenticator, login/callback/logout, fake-issuer tests (NEW)
├── api/
│   ├── api.go + respond.go + me.go + api_test.go   # T9: Server struct, Routes(), error envelope (NEW)
│   ├── profiles.go + profiles_test.go              # T10: profile CRUD + token rotate (NEW)
│   ├── credentials.go + credentials_test.go        # T11: write-only credential CRUD via vault (NEW)
│   ├── servers.go, users.go, audit.go (+ tests)    # T12: installer endpoints, users, impersonate, audit read (NEW)
├── registry/
│   └── installer.go + installer_test.go  # T12: 3-method Installer contract + ErrNotImplemented stub (REGISTRY-OWNED)
└── gateway/
    ├── spawn.go                      # T13: tenant param (runtime-owner sanity check)
    ├── testharness.go                # T13: pass "default"; T18: seed profile instead
    ├── resolver.go + resolver_test.go            # T14: profile→owner tenant join (SHARED MERGE FILE)
    ├── audit_resolver.go + audit_resolver_test.go # T14: AuditingResolver decorator (NEW)
    ├── profilehost.go + profilehost_test.go       # T15: /mcp/p/{slug} lazy runtimes (NEW)
    ├── profile_e2e_test.go           # T17: container-only two-tenant egress E2E (NEW)
    ├── e2e_test.go                   # T18: migrate off RequireBearer
    └── auth.go + auth_test.go        # T18: DELETED at cutover
docker-compose.yml                # T16: GIG_OIDC_*/GIG_PUBLIC_URL passthrough; T18: drop GIG_BEARER_TOKEN
```

Responsibilities stay layered: `config` only parses env; `store` only persists; `auth` owns tokens/sessions/OIDC/middleware; `api` owns HTTP handlers and imports `auth` + `registry` (never `gateway`); `registry` is the contract package the registry workstream replaces; `gateway` owns MCP runtimes, the resolver join, and the audit decorator; `cmd/gateway` composes everything.

---

### Task 1: Zitadel dev fixture + OIDC spike (HUMAN-IN-THE-LOOP)

**Files:** Create `docker-compose.dev.yml`, `cmd/oidc-spike/main.go` (THROWAWAY — deleted in the final step). Modify `go.mod`/`go.sum` (add go-oidc, promote oauth2).

> **This whole task requires the human once:** clicking through the Zitadel console to create the project, role, and app, and completing one interactive browser login. Do not attempt to automate the console; ask the human to do the bootstrap steps and report back the client ID.

- [ ] **Step 1: Add dependencies**

```bash
go get github.com/coreos/go-oidc/v3@latest
go get golang.org/x/oauth2@v0.35.0
go mod tidy
go mod why github.com/go-jose/go-jose/v4   # expect: transitive via go-oidc (needed for Task 8 tests)
```

Confirm `go.mod` now lists `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` in the main `require` block (oauth2 promoted from indirect). If `go mod why` shows go-jose is NOT a dependency, run `go get github.com/go-jose/go-jose/v4@latest` and note it.

- [ ] **Step 2: Create `docker-compose.dev.yml`** (dev-only — never merged into the production compose):

```yaml
# Dev-only fixture: a local Zitadel IdP for OIDC development and the Task 1
# spike. NOT for production. Start with:
#   docker compose -f docker-compose.dev.yml up -d
# Console: http://localhost:8082/ui/console  (admin / Password1!)
services:
  zitadel:
    image: ghcr.io/zitadel/zitadel:latest
    command: 'start-from-init --masterkey "MasterkeyNeedsToHave32Characters" --tlsMode disabled'
    environment:
      ZITADEL_DATABASE_POSTGRES_HOST: zitadel-db
      ZITADEL_DATABASE_POSTGRES_PORT: 5432
      ZITADEL_DATABASE_POSTGRES_DATABASE: zitadel
      ZITADEL_DATABASE_POSTGRES_USER_USERNAME: zitadel
      ZITADEL_DATABASE_POSTGRES_USER_PASSWORD: zitadel
      ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE: disable
      ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME: postgres
      ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD: postgres
      ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE: disable
      ZITADEL_EXTERNALSECURE: "false"
      ZITADEL_EXTERNALDOMAIN: localhost
      ZITADEL_EXTERNALPORT: 8082
      ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME: admin
      ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD: Password1!
    ports:
      - "8082:8080"
    depends_on:
      zitadel-db:
        condition: service_healthy
  zitadel-db:
    image: postgres:17-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 20
```

Run `docker compose -f docker-compose.dev.yml up -d` and wait until `http://localhost:8082/.well-known/openid-configuration` returns JSON (first init takes ~1 min).

- [ ] **Step 3: Manual Zitadel bootstrap (HUMAN).** Ask the human to do this once in the console at `http://localhost:8082/ui/console` (login `admin@zitadel.localhost` or `admin`, password `Password1!`, change password when prompted):
  1. Create a **Project** named `gigmcp`.
  2. In the project, create a **Role** with key `gigmcp-admin`.
  3. Under the project's **Authorizations**, grant the admin user the `gigmcp-admin` role.
  4. In the project's general settings, enable **"Assert Roles on Authentication"** (so the roles claim `urn:zitadel:iam:org:project:roles` is embedded in the ID token).
  5. In the project, create an **Application**: type **Web**, authentication method **PKCE** (no client secret), redirect URI `http://localhost:8080/api/auth/callback`, and enable **Development Mode** (allows the http:// redirect). Record the **Client ID**.

- [ ] **Step 4: Write the throwaway spike** — `cmd/oidc-spike/main.go`:

```go
// Command oidc-spike is a THROWAWAY proof of the full OIDC code+PKCE flow
// against the dev Zitadel: NewProvider → AuthCodeURL(state, nonce, PKCE) →
// browser login → callback → Exchange → Verify → claims (incl. the Zitadel
// roles claim). Delete this file before committing Task 1.
//
// Run:  SPIKE_CLIENT_ID=<client-id> go run ./cmd/oidc-spike
// then open http://localhost:8080/ and log in as the Zitadel admin.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func main() {
	issuer := os.Getenv("SPIKE_ISSUER")
	if issuer == "" {
		issuer = "http://localhost:8082"
	}
	clientID := os.Getenv("SPIKE_CLIENT_ID")
	if clientID == "" {
		log.Fatal("set SPIKE_CLIENT_ID to the Zitadel app's client id")
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("discovery: %v", err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	conf := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: os.Getenv("SPIKE_CLIENT_SECRET"), // empty for the PKCE public client
		Endpoint:     provider.Endpoint(),
		RedirectURL:  "http://localhost:8080/api/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	const state, nonce = "spike-state", "spike-nonce"
	pkce := oauth2.GenerateVerifier()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r,
			conf.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)),
			http.StatusFound)
	})
	http.HandleFunc("/api/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		tok, err := conf.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(pkce))
		if err != nil {
			http.Error(w, "exchange: "+err.Error(), http.StatusBadGateway)
			return
		}
		rawID, ok := tok.Extra("id_token").(string)
		if !ok {
			http.Error(w, "no id_token in response", http.StatusBadGateway)
			return
		}
		idt, err := verifier.Verify(r.Context(), rawID)
		if err != nil {
			http.Error(w, "verify: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if idt.Nonce != nonce {
			http.Error(w, "nonce mismatch", http.StatusUnauthorized)
			return
		}
		var claims map[string]any
		if err := idt.Claims(&claims); err != nil {
			http.Error(w, "claims: "+err.Error(), http.StatusBadGateway)
			return
		}
		log.Printf("SPIKE OK issuer=%s sub=%s", idt.Issuer, idt.Subject)
		log.Printf("SPIKE roles claim: %#v", claims["urn:zitadel:iam:org:project:roles"])
		fmt.Fprintf(w, "SPIKE OK\nissuer=%s\nsub=%s\nclaims=%v\n", idt.Issuer, idt.Subject, claims)
	})
	log.Println("spike on http://localhost:8080/ — open it in a browser")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

- [ ] **Step 5: Run the spike (HUMAN clicks through login).** `SPIKE_CLIENT_ID=<client-id> go run ./cmd/oidc-spike`, open `http://localhost:8080/`, log in. Success criteria: the page shows `SPIKE OK`, the log shows the issuer/sub, and the roles claim log line shows a map containing the key `gigmcp-admin` (because the admin user was granted that role). If the roles claim is missing, re-check console step 4 ("Assert Roles on Authentication") and the authorization grant.

- [ ] **Step 6: Record findings.** Compare every name in the cheat-sheet's "go-oidc / oauth2 surface" bullet against what actually compiled and ran. If ANY name drifted (e.g. `S256ChallengeOption` renamed, `idt.Nonce` absent), update this plan's cheat sheet AND the affected code in Tasks 8 and 18 before proceeding. Append a dated note under the cheat sheet: `Verified by spike <date>: <list any corrections, or "no drift">.`

- [ ] **Step 7: Delete the spike and commit** —

```bash
rm -rf cmd/oidc-spike
git add docker-compose.dev.yml go.mod go.sum docs/superpowers/plans/2026-06-06-control-plane.md
git commit -m "chore: Zitadel dev fixture + go-oidc dep; OIDC flow verified by spike"
```

---

### Task 2: Config — OIDC, session TTL, public URL

**Files:** Modify `internal/config/config.go`. Create `internal/config/config_test.go`.

- [ ] **Step 1: Write the failing test** — `internal/config/config_test.go`

```go
package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/config"
)

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
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/config/` → undefined `cfg.OIDCEnabled` / missing fields.

- [ ] **Step 3: Implement** — modify `internal/config/config.go`. Add fields to `Config`:

```go
	OIDCIssuer       string        // GIG_OIDC_ISSUER, e.g. http://localhost:8082; empty = control plane disabled
	OIDCClientID     string        // GIG_OIDC_CLIENT_ID
	OIDCClientSecret string        // GIG_OIDC_CLIENT_SECRET or GIG_OIDC_CLIENT_SECRET_FILE; optional (PKCE public client)
	OIDCRedirectURL  string        // GIG_OIDC_REDIRECT_URL, e.g. https://gig.example.com/api/auth/callback
	OIDCAdminRole    string        // GIG_OIDC_ADMIN_ROLE — Zitadel role mapping to "admin"; default "gigmcp-admin"
	SessionTTL       time.Duration // GIG_SESSION_TTL, default 168h
	PublicURL        string        // GIG_PUBLIC_URL — https prefix turns on Secure cookies
```

Add `"strings"` and `"time"` to the imports. Add a method + helper and extend `FromEnv`:

```go
// OIDCEnabled reports whether the OIDC control plane is configured.
func (c Config) OIDCEnabled() bool { return c.OIDCIssuer != "" }
```

In `FromEnv`, after the existing field assignments:

```go
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
```

And the file-or-env helper at the bottom of the file:

```go
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
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/config/` → PASS (5 tests).

- [ ] **Step 5: Commit** — `git add internal/config/ && git commit -m "feat(config): OIDC, session TTL, public URL keys with all-or-none validation"`

---

### Task 3: Store — users (JIT OIDC upsert)

**Files:** Create `internal/store/users.go`, `internal/store/users_test.go`. Modify `internal/store/store.go` (interface — SHARED MERGE FILE, additive), `internal/store/sqlite.go` (one appended ExecContext block — SHARED MERGE FILE, keep diff minimal).

- [ ] **Step 1: Write the failing test** — `internal/store/users_test.go`

```go
package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

// openTestStore is shared by the new store test files.
func openTestStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestUpsertUserByOIDCCreatesAndUpdates(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	u1, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-1", "a@example.com", "Alice", "user")
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if u1.ID == 0 || u1.Role != "user" || u1.Email != "a@example.com" || u1.CreatedAt.IsZero() {
		t.Fatalf("bad user: %+v", u1)
	}

	// Same (issuer, subject) → same row; email/name/role/last_login refreshed.
	u2, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-1", "new@example.com", "Alice A.", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if u2.ID != u1.ID {
		t.Fatalf("upsert created a new row: %d != %d", u2.ID, u1.ID)
	}
	if u2.Email != "new@example.com" || u2.DisplayName != "Alice A." || u2.Role != "admin" {
		t.Fatalf("fields not refreshed: %+v", u2)
	}

	// Different subject → new row.
	u3, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-2", "b@example.com", "Bob", "user")
	if err != nil {
		t.Fatal(err)
	}
	if u3.ID == u1.ID {
		t.Fatal("distinct subject must create a new user")
	}
}

func TestGetUserAndListUsers(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	if _, err := st.GetUser(ctx, 999); !errors.Is(err, store.ErrUserNotFound) {
		t.Fatalf("want ErrUserNotFound, got %v", err)
	}
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-1", "a@example.com", "Alice", "user")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertUserByOIDC(ctx, "https://idp", "sub-2", "b@example.com", "Bob", "admin"); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetUser(ctx, u.ID)
	if err != nil || got.Subject != "sub-1" {
		t.Fatalf("get: %v %+v", err, got)
	}
	all, err := st.ListUsers(ctx)
	if err != nil || len(all) != 2 {
		t.Fatalf("list: %v %d", err, len(all))
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/store/ -run User` → undefined `st.UpsertUserByOIDC` / `store.ErrUserNotFound`.

- [ ] **Step 3: Implement** — `internal/store/users.go`

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrUserNotFound is returned by GetUser for an unknown id.
var ErrUserNotFound = errors.New("store: user not found")

// User is a JIT-provisioned account keyed by the OIDC (issuer, subject) pair.
// Role is a CACHE of the IdP role claim, refreshed on every login (spec §3);
// it is never edited locally in v1.
type User struct {
	ID          int64
	Issuer      string
	Subject     string
	Email       string
	DisplayName string
	Role        string // "admin" or "user"
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// NOTE: FOREIGN KEY clauses are intentionally omitted from all new schemas.
// SQLite requires PRAGMA foreign_keys=ON per-connection for FK enforcement
// (parity rule, DESIGN #14); ownership is enforced in application code instead.
const usersSchema = `
CREATE TABLE IF NOT EXISTS users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	issuer        TEXT NOT NULL,
	subject       TEXT NOT NULL,
	email         TEXT NOT NULL,
	display_name  TEXT NOT NULL,
	role          TEXT NOT NULL CHECK(role IN ('admin','user')),
	created_at    INTEGER NOT NULL,
	last_login_at INTEGER NOT NULL,
	UNIQUE(issuer, subject)
);`

const userCols = `id,issuer,subject,email,display_name,role,created_at,last_login_at`

func scanUser(row *sql.Row) (User, error) {
	var u User
	var created, lastLogin int64
	err := row.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Email, &u.DisplayName, &u.Role, &created, &lastLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.CreatedAt = time.Unix(created, 0)
	u.LastLoginAt = time.Unix(lastLogin, 0)
	return u, nil
}

// UpsertUserByOIDC JIT-provisions (or refreshes) a user keyed by
// UNIQUE(issuer, subject): email, display name, role and last_login are
// updated on every login.
func (s *sqliteStore) UpsertUserByOIDC(ctx context.Context, issuer, subject, email, displayName, role string) (User, error) {
	now := time.Now().Unix()
	row := s.db.QueryRowContext(ctx,
		`INSERT INTO users (issuer,subject,email,display_name,role,created_at,last_login_at)
		 VALUES (?,?,?,?,?,?,?)
		 ON CONFLICT(issuer,subject) DO UPDATE SET
		   email=excluded.email, display_name=excluded.display_name,
		   role=excluded.role, last_login_at=excluded.last_login_at
		 RETURNING `+userCols,
		issuer, subject, email, displayName, role, now, now)
	return scanUser(row)
}

// GetUser fetches a user by id.
func (s *sqliteStore) GetUser(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userCols+` FROM users WHERE id=?`, id))
}

// ListUsers returns all users ordered by id.
func (s *sqliteStore) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+userCols+` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var u User
		var created, lastLogin int64
		if err := rows.Scan(&u.ID, &u.Issuer, &u.Subject, &u.Email, &u.DisplayName, &u.Role, &created, &lastLogin); err != nil {
			return nil, err
		}
		u.CreatedAt = time.Unix(created, 0)
		u.LastLoginAt = time.Unix(lastLogin, 0)
		users = append(users, u)
	}
	return users, rows.Err()
}
```

In `internal/store/store.go`, append to the `Store` interface (keep the existing methods untouched — the registry workstream also appends here):

```go
	// UpsertUserByOIDC JIT-provisions or refreshes a user by (issuer, subject).
	UpsertUserByOIDC(ctx context.Context, issuer, subject, email, displayName, role string) (User, error)
	// GetUser fetches a user by id; ErrUserNotFound if missing.
	GetUser(ctx context.Context, id int64) (User, error)
	// ListUsers returns all users ordered by id.
	ListUsers(ctx context.Context) ([]User, error)
```

In `internal/store/sqlite.go` `OpenSQLite`, append after the `credSchema` block (one block, same shape — this is the shared merge file, change nothing else):

```go
	if _, err := db.ExecContext(ctx, usersSchema); err != nil {
		db.Close()
		return nil, err
	}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/store/` → PASS (existing credential tests + 2 new).

- [ ] **Step 5: Commit** — `git add internal/store/ && git commit -m "feat(store): users table with OIDC JIT upsert"`

---

### Task 4: Store — sessions (opaque, delete-on-read expiry, impersonation columns)

**Files:** Create `internal/store/sessions.go`, `internal/store/sessions_test.go`. Modify `internal/store/store.go`, `internal/store/sqlite.go` (one appended block each).

- [ ] **Step 1: Write the failing test** — `internal/store/sessions_test.go`

```go
package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestSessionRoundTrip(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "s1", "a@x", "A", "user")
	if err != nil {
		t.Fatal(err)
	}

	exp := time.Now().Add(time.Hour)
	if err := st.CreateSession(ctx, "hash-1", u.ID, exp); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := st.GetSession(ctx, "hash-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.UserID != u.ID || got.TokenHash != "hash-1" || got.ImpersonatingUserID != nil {
		t.Fatalf("session mismatch: %+v", got)
	}
	if got.ExpiresAt.Unix() != exp.Unix() {
		t.Fatalf("expiry mismatch: %v vs %v", got.ExpiresAt, exp)
	}

	if err := st.DeleteSession(ctx, "hash-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, "hash-1"); !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("want ErrSessionNotFound after delete, got %v", err)
	}
}

func TestExpiredSessionDeletedOnRead(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u, _ := st.UpsertUserByOIDC(ctx, "https://idp", "s1", "a@x", "A", "user")

	if err := st.CreateSession(ctx, "old", u.ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetSession(ctx, "old"); !errors.Is(err, store.ErrSessionNotFound) {
		t.Fatalf("expired session must read as not-found, got %v", err)
	}
	// The expired row was deleted, so re-creating the same hash succeeds.
	if err := st.CreateSession(ctx, "old", u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("expired row not deleted on read: %v", err)
	}
}

func TestImpersonationSetAndClear(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	admin, _ := st.UpsertUserByOIDC(ctx, "https://idp", "adm", "adm@x", "Adm", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "tgt", "tgt@x", "Tgt", "user")

	if err := st.CreateSession(ctx, "h", admin.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	impExp := time.Now().Add(30 * time.Minute)
	if err := st.SetImpersonation(ctx, "h", target.ID, impExp); err != nil {
		t.Fatalf("set impersonation: %v", err)
	}
	got, err := st.GetSession(ctx, "h")
	if err != nil {
		t.Fatal(err)
	}
	if got.ImpersonatingUserID == nil || *got.ImpersonatingUserID != target.ID {
		t.Fatalf("impersonating_user_id: %+v", got)
	}
	if got.ImpersonationExpiresAt == nil || got.ImpersonationExpiresAt.Unix() != impExp.Unix() {
		t.Fatalf("impersonation_expires_at: %+v", got)
	}
	if err := st.ClearImpersonation(ctx, "h"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetSession(ctx, "h")
	if got.ImpersonatingUserID != nil || got.ImpersonationExpiresAt != nil {
		t.Fatalf("impersonation not cleared: %+v", got)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/store/ -run Session\|Impersonation` → undefined symbols.

- [ ] **Step 3: Implement** — `internal/store/sessions.go`

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrSessionNotFound is returned for unknown or expired sessions.
var ErrSessionNotFound = errors.New("store: session not found")

// Session is an opaque DB-backed browser session (spec §1 decision 1).
// TokenHash is the SHA-256 hex of the cookie value — the plaintext never
// touches the database. The impersonation columns implement DESIGN #20
// view-as mode.
type Session struct {
	TokenHash              string
	UserID                 int64
	CreatedAt              time.Time
	ExpiresAt              time.Time
	ImpersonatingUserID    *int64
	ImpersonationExpiresAt *time.Time
}

const sessionsSchema = `
CREATE TABLE IF NOT EXISTS sessions (
	token_hash               TEXT PRIMARY KEY,
	user_id                  INTEGER NOT NULL,
	created_at               INTEGER NOT NULL,
	expires_at               INTEGER NOT NULL,
	impersonating_user_id    INTEGER,
	impersonation_expires_at INTEGER
);`

// CreateSession inserts a session row.
func (s *sqliteStore) CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)`,
		tokenHash, userID, time.Now().Unix(), expiresAt.Unix())
	return err
}

// GetSession fetches a live session. Expired rows are deleted on read and
// reported as ErrSessionNotFound (cheap lazy reaping; no background sweeper).
func (s *sqliteStore) GetSession(ctx context.Context, tokenHash string) (Session, error) {
	var sess Session
	var created, expires int64
	var impID, impExp sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT token_hash,user_id,created_at,expires_at,impersonating_user_id,impersonation_expires_at
		 FROM sessions WHERE token_hash=?`, tokenHash).
		Scan(&sess.TokenHash, &sess.UserID, &created, &expires, &impID, &impExp)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrSessionNotFound
	}
	if err != nil {
		return Session{}, err
	}
	sess.CreatedAt = time.Unix(created, 0)
	sess.ExpiresAt = time.Unix(expires, 0)
	if impID.Valid {
		v := impID.Int64
		sess.ImpersonatingUserID = &v
	}
	if impExp.Valid {
		tv := time.Unix(impExp.Int64, 0)
		sess.ImpersonationExpiresAt = &tv
	}
	if time.Now().After(sess.ExpiresAt) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
		return Session{}, ErrSessionNotFound
	}
	return sess, nil
}

// DeleteSession removes a session (logout / revocation). Missing rows are not an error.
func (s *sqliteStore) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash)
	return err
}

// SetImpersonation stamps view-as state onto a session row.
func (s *sqliteStore) SetImpersonation(ctx context.Context, tokenHash string, targetUserID int64, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET impersonating_user_id=?, impersonation_expires_at=? WHERE token_hash=?`,
		targetUserID, expiresAt.Unix(), tokenHash)
	return err
}

// ClearImpersonation removes view-as state from a session row.
func (s *sqliteStore) ClearImpersonation(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET impersonating_user_id=NULL, impersonation_expires_at=NULL WHERE token_hash=?`,
		tokenHash)
	return err
}
```

Append to the `Store` interface in `internal/store/store.go`:

```go
	// CreateSession inserts an opaque session row keyed by token hash.
	CreateSession(ctx context.Context, tokenHash string, userID int64, expiresAt time.Time) error
	// GetSession fetches a live session; expired rows are deleted on read (ErrSessionNotFound).
	GetSession(ctx context.Context, tokenHash string) (Session, error)
	// DeleteSession removes a session.
	DeleteSession(ctx context.Context, tokenHash string) error
	// SetImpersonation stamps view-as state onto a session.
	SetImpersonation(ctx context.Context, tokenHash string, targetUserID int64, expiresAt time.Time) error
	// ClearImpersonation removes view-as state from a session.
	ClearImpersonation(ctx context.Context, tokenHash string) error
```

Append to `OpenSQLite` in `internal/store/sqlite.go`:

```go
	if _, err := db.ExecContext(ctx, sessionsSchema); err != nil {
		db.Close()
		return nil, err
	}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/store/` → PASS.

- [ ] **Step 5: Commit** — `git add internal/store/ && git commit -m "feat(store): opaque sessions with delete-on-read expiry and impersonation columns"`

---

### Task 5: Store — profiles + profile_servers join

**Files:** Create `internal/store/profiles.go`, `internal/store/profiles_test.go`. Modify `internal/store/store.go`, `internal/store/sqlite.go` (two appended blocks).

- [ ] **Step 1: Write the failing test** — `internal/store/profiles_test.go`

```go
package store_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func seedUser(t *testing.T, st store.Store, sub string) store.User {
	t.Helper()
	u, err := st.UpsertUserByOIDC(context.Background(), "https://idp", sub, sub+"@x", sub, "user")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestProfileCRUD(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u := seedUser(t, st, "alice")

	p, err := st.CreateProfile(ctx, "main", "Main profile", u.ID, "tokhash-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == 0 || p.Slug != "main" || p.UserID != u.ID || p.TokenHash != "tokhash-1" || p.MetaTools {
		t.Fatalf("bad profile: %+v", p)
	}

	// Slug is unique.
	if _, err := st.CreateProfile(ctx, "main", "Dup", u.ID, "tokhash-2"); err == nil {
		t.Fatal("duplicate slug must error")
	}

	got, err := st.GetProfileByID(ctx, p.ID)
	if err != nil || got.Slug != "main" {
		t.Fatalf("get by id: %v %+v", err, got)
	}
	if _, err := st.GetProfileByID(ctx, 999); !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("want ErrProfileNotFound, got %v", err)
	}

	if err := st.UpdateProfileName(ctx, p.ID, "Renamed"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetProfileByID(ctx, p.ID)
	if got.Name != "Renamed" {
		t.Fatalf("rename failed: %+v", got)
	}

	if err := st.SetProfileToken(ctx, p.ID, "tokhash-rotated"); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetProfileByID(ctx, p.ID)
	if got.TokenHash != "tokhash-rotated" {
		t.Fatalf("rotate failed: %+v", got)
	}
}

func TestGetProfileBySlugAndTokenHash(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u := seedUser(t, st, "alice")
	p, _ := st.CreateProfile(ctx, "main", "Main", u.ID, "good-hash")

	got, err := st.GetProfileBySlugAndTokenHash(ctx, "main", "good-hash")
	if err != nil || got.ID != p.ID {
		t.Fatalf("auth lookup: %v %+v", err, got)
	}
	if _, err := st.GetProfileBySlugAndTokenHash(ctx, "main", "bad-hash"); !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("wrong hash must be not-found, got %v", err)
	}
	if _, err := st.GetProfileBySlugAndTokenHash(ctx, "nope", "good-hash"); !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("wrong slug must be not-found, got %v", err)
	}
}

func TestListProfilesOwnVsAll(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	a := seedUser(t, st, "alice")
	b := seedUser(t, st, "bob")
	st.CreateProfile(ctx, "a1", "A1", a.ID, "h1")
	st.CreateProfile(ctx, "a2", "A2", a.ID, "h2")
	st.CreateProfile(ctx, "b1", "B1", b.ID, "h3")

	own, err := st.ListProfiles(ctx, a.ID)
	if err != nil || len(own) != 2 {
		t.Fatalf("own: %v %d", err, len(own))
	}
	all, err := st.ListProfiles(ctx, 0) // 0 = all (admin view)
	if err != nil || len(all) != 3 {
		t.Fatalf("all: %v %d", err, len(all))
	}
}

func TestProfileServersReplaceAllAndCascade(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	u := seedUser(t, st, "alice")
	p, _ := st.CreateProfile(ctx, "main", "Main", u.ID, "h")

	if err := st.SetProfileServers(ctx, p.ID, []string{"github", "echo"}); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetProfileServers(ctx, p.ID)
	if err != nil || !reflect.DeepEqual(got, []string{"echo", "github"}) { // ordered by name
		t.Fatalf("servers: %v %v", err, got)
	}

	// Replace-all semantics.
	if err := st.SetProfileServers(ctx, p.ID, []string{"fetch"}); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetProfileServers(ctx, p.ID)
	if !reflect.DeepEqual(got, []string{"fetch"}) {
		t.Fatalf("replace-all: %v", got)
	}

	// Delete cascades the join rows.
	if err := st.DeleteProfile(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetProfileByID(ctx, p.ID); !errors.Is(err, store.ErrProfileNotFound) {
		t.Fatalf("profile not deleted: %v", err)
	}
	got, _ = st.GetProfileServers(ctx, p.ID)
	if len(got) != 0 {
		t.Fatalf("join rows not cascaded: %v", got)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/store/ -run Profile` → undefined symbols.

- [ ] **Step 3: Implement** — `internal/store/profiles.go`

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrProfileNotFound is returned for unknown profiles or failed token lookups.
var ErrProfileNotFound = errors.New("store: profile not found")

// Profile is a named bundle of servers exposed at /mcp/p/<slug> behind its
// own bearer token (DESIGN #11). TokenHash is the SHA-256 hex of the token —
// plaintext is shown once at create/rotate and never stored. MetaTools is the
// DESIGN #11 opt-in flag (schema only in v1; implementation deferred).
type Profile struct {
	ID        int64
	Slug      string
	Name      string
	UserID    int64 // owner
	TokenHash string
	MetaTools bool
	CreatedAt time.Time
}

const profilesSchema = `
CREATE TABLE IF NOT EXISTS profiles (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	slug       TEXT NOT NULL UNIQUE,
	name       TEXT NOT NULL,
	user_id    INTEGER NOT NULL,
	token_hash TEXT NOT NULL,
	meta_tools INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);`

const profileServersSchema = `
CREATE TABLE IF NOT EXISTS profile_servers (
	profile_id  INTEGER NOT NULL,
	server_name TEXT NOT NULL,
	PRIMARY KEY (profile_id, server_name)
);`

const profileCols = `id,slug,name,user_id,token_hash,meta_tools,created_at`

func scanProfile(row *sql.Row) (Profile, error) {
	var p Profile
	var meta int
	var created int64
	err := row.Scan(&p.ID, &p.Slug, &p.Name, &p.UserID, &p.TokenHash, &meta, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrProfileNotFound
	}
	if err != nil {
		return Profile{}, err
	}
	p.MetaTools = meta != 0
	p.CreatedAt = time.Unix(created, 0)
	return p, nil
}

// CreateProfile inserts a profile. Slug uniqueness is enforced by the schema.
func (s *sqliteStore) CreateProfile(ctx context.Context, slug, name string, userID int64, tokenHash string) (Profile, error) {
	return scanProfile(s.db.QueryRowContext(ctx,
		`INSERT INTO profiles (slug,name,user_id,token_hash,created_at)
		 VALUES (?,?,?,?,?) RETURNING `+profileCols,
		slug, name, userID, tokenHash, time.Now().Unix()))
}

// GetProfileByID fetches a profile by id.
func (s *sqliteStore) GetProfileByID(ctx context.Context, id int64) (Profile, error) {
	return scanProfile(s.db.QueryRowContext(ctx,
		`SELECT `+profileCols+` FROM profiles WHERE id=?`, id))
}

// GetProfileBySlugAndTokenHash is the /mcp/p/{slug} auth lookup: both the
// slug and the hashed bearer token must match.
func (s *sqliteStore) GetProfileBySlugAndTokenHash(ctx context.Context, slug, tokenHash string) (Profile, error) {
	return scanProfile(s.db.QueryRowContext(ctx,
		`SELECT `+profileCols+` FROM profiles WHERE slug=? AND token_hash=?`, slug, tokenHash))
}

// ListProfiles returns profiles owned by userID, or ALL profiles when
// userID == 0 (admin view). Ordered by id.
func (s *sqliteStore) ListProfiles(ctx context.Context, userID int64) ([]Profile, error) {
	q := `SELECT ` + profileCols + ` FROM profiles`
	var args []any
	if userID != 0 {
		q += ` WHERE user_id=?`
		args = append(args, userID)
	}
	q += ` ORDER BY id`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Profile
	for rows.Next() {
		var p Profile
		var meta int
		var created int64
		if err := rows.Scan(&p.ID, &p.Slug, &p.Name, &p.UserID, &p.TokenHash, &meta, &created); err != nil {
			return nil, err
		}
		p.MetaTools = meta != 0
		p.CreatedAt = time.Unix(created, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdateProfileName renames a profile.
func (s *sqliteStore) UpdateProfileName(ctx context.Context, id int64, name string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE profiles SET name=? WHERE id=?`, name, id)
	return err
}

// SetProfileToken replaces the stored token hash (rotation).
func (s *sqliteStore) SetProfileToken(ctx context.Context, id int64, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE profiles SET token_hash=? WHERE id=?`, tokenHash, id)
	return err
}

// DeleteProfile removes a profile and its profile_servers rows in one tx.
func (s *sqliteStore) DeleteProfile(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM profile_servers WHERE profile_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM profiles WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// SetProfileServers replaces the profile's server bundle (replace-all, one tx).
func (s *sqliteStore) SetProfileServers(ctx context.Context, id int64, names []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM profile_servers WHERE profile_id=?`, id); err != nil {
		return err
	}
	for _, n := range names {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO profile_servers (profile_id, server_name) VALUES (?,?)`, id, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetProfileServers returns the profile's bundled server names, ordered.
func (s *sqliteStore) GetProfileServers(ctx context.Context, id int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT server_name FROM profile_servers WHERE profile_id=? ORDER BY server_name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}
```

Append to the `Store` interface in `internal/store/store.go`:

```go
	// CreateProfile inserts a profile (slug UNIQUE).
	CreateProfile(ctx context.Context, slug, name string, userID int64, tokenHash string) (Profile, error)
	// GetProfileByID fetches a profile; ErrProfileNotFound if missing.
	GetProfileByID(ctx context.Context, id int64) (Profile, error)
	// GetProfileBySlugAndTokenHash is the MCP endpoint auth lookup.
	GetProfileBySlugAndTokenHash(ctx context.Context, slug, tokenHash string) (Profile, error)
	// ListProfiles returns profiles owned by userID (0 = all).
	ListProfiles(ctx context.Context, userID int64) ([]Profile, error)
	// UpdateProfileName renames a profile.
	UpdateProfileName(ctx context.Context, id int64, name string) error
	// SetProfileToken replaces the stored token hash (rotation).
	SetProfileToken(ctx context.Context, id int64, tokenHash string) error
	// DeleteProfile removes a profile, cascading profile_servers.
	DeleteProfile(ctx context.Context, id int64) error
	// SetProfileServers replaces the profile's server bundle (one tx).
	SetProfileServers(ctx context.Context, id int64, names []string) error
	// GetProfileServers returns the profile's bundled server names.
	GetProfileServers(ctx context.Context, id int64) ([]string, error)
```

Append to `OpenSQLite` in `internal/store/sqlite.go`:

```go
	if _, err := db.ExecContext(ctx, profilesSchema); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, profileServersSchema); err != nil {
		db.Close()
		return nil, err
	}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/store/` → PASS.

- [ ] **Step 5: Commit** — `git add internal/store/ && git commit -m "feat(store): profiles + profile_servers with slug/token auth lookup"`

---

### Task 6: Store — audit table with keyset pagination

**Files:** Create `internal/store/audit.go`, `internal/store/audit_test.go`. Modify `internal/store/store.go`, `internal/store/sqlite.go` (one appended block).

- [ ] **Step 1: Write the failing test** — `internal/store/audit_test.go`

```go
package store_test

import (
	"context"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestAppendAndListAudit(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	alice := seedUser(t, st, "alice")
	bob := seedUser(t, st, "bob")

	mk := func(uid int64, host string) store.AuditEvent {
		return store.AuditEvent{Kind: "egress", UserID: &uid, Server: "github", Host: host, Decision: "resolved"}
	}
	if err := st.AppendAudit(ctx, mk(alice.ID, "h1.example.com")); err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := st.AppendAudit(ctx, mk(bob.ID, "h2.example.com")); err != nil {
		t.Fatal(err)
	}
	if err := st.AppendAudit(ctx, mk(alice.ID, "h3.example.com")); err != nil {
		t.Fatal(err)
	}
	// An event with no user (e.g. legacy "default" tenant egress).
	if err := st.AppendAudit(ctx, store.AuditEvent{Kind: "egress", Server: "echo", Host: "h4", Decision: "denied", Detail: "host not in allowlist"}); err != nil {
		t.Fatal(err)
	}

	all, err := st.ListAudit(ctx, 0, 10, 0)
	if err != nil || len(all) != 4 {
		t.Fatalf("list all: %v %d", err, len(all))
	}
	// Newest first; ts and id populated.
	if all[0].Host != "h4" || all[3].Host != "h1.example.com" || all[0].ID == 0 || all[0].TS.IsZero() {
		t.Fatalf("ordering/fields: %+v", all)
	}

	// Keyset pagination: page after the newest two.
	page, err := st.ListAudit(ctx, all[1].ID, 10, 0)
	if err != nil || len(page) != 2 || page[0].ID != all[2].ID {
		t.Fatalf("keyset page: %v %+v", err, page)
	}

	// Per-user filter.
	mine, err := st.ListAudit(ctx, 0, 10, alice.ID)
	if err != nil || len(mine) != 2 {
		t.Fatalf("user filter: %v %d", err, len(mine))
	}
	for _, e := range mine {
		if e.UserID == nil || *e.UserID != alice.ID {
			t.Fatalf("foreign event leaked: %+v", e)
		}
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/store/ -run Audit` → undefined `store.AuditEvent`.

- [ ] **Step 3: Implement** — `internal/store/audit.go`

```go
package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// AuditEvent is one persisted audit row (spec §3, §7). Kind partitions the
// stream: "egress" (proxy resolutions, written by the AuditingResolver),
// "auth" (login/logout) and "admin" (profile/credential/impersonation/install
// mutations, written synchronously by API handlers).
type AuditEvent struct {
	ID        int64
	TS        time.Time
	Kind      string // 'egress' | 'auth' | 'admin'
	UserID    *int64
	ProfileID *int64
	Server    string
	Host      string
	Decision  string
	Detail    string
}

const auditSchema = `
CREATE TABLE IF NOT EXISTS audit (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         INTEGER NOT NULL,
	kind       TEXT NOT NULL CHECK(kind IN ('egress','auth','admin')),
	user_id    INTEGER,
	profile_id INTEGER,
	server     TEXT NOT NULL DEFAULT '',
	host       TEXT NOT NULL DEFAULT '',
	decision   TEXT NOT NULL DEFAULT '',
	detail     TEXT NOT NULL DEFAULT ''
);`

// AppendAudit inserts an audit row. A zero TS means "now".
func (s *sqliteStore) AppendAudit(ctx context.Context, e AuditEvent) error {
	ts := e.TS
	if ts.IsZero() {
		ts = time.Now()
	}
	var uid, pid any // nil → SQL NULL
	if e.UserID != nil {
		uid = *e.UserID
	}
	if e.ProfileID != nil {
		pid = *e.ProfileID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO audit (ts,kind,user_id,profile_id,server,host,decision,detail)
		 VALUES (?,?,?,?,?,?,?,?)`,
		ts.Unix(), e.Kind, uid, pid, e.Server, e.Host, e.Decision, e.Detail)
	return err
}

// ListAudit returns audit rows newest-first with keyset pagination:
// beforeID == 0 starts at the newest row; pass the last row's ID to get the
// next page. userID filters to one user's events (0 = all). limit is clamped
// to [1,500] (defaults to 100).
func (s *sqliteStore) ListAudit(ctx context.Context, beforeID int64, limit int, userID int64) ([]AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id,ts,kind,user_id,profile_id,server,host,decision,detail FROM audit`
	var conds []string
	var args []any
	if beforeID > 0 {
		conds = append(conds, "id < ?")
		args = append(args, beforeID)
	}
	if userID > 0 {
		conds = append(conds, "user_id = ?")
		args = append(args, userID)
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var ts int64
		var uid, pid sql.NullInt64
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &uid, &pid, &e.Server, &e.Host, &e.Decision, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		if uid.Valid {
			v := uid.Int64
			e.UserID = &v
		}
		if pid.Valid {
			v := pid.Int64
			e.ProfileID = &v
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
```

Append to the `Store` interface in `internal/store/store.go`:

```go
	// AppendAudit inserts an audit row (zero TS = now).
	AppendAudit(ctx context.Context, e AuditEvent) error
	// ListAudit pages audit rows newest-first (keyset: beforeID, 0 = newest; userID 0 = all).
	ListAudit(ctx context.Context, beforeID int64, limit int, userID int64) ([]AuditEvent, error)
```

Append to `OpenSQLite` in `internal/store/sqlite.go`:

```go
	if _, err := db.ExecContext(ctx, auditSchema); err != nil {
		db.Close()
		return nil, err
	}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/store/` → PASS. Also run `make test-local` to confirm the whole tree still compiles.

- [ ] **Step 5: Commit** — `git add internal/store/ && git commit -m "feat(store): audit table with keyset-paginated read"`

---

### Task 7: Auth — tokens, session middleware, impersonation context, RBAC

**Files:** Create `internal/auth/session.go`, `internal/auth/session_test.go`.

- [ ] **Step 1: Write the failing test** — `internal/auth/session_test.go`

```go
package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

func openStore(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func seedSession(t *testing.T, st store.Store, sub, role string) (store.User, *http.Cookie) {
	t.Helper()
	ctx := context.Background()
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", sub, sub+"@x", sub, role)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, auth.HashToken(tok), u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return u, &http.Cookie{Name: auth.SessionCookie, Value: tok}
}

func TestTokenHelpers(t *testing.T) {
	s1, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	s2, _ := auth.NewSessionToken()
	if s1 == s2 || len(s1) != 43 { // 32 bytes base64url unpadded
		t.Fatalf("session tokens: %q %q", s1, s2)
	}
	p, err := auth.NewProfileToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, "gig_") || len(p) != 4+43 {
		t.Fatalf("profile token: %q", p)
	}
	h := auth.HashToken("x")
	if len(h) != 64 || h != auth.HashToken("x") || h == auth.HashToken("y") {
		t.Fatalf("hash: %q", h)
	}
}

func TestSessionMiddlewareAuthenticates(t *testing.T) {
	st := openStore(t)
	u, cookie := seedSession(t, st, "alice", "user")

	var gotReal, gotEff store.User
	var gotImp bool
	h := auth.SessionMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReal, _ = auth.RealUser(r.Context())
		gotEff, _ = auth.EffectiveUser(r.Context())
		gotImp = auth.IsImpersonating(r.Context())
		if _, ok := auth.SessionTokenHash(r.Context()); !ok {
			t.Error("no session hash in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	// No cookie → 401 with the error envelope.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/api/me", nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("no-cookie: %d %s", rec.Code, rec.Body)
	}

	// Garbage cookie → 401.
	req := httptest.NewRequest("GET", "/api/me", nil)
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: "garbage"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("garbage cookie: %d", rec.Code)
	}

	// Valid cookie → 200, real == effective, not impersonating.
	req = httptest.NewRequest("GET", "/api/me", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotReal.ID != u.ID || gotEff.ID != u.ID || gotImp {
		t.Fatalf("valid: %d real=%+v eff=%+v imp=%v", rec.Code, gotReal, gotEff, gotImp)
	}
}

func TestSessionMiddlewareImpersonation(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	admin, cookie := seedSession(t, st, "admin", "admin")
	target, _ := st.UpsertUserByOIDC(ctx, "https://idp", "target", "t@x", "Target", "user")
	if err := st.SetImpersonation(ctx, auth.HashToken(cookie.Value), target.ID, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	var gotReal, gotEff store.User
	h := auth.SessionMiddleware(st, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReal, _ = auth.RealUser(r.Context())
		gotEff, _ = auth.EffectiveUser(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	// GET: effective = target, real = admin.
	req := httptest.NewRequest("GET", "/api/profiles", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotReal.ID != admin.ID || gotEff.ID != target.ID {
		t.Fatalf("impersonated GET: %d real=%+v eff=%+v", rec.Code, gotReal, gotEff)
	}

	// Any non-GET mutation while impersonating → 403...
	req = httptest.NewRequest("POST", "/api/profiles", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("impersonated POST must be 403, got %d", rec.Code)
	}

	// ...EXCEPT DELETE /api/admin/impersonate (stop view-as).
	req = httptest.NewRequest("DELETE", "/api/admin/impersonate", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("stop-impersonation must pass through, got %d", rec.Code)
	}

	// Expired impersonation behaves as not impersonating.
	if err := st.SetImpersonation(ctx, auth.HashToken(cookie.Value), target.ID, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "/api/profiles", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if gotEff.ID != admin.ID {
		t.Fatalf("expired impersonation must fall back to real user, got eff=%+v", gotEff)
	}
}

func TestRequireAdmin(t *testing.T) {
	st := openStore(t)
	_, userCookie := seedSession(t, st, "plain", "user")
	_, adminCookie := seedSession(t, st, "boss", "admin")

	h := auth.SessionMiddleware(st, auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/api/users", nil)
	req.AddCookie(userCookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("user must be 403, got %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/api/users", nil)
	req.AddCookie(adminCookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin must pass, got %d", rec.Code)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/auth/` → undefined symbols.

- [ ] **Step 3: Implement** — `internal/auth/session.go`

```go
// Package auth owns gigmcp authentication: opaque session + profile tokens,
// the OIDC login flow (oidc.go), the session/impersonation middleware, and
// RBAC. The Go gateway is the sole auth authority (DESIGN #18); Next.js only
// forwards the cookie.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gigmcp/gigmcp/internal/store"
)

// SessionCookie is the browser session cookie name.
const SessionCookie = "gig_session"

// NewSessionToken returns a fresh opaque session token: 32 random bytes,
// base64url unpadded (43 chars). Only its SHA-256 is stored (spec §1 #1).
func NewSessionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewProfileToken returns a fresh profile bearer token: "gig_" + 32 random
// bytes base64url. The prefix makes leaked tokens greppable. Plaintext is
// shown once at create/rotate; only the SHA-256 is stored (spec §1 #2).
func NewProfileToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "gig_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the hex SHA-256 of a token — the at-rest form for both
// session and profile tokens.
func HashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

type ctxKey int

const (
	realUserKey ctxKey = iota
	effectiveUserKey
	sessionHashKey
	impersonatingKey
)

// RealUser returns the authenticated user (the admin, during impersonation).
func RealUser(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(realUserKey).(store.User)
	return u, ok
}

// EffectiveUser returns the user requests should resolve against (the
// impersonation target while view-as is active, else the real user).
func EffectiveUser(ctx context.Context) (store.User, bool) {
	u, ok := ctx.Value(effectiveUserKey).(store.User)
	return u, ok
}

// IsImpersonating reports whether view-as mode is active on this request.
func IsImpersonating(ctx context.Context) bool {
	v, _ := ctx.Value(impersonatingKey).(bool)
	return v
}

// SessionTokenHash returns the hash of the current session token (used by
// the impersonation handlers to stamp the session row, and by logout).
func SessionTokenHash(ctx context.Context) (string, bool) {
	h, ok := ctx.Value(sessionHashKey).(string)
	return h, ok
}

// writeAuthError mirrors internal/api's {"error":{"code","message"}}
// envelope. Deliberately duplicated (a handful of lines) so auth does not
// import api and api can import auth.
func writeAuthError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	}); err != nil {
		log.Printf("WARN: write auth error: %v", err)
	}
}

// stopImpersonationPath is the one mutation allowed while impersonating.
const stopImpersonationPath = "/api/admin/impersonate"

// NOTE: an impersonating admin CANNOT switch targets without stopping first.
// POST /api/admin/impersonate is itself a mutation, so the guard below blocks
// it while view-as is active (the admin must DELETE first). This is intentional
// — do not "fix" it.

// SessionMiddleware authenticates by the gig_session cookie, loads the real
// and effective users into the context, and enforces the view-as rule:
// while impersonating, every non-GET request is 403 except
// DELETE /api/admin/impersonate (DESIGN #20: view-as is read-only).
func SessionMiddleware(st store.Store, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(SessionCookie)
		if err != nil || c.Value == "" {
			writeAuthError(w, http.StatusUnauthorized, "unauthenticated", "missing session cookie")
			return
		}
		hash := HashToken(c.Value)
		sess, err := st.GetSession(r.Context(), hash)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "unauthenticated", "invalid or expired session")
			return
		}
		real, err := st.GetUser(r.Context(), sess.UserID)
		if err != nil {
			writeAuthError(w, http.StatusUnauthorized, "unauthenticated", "session user no longer exists")
			return
		}
		effective := real
		impersonating := false
		if sess.ImpersonatingUserID != nil && sess.ImpersonationExpiresAt != nil &&
			time.Now().Before(*sess.ImpersonationExpiresAt) {
			if target, err := st.GetUser(r.Context(), *sess.ImpersonatingUserID); err == nil {
				effective = target
				impersonating = true
			}
		}
		if impersonating && r.Method != http.MethodGet &&
			!(r.Method == http.MethodDelete && r.URL.Path == stopImpersonationPath) {
			writeAuthError(w, http.StatusForbidden, "impersonating",
				"mutations are blocked while impersonating (view-as is read-only)")
			return
		}
		ctx := context.WithValue(r.Context(), realUserKey, real)
		ctx = context.WithValue(ctx, effectiveUserKey, effective)
		ctx = context.WithValue(ctx, sessionHashKey, hash)
		ctx = context.WithValue(ctx, impersonatingKey, impersonating)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin gates a handler on the REAL user's role, so an admin keeps
// admin endpoints while impersonating (needed to stop view-as) and a
// non-admin can never gain them.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := RealUser(r.Context())
		if !ok || u.Role != "admin" {
			writeAuthError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/auth/` → PASS (4 tests).

- [ ] **Step 5: Commit** — `git add internal/auth/ && git commit -m "feat(auth): opaque tokens, session middleware, impersonation context, RBAC"`

---

### Task 8: Auth — OIDC Authenticator (login / callback / logout)

**Files:** Create `internal/auth/oidc.go`, `internal/auth/oidc_test.go`. Possibly modify `go.mod` (`go-jose/v4` into `require` if `go mod tidy` puts it there for the test import).

> The go-oidc/oauth2 names below were pre-verified by the Task 1 spike. If the spike recorded drift, apply it here first.

- [ ] **Step 1: Write the failing test** — `internal/auth/oidc_test.go`. This file contains the complete fake-OIDC-issuer helper: an httptest server serving discovery JSON, a JWKS, and a token endpoint; ID tokens are RS256-signed with go-jose.

```go
package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/config"
	"github.com/gigmcp/gigmcp/internal/store"
)

// fakeIssuer is a minimal OIDC provider: discovery + JWKS + token endpoint.
// The test mints the ID token AFTER it learns the nonce from the login
// redirect, then the token endpoint serves it.
type fakeIssuer struct {
	srv     *httptest.Server
	key     *rsa.PrivateKey
	idToken string // set by the test before hitting the callback
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIssuer{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &f.key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig",
		}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     f.idToken,
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// mintIDToken RS256-signs an ID token with the given nonce and roles claim.
func (f *fakeIssuer) mintIDToken(t *testing.T, clientID, sub, email, name, nonce string, roles map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{
		"iss":           f.srv.URL,
		"aud":           clientID,
		"sub":           sub,
		"exp":           time.Now().Add(time.Hour).Unix(),
		"iat":           time.Now().Unix(),
		"nonce":         nonce,
		"email":         email,
		"name":          name,
		auth.RolesClaim: roles,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sig.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func newAuthenticator(t *testing.T, issuerURL string, st store.Store) *auth.Authenticator {
	t.Helper()
	cfg := config.Config{
		OIDCIssuer:      issuerURL,
		OIDCClientID:    "gigmcp-client",
		OIDCRedirectURL: "http://localhost:8080/api/auth/callback",
		OIDCAdminRole:   "gigmcp-admin",
		SessionTTL:      time.Hour,
		PublicURL:       "http://localhost:8080",
	}
	a, err := auth.NewAuthenticator(context.Background(), cfg, st)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}

// startLogin drives LoginHandler and returns the state, nonce and flow cookie.
func startLogin(t *testing.T, a *auth.Authenticator) (state, nonce string, flow *http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.LoginHandler(rec, httptest.NewRequest("GET", "/api/auth/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login status %d: %s", rec.Code, rec.Body)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state = loc.Query().Get("state")
	nonce = loc.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatalf("authorize URL missing state/nonce: %s", loc)
	}
	if loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("PKCE challenge missing from authorize URL: %s", loc)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "gig_oidc_flow" {
			flow = c
		}
	}
	if flow == nil {
		t.Fatal("no flow cookie set by LoginHandler")
	}
	return state, nonce, flow
}

func TestLoginCallbackProvisionsUserAndSession(t *testing.T) {
	ctx := context.Background()
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)

	state, nonce, flow := startLogin(t, a)

	// Roles claim contains the admin role → user must come out "admin".
	iss.idToken = iss.mintIDToken(t, "gigmcp-client", "user-123", "alice@example.com", "Alice", nonce,
		map[string]any{"gigmcp-admin": map[string]any{"org1": "org1.example"}})

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: code=%d loc=%q body=%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	var sessionCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookie && c.Value != "" {
			sessionCookie = c
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly {
		t.Fatalf("session cookie missing or not httpOnly: %+v", sessionCookie)
	}

	users, err := st.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("users: %v %d", err, len(users))
	}
	if users[0].Subject != "user-123" || users[0].Role != "admin" || users[0].Email != "alice@example.com" {
		t.Fatalf("JIT user: %+v", users[0])
	}

	sess, err := st.GetSession(ctx, auth.HashToken(sessionCookie.Value))
	if err != nil || sess.UserID != users[0].ID {
		t.Fatalf("session row: %v %+v", err, sess)
	}

	events, err := st.ListAudit(ctx, 0, 10, 0)
	if err != nil || len(events) == 0 || events[0].Kind != "auth" || events[0].Decision != "login" {
		t.Fatalf("login audit event: %v %+v", err, events)
	}
}

func TestCallbackRejectsStateMismatch(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	_, nonce, flow := startLogin(t, a)
	iss.idToken = iss.mintIDToken(t, "gigmcp-client", "user-123", "a@x", "A", nonce, nil)

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state=evil", nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("state mismatch must 400, got %d", rec.Code)
	}
	if users, _ := st.ListUsers(context.Background()); len(users) != 0 {
		t.Fatal("no user may be provisioned on a failed callback")
	}
}

func TestCallbackRejectsNonceMismatch(t *testing.T) {
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	state, _, flow := startLogin(t, a)
	// Mint with the WRONG nonce.
	iss.idToken = iss.mintIDToken(t, "gigmcp-client", "user-123", "a@x", "A", "wrong-nonce", nil)

	req := httptest.NewRequest("GET", "/api/auth/callback?code=fake-code&state="+url.QueryEscape(state), nil)
	req.AddCookie(flow)
	rec := httptest.NewRecorder()
	a.CallbackHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("nonce mismatch must 401, got %d", rec.Code)
	}
}

func TestLogoutDeletesSession(t *testing.T) {
	ctx := context.Background()
	iss := newFakeIssuer(t)
	st := openStore(t)
	a := newAuthenticator(t, iss.srv.URL, st)
	_, cookie := seedSession(t, st, "alice", "user")

	req := httptest.NewRequest("POST", "/api/auth/logout", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	a.LogoutHandler(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if _, err := st.GetSession(ctx, auth.HashToken(cookie.Value)); err == nil {
		t.Fatal("session must be deleted on logout")
	}
	events, _ := st.ListAudit(ctx, 0, 10, 0)
	if len(events) == 0 || events[0].Decision != "logout" {
		t.Fatalf("logout audit event: %+v", events)
	}
}

func TestMapRole(t *testing.T) {
	if auth.MapRole(map[string]any{"gigmcp-admin": map[string]any{}}, "gigmcp-admin") != "admin" {
		t.Fatal("admin role present must map to admin")
	}
	if auth.MapRole(map[string]any{"other-role": 1}, "gigmcp-admin") != "user" {
		t.Fatal("other roles must map to user")
	}
	if auth.MapRole(nil, "gigmcp-admin") != "user" {
		t.Fatal("nil claim must map to user")
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/auth/ -run Login\|Callback\|Logout\|MapRole` → undefined `auth.NewAuthenticator` etc. If the `go-jose/v4` import fails, run `go get github.com/go-jose/go-jose/v4 && go mod tidy`.

- [ ] **Step 3: Implement** — `internal/auth/oidc.go`

```go
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/gigmcp/gigmcp/internal/config"
	"github.com/gigmcp/gigmcp/internal/store"
)

// RolesClaim is Zitadel's project-roles ID-token claim: a map of
// role-key → {orgID: orgDomain}. Membership of the configured admin role key
// maps to gigmcp role "admin" (spec §1 decision 6, §4).
const RolesClaim = "urn:zitadel:iam:org:project:roles"

// flowCookie carries state+nonce+PKCE verifier between login and callback.
const flowCookie = "gig_oidc_flow"

// Authenticator drives the OIDC authorization-code+PKCE flow and issues
// opaque DB sessions. Zitadel is the sole IdP (generic OIDC client; social
// login is federated inside Zitadel).
type Authenticator struct {
	Store      store.Store
	verifier   *oidc.IDTokenVerifier
	oauth      oauth2.Config
	adminRole  string
	sessionTTL time.Duration
	secure     bool // Secure cookie flag: true iff GIG_PUBLIC_URL is https
	// hmacKey signs the transient flow cookie. Random per process: in-flight
	// logins do NOT survive a gateway restart (acceptable — users just retry).
	hmacKey []byte
}

// NewAuthenticator runs OIDC discovery against cfg.OIDCIssuer and builds the
// flow. Call only when cfg.OIDCEnabled().
func NewAuthenticator(ctx context.Context, cfg config.Config, st store.Store) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %s: %w", cfg.OIDCIssuer, err)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &Authenticator{
		Store:    st,
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID}),
		oauth: oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret, // empty for PKCE public clients
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.OIDCRedirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		adminRole:  cfg.OIDCAdminRole,
		sessionTTL: cfg.SessionTTL,
		secure:     strings.HasPrefix(cfg.PublicURL, "https://"),
		hmacKey:    key,
	}, nil
}

// flowState is the signed payload of the 10-minute flow cookie — no DB row
// for pending logins (spec §4).
type flowState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"` // PKCE code verifier
	Expires  int64  `json:"expires"`  // unix seconds
}

func randB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Authenticator) signFlow(fs flowState) (string, error) {
	payload, err := json.Marshal(fs)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, a.hmacKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (a *Authenticator) verifyFlow(v string) (flowState, error) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return flowState{}, errors.New("malformed flow cookie")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return flowState{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return flowState{}, err
	}
	mac := hmac.New(sha256.New, a.hmacKey)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return flowState{}, errors.New("bad flow cookie signature")
	}
	var fs flowState
	if err := json.Unmarshal(payload, &fs); err != nil {
		return flowState{}, err
	}
	if time.Now().Unix() > fs.Expires {
		return flowState{}, errors.New("login flow expired")
	}
	return fs, nil
}

func (a *Authenticator) flowCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: flowCookie, Value: value, Path: "/api/auth", MaxAge: maxAge,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	}
}

// LoginHandler — GET /api/auth/login: 302 to the IdP's authorize endpoint
// with state + nonce + PKCE S256 challenge; the verifier travels only in the
// signed flow cookie.
func (a *Authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randB64(16)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "entropy unavailable")
		return
	}
	nonce, err := randB64(16)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "entropy unavailable")
		return
	}
	pkce := oauth2.GenerateVerifier()
	signed, err := a.signFlow(flowState{
		State: state, Nonce: nonce, Verifier: pkce,
		Expires: time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "sign login flow")
		return
	}
	http.SetCookie(w, a.flowCookie(signed, 600))
	http.Redirect(w, r,
		a.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkce)),
		http.StatusFound)
}

// CallbackHandler — GET /api/auth/callback: state check, code exchange
// (PKCE verifier), ID-token verification (signature, issuer, audience,
// nonce), role mapping, JIT user upsert, session issuance, 302 "/".
func (a *Authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(flowCookie)
	if err != nil {
		writeAuthError(w, http.StatusBadRequest, "oidc", "missing login flow cookie (login again)")
		return
	}
	fs, err := a.verifyFlow(c.Value)
	if err != nil {
		writeAuthError(w, http.StatusBadRequest, "oidc", "invalid login flow: "+err.Error())
		return
	}
	if r.URL.Query().Get("state") != fs.State {
		writeAuthError(w, http.StatusBadRequest, "oidc", "state mismatch")
		return
	}
	tok, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(fs.Verifier))
	if err != nil {
		writeAuthError(w, http.StatusBadGateway, "oidc", "code exchange failed")
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		writeAuthError(w, http.StatusBadGateway, "oidc", "token response had no id_token")
		return
	}
	idt, err := a.verifier.Verify(r.Context(), rawID)
	if err != nil {
		writeAuthError(w, http.StatusUnauthorized, "oidc", "id_token verification failed")
		return
	}
	if idt.Nonce != fs.Nonce {
		writeAuthError(w, http.StatusUnauthorized, "oidc", "nonce mismatch")
		return
	}
	var claims struct {
		Email string         `json:"email"`
		Name  string         `json:"name"`
		Roles map[string]any `json:"urn:zitadel:iam:org:project:roles"`
	}
	if err := idt.Claims(&claims); err != nil {
		writeAuthError(w, http.StatusBadGateway, "oidc", "parse id_token claims")
		return
	}
	role := MapRole(claims.Roles, a.adminRole)
	user, err := a.Store.UpsertUserByOIDC(r.Context(), idt.Issuer, idt.Subject, claims.Email, claims.Name, role)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "provision user")
		return
	}
	sessionToken, err := NewSessionToken()
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "entropy unavailable")
		return
	}
	if err := a.Store.CreateSession(r.Context(), HashToken(sessionToken), user.ID, time.Now().Add(a.sessionTTL)); err != nil {
		writeAuthError(w, http.StatusInternalServerError, "internal", "create session")
		return
	}
	http.SetCookie(w, a.flowCookie("", -1)) // clear the flow cookie
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: sessionToken, Path: "/",
		MaxAge: int(a.sessionTTL / time.Second),
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
	uid := user.ID
	if err := a.Store.AppendAudit(r.Context(), store.AuditEvent{
		Kind: "auth", UserID: &uid, Decision: "login", Detail: user.Email,
	}); err != nil {
		log.Printf("WARN: audit login: %v", err)
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// LogoutHandler — POST /api/auth/logout: delete the session row, clear the
// cookie. Local logout only in v1 (RP-initiated Zitadel logout is a follow-up).
func (a *Authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(SessionCookie); err == nil && c.Value != "" {
		hash := HashToken(c.Value)
		if sess, err := a.Store.GetSession(r.Context(), hash); err == nil {
			uid := sess.UserID
			if err := a.Store.AppendAudit(r.Context(), store.AuditEvent{
				Kind: "auth", UserID: &uid, Decision: "logout",
			}); err != nil {
				log.Printf("WARN: audit logout: %v", err)
			}
		}
		if err := a.Store.DeleteSession(r.Context(), hash); err != nil {
			log.Printf("WARN: delete session: %v", err)
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: a.secure, SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// MapRole maps the Zitadel roles claim to a gigmcp role: "admin" iff the
// claim map contains the configured admin role key. Refreshed every login —
// roles are a cache of IdP state, never edited locally.
func MapRole(roles map[string]any, adminRole string) string {
	if _, ok := roles[adminRole]; ok {
		return "admin"
	}
	return "user"
}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/auth/` → PASS (9 tests). Run `go mod tidy` and confirm `github.com/go-jose/go-jose/v4` landed in `go.mod` (test-only import).

- [ ] **Step 5: Commit** — `git add internal/auth/ go.mod go.sum && git commit -m "feat(auth): OIDC code+PKCE flow with signed flow cookie, JIT provisioning, role mapping"`

---

### Task 9: API skeleton — Server, Routes, error envelope, /api/me

**Files:** Create `internal/api/api.go`, `internal/api/respond.go`, `internal/api/me.go`, `internal/api/api_test.go`.

- [ ] **Step 1: Write the failing test** — `internal/api/api_test.go`

```go
package api_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/api"
	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// fakeInvalidator records ProfileHost invalidations.
type fakeInvalidator struct{ ids []int64 }

func (f *fakeInvalidator) Invalidate(id int64) { f.ids = append(f.ids, id) }

// newTestAPI builds an api.Server over a temp SQLite store + random-KEK vault
// (Auth stays nil — the /api/auth/* mounts are skipped; session rows are
// seeded directly).
func newTestAPI(t *testing.T) (*api.Server, *httptest.Server, store.Store, *fakeInvalidator) {
	t.Helper()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	inv := &fakeInvalidator{}
	srv := &api.Server{Store: st, Vault: v, Profiles: inv}
	ts := httptest.NewServer(srv.Routes())
	t.Cleanup(ts.Close)
	return srv, ts, st, inv
}

// seedUserSession provisions a user + live session, returning the cookie.
func seedUserSession(t *testing.T, st store.Store, email, role string) (store.User, *http.Cookie) {
	t.Helper()
	ctx := context.Background()
	u, err := st.UpsertUserByOIDC(ctx, "https://idp.test", "sub-"+email, email, email, role)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := auth.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, auth.HashToken(tok), u.ID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	return u, &http.Cookie{Name: auth.SessionCookie, Value: tok}
}

// doJSON sends a request with optional cookie + JSON body, returning status + body.
func doJSON(t *testing.T, ts *httptest.Server, cookie *http.Cookie, method, path, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

func TestMeRequiresSession(t *testing.T) {
	_, ts, _, _ := newTestAPI(t)
	code, body := doJSON(t, ts, nil, "GET", "/api/me", "")
	if code != http.StatusUnauthorized || !strings.Contains(string(body), `"error"`) {
		t.Fatalf("unauthed /api/me: %d %s", code, body)
	}
}

func TestMeReturnsEffectiveUser(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	u, cookie := seedUserSession(t, st, "alice@x", "user")

	code, body := doJSON(t, ts, cookie, "GET", "/api/me", "")
	if code != http.StatusOK {
		t.Fatalf("/api/me: %d %s", code, body)
	}
	var got struct {
		User struct {
			ID    int64  `json:"id"`
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
		Impersonating bool `json:"impersonating"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.User.ID != u.ID || got.User.Email != "alice@x" || got.User.Role != "user" || got.Impersonating {
		t.Fatalf("me: %+v", got)
	}
}

func TestMeShowsImpersonation(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	admin, cookie := seedUserSession(t, st, "admin@x", "admin")
	target, _ := seedUserSession(t, st, "target@x", "user")
	if err := st.SetImpersonation(context.Background(), auth.HashToken(cookie.Value), target.ID, time.Now().Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/me", "")
	if code != http.StatusOK {
		t.Fatalf("/api/me: %d %s", code, body)
	}
	var got struct {
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
		Impersonating bool `json:"impersonating"`
		RealUser      *struct {
			ID int64 `json:"id"`
		} `json:"real_user"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Impersonating || got.User.ID != target.ID || got.RealUser == nil || got.RealUser.ID != admin.ID {
		t.Fatalf("impersonated me: %+v", got)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/api/` → undefined `api.Server`.

- [ ] **Step 3: Implement** — three files.

`internal/api/api.go`:

```go
// Package api is the REST control plane (spec §5): JSON endpoints behind the
// session middleware, mounted under /api/ on the gateway's single mux. It
// imports auth and registry, never gateway (ProfileInvalidator decouples it
// from the ProfileHost).
package api

import (
	"net/http"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// ProfileInvalidator tears down a profile's MCP runtime after a mutation.
// Implemented by *gateway.ProfileHost (declared locally to avoid an
// api→gateway import). May be nil in tests.
type ProfileInvalidator interface {
	Invalidate(profileID int64)
}

// Server holds the control-plane dependencies.
type Server struct {
	Store    store.Store
	Vault    *vault.Vault
	Auth     *auth.Authenticator // nil = OIDC unconfigured (auth routes unmounted)
	Profiles ProfileInvalidator
}

// invalidate is a nil-safe ProfileInvalidator call.
func (s *Server) invalidate(profileID int64) {
	if s.Profiles != nil {
		s.Profiles.Invalidate(profileID)
	}
}

// Routes builds the /api mux: /api/auth/* is unauthenticated (it IS the
// authentication); everything else runs behind SessionMiddleware. Go 1.22+
// ServeMux precedence makes the specific auth patterns win over "/api/".
func (s *Server) Routes() *http.ServeMux {
	authed := http.NewServeMux()
	authed.HandleFunc("GET /api/me", s.handleMe)

	mux := http.NewServeMux()
	if s.Auth != nil {
		mux.HandleFunc("GET /api/auth/login", s.Auth.LoginHandler)
		mux.HandleFunc("GET /api/auth/callback", s.Auth.CallbackHandler)
		mux.HandleFunc("POST /api/auth/logout", s.Auth.LogoutHandler)
	}
	mux.Handle("/api/", auth.SessionMiddleware(s.Store, authed))
	return mux
}
```

`internal/api/respond.go`:

```go
package api

import (
	"encoding/json"
	"log"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("WARN: write JSON response: %v", err)
	}
}

// writeErr emits the uniform {"error":{"code","message"}} envelope (spec §5).
func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
```

`internal/api/me.go`:

```go
package api

import (
	"net/http"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

type userJSON struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

func toUserJSON(u store.User) userJSON {
	return userJSON{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Role: u.Role}
}

// handleMe — GET /api/me: the effective user, plus both identities while
// impersonating (the dashboard banner is driven by this).
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	effective, ok := auth.EffectiveUser(r.Context())
	if !ok {
		writeErr(w, http.StatusUnauthorized, "unauthenticated", "no user in context")
		return
	}
	resp := struct {
		User          userJSON  `json:"user"`
		Impersonating bool      `json:"impersonating"`
		RealUser      *userJSON `json:"real_user,omitempty"`
	}{User: toUserJSON(effective), Impersonating: auth.IsImpersonating(r.Context())}
	if resp.Impersonating {
		if real, ok := auth.RealUser(r.Context()); ok {
			rj := toUserJSON(real)
			resp.RealUser = &rj
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/api/` → PASS (3 tests).

- [ ] **Step 5: Commit** — `git add internal/api/ && git commit -m "feat(api): skeleton — Server, Routes, error envelope, GET /api/me"`

---

### Task 10: API — profile CRUD + one-time tokens

**Files:** Create `internal/api/profiles.go`, `internal/api/profiles_test.go`. Modify `internal/api/api.go` (route lines only).

- [ ] **Step 1: Write the failing test** — `internal/api/profiles_test.go`

```go
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type profileResp struct {
	ID       int64    `json:"id"`
	Slug     string   `json:"slug"`
	Name     string   `json:"name"`
	UserID   int64    `json:"user_id"`
	Endpoint string   `json:"endpoint"`
	Servers  []string `json:"servers"`
	Token    string   `json:"token"`
}

func TestProfileCreateReturnsTokenOnce(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")

	code, body := doJSON(t, ts, cookie, "POST", "/api/profiles", `{"name":"Main","slug":"main"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created profileResp
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Token, "gig_") || created.Endpoint != "/mcp/p/main" {
		t.Fatalf("created: %+v", created)
	}

	// Detail never returns the token.
	code, body = doJSON(t, ts, cookie, "GET", "/api/profiles/"+itoa(created.ID), "")
	if code != http.StatusOK || strings.Contains(string(body), created.Token) || strings.Contains(string(body), `"token"`) {
		t.Fatalf("detail leaked token: %d %s", code, body)
	}

	// Duplicate slug → 409.
	code, _ = doJSON(t, ts, cookie, "POST", "/api/profiles", `{"name":"Dup","slug":"main"}`)
	if code != http.StatusConflict {
		t.Fatalf("duplicate slug: %d", code)
	}
}

func TestProfileSlugValidation(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	for _, slug := range []string{"", "A", "-x", "has space", "x", strings.Repeat("a", 64)} {
		code, _ := doJSON(t, ts, cookie, "POST", "/api/profiles", `{"name":"N","slug":"`+slug+`"}`)
		if code != http.StatusBadRequest {
			t.Fatalf("slug %q must 400, got %d", slug, code)
		}
	}
}

func TestProfileOwnership(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, alice := seedUserSession(t, st, "alice@x", "user")
	_, bob := seedUserSession(t, st, "bob@x", "user")
	_, admin := seedUserSession(t, st, "admin@x", "admin")

	code, body := doJSON(t, ts, alice, "POST", "/api/profiles", `{"name":"Main","slug":"main"}`)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created profileResp
	json.Unmarshal(body, &created)

	// Bob can neither see nor mutate Alice's profile (404, not 403 — no existence leak).
	if code, _ := doJSON(t, ts, bob, "GET", "/api/profiles/"+itoa(created.ID), ""); code != http.StatusNotFound {
		t.Fatalf("bob GET: %d", code)
	}
	if code, _ := doJSON(t, ts, bob, "DELETE", "/api/profiles/"+itoa(created.ID), ""); code != http.StatusNotFound {
		t.Fatalf("bob DELETE: %d", code)
	}
	// Admin can.
	if code, _ := doJSON(t, ts, admin, "GET", "/api/profiles/"+itoa(created.ID), ""); code != http.StatusOK {
		t.Fatalf("admin GET: %d", code)
	}
	// List: alice sees hers, bob sees none, admin sees all.
	_, body = doJSON(t, ts, alice, "GET", "/api/profiles", "")
	var mine []profileResp
	json.Unmarshal(body, &mine)
	if len(mine) != 1 {
		t.Fatalf("alice list: %s", body)
	}
	_, body = doJSON(t, ts, bob, "GET", "/api/profiles", "")
	var theirs []profileResp
	json.Unmarshal(body, &theirs)
	if len(theirs) != 0 {
		t.Fatalf("bob list: %s", body)
	}
	_, body = doJSON(t, ts, admin, "GET", "/api/profiles", "")
	var all []profileResp
	json.Unmarshal(body, &all)
	if len(all) != 1 {
		t.Fatalf("admin list: %s", body)
	}
}

func TestProfileServersAndRotateAndDelete(t *testing.T) {
	ctx := context.Background()
	_, ts, st, inv := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}

	_, body := doJSON(t, ts, cookie, "POST", "/api/profiles", `{"name":"Main","slug":"main"}`)
	var created profileResp
	json.Unmarshal(body, &created)
	id := itoa(created.ID)

	// Unknown server name → 400.
	if code, _ := doJSON(t, ts, cookie, "PUT", "/api/profiles/"+id+"/servers", `{"servers":["nope"]}`); code != http.StatusBadRequest {
		t.Fatalf("unknown server: %d", code)
	}
	// Valid bundle → 200 + runtime invalidated.
	if code, _ := doJSON(t, ts, cookie, "PUT", "/api/profiles/"+id+"/servers", `{"servers":["echo"]}`); code != http.StatusOK {
		t.Fatalf("set servers: %d", code)
	}
	if len(inv.ids) != 1 || inv.ids[0] != created.ID {
		t.Fatalf("bundle change must invalidate runtime: %v", inv.ids)
	}
	names, _ := st.GetProfileServers(ctx, created.ID)
	if len(names) != 1 || names[0] != "echo" {
		t.Fatalf("servers not persisted: %v", names)
	}

	// Rotate: new plaintext, old hash replaced, runtime NOT invalidated.
	before := len(inv.ids)
	code, body := doJSON(t, ts, cookie, "POST", "/api/profiles/"+id+"/token", "")
	if code != http.StatusOK {
		t.Fatalf("rotate: %d %s", code, body)
	}
	var rotated profileResp
	json.Unmarshal(body, &rotated)
	if !strings.HasPrefix(rotated.Token, "gig_") || rotated.Token == created.Token {
		t.Fatalf("rotated token: %+v", rotated)
	}
	if len(inv.ids) != before {
		t.Fatal("token rotation must NOT invalidate the runtime")
	}

	// Rename.
	if code, _ := doJSON(t, ts, cookie, "PATCH", "/api/profiles/"+id, `{"name":"Renamed"}`); code != http.StatusOK {
		t.Fatalf("patch: %d", code)
	}

	// Delete → 204, runtime invalidated, audit rows exist.
	if code, _ := doJSON(t, ts, cookie, "DELETE", "/api/profiles/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if inv.ids[len(inv.ids)-1] != created.ID {
		t.Fatalf("delete must invalidate runtime: %v", inv.ids)
	}
	events, err := st.ListAudit(ctx, 0, 50, 0)
	if err != nil || len(events) == 0 {
		t.Fatalf("audit: %v %d", err, len(events))
	}
	decisions := map[string]bool{}
	for _, e := range events {
		decisions[e.Decision] = true
	}
	for _, want := range []string{"profile_create", "profile_servers", "profile_token_rotate", "profile_delete"} {
		if !decisions[want] {
			t.Fatalf("missing audit decision %q in %v", want, decisions)
		}
	}
}
```

Also add this tiny helper to `internal/api/api_test.go` (bottom of the file):

```go
func itoa(n int64) string { return strconv.FormatInt(n, 10) }
```

with `"strconv"` added to its imports.

- [ ] **Step 2: Run, verify fail** — `go test ./internal/api/ -run Profile` → 404s (routes missing) / undefined handlers.

- [ ] **Step 3: Implement** — `internal/api/profiles.go`

```go
package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// slugRe: lowercase DNS-ish, 2–63 chars, no leading hyphen (spec Task rule).
var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

type profileJSON struct {
	ID       int64    `json:"id"`
	Slug     string   `json:"slug"`
	Name     string   `json:"name"`
	UserID   int64    `json:"user_id"`
	Endpoint string   `json:"endpoint"`
	Servers  []string `json:"servers"`
	Token    string   `json:"token,omitempty"` // plaintext, ONLY on create/rotate
}

func (s *Server) toProfileJSON(r *http.Request, p store.Profile) (profileJSON, error) {
	servers, err := s.Store.GetProfileServers(r.Context(), p.ID)
	if err != nil {
		return profileJSON{}, err
	}
	if servers == nil {
		servers = []string{}
	}
	return profileJSON{
		ID: p.ID, Slug: p.Slug, Name: p.Name, UserID: p.UserID,
		Endpoint: "/mcp/p/" + p.Slug, Servers: servers,
	}, nil
}

// audit writes a synchronous admin/auth audit row from a handler.
func (s *Server) audit(r *http.Request, kind, decision, detail string, profileID *int64) {
	var uid *int64
	if u, ok := auth.RealUser(r.Context()); ok {
		id := u.ID
		uid = &id
	}
	if err := s.Store.AppendAudit(r.Context(), store.AuditEvent{
		Kind: kind, UserID: uid, ProfileID: profileID, Decision: decision, Detail: detail,
	}); err != nil {
		log.Printf("WARN: audit %s/%s: %v", kind, decision, err)
	}
}

// loadOwnedProfile fetches {id} and enforces owner-or-admin; foreign profiles
// read as 404 to avoid leaking existence.
func (s *Server) loadOwnedProfile(w http.ResponseWriter, r *http.Request) (store.Profile, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid profile id")
		return store.Profile{}, false
	}
	p, err := s.Store.GetProfileByID(r.Context(), id)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "profile not found")
		return store.Profile{}, false
	}
	effective, _ := auth.EffectiveUser(r.Context())
	real, _ := auth.RealUser(r.Context())
	if p.UserID != effective.ID && real.Role != "admin" {
		writeErr(w, http.StatusNotFound, "not_found", "profile not found")
		return store.Profile{}, false
	}
	return p, true
}

// handleListProfiles — GET /api/profiles: own; admins see all.
func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	effective, _ := auth.EffectiveUser(r.Context())
	filter := effective.ID
	if effective.Role == "admin" {
		filter = 0
	}
	profiles, err := s.Store.ListProfiles(r.Context(), filter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "list profiles")
		return
	}
	out := []profileJSON{}
	for _, p := range profiles {
		pj, err := s.toProfileJSON(r, p)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "load profile servers")
			return
		}
		out = append(out, pj)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleCreateProfile — POST /api/profiles {name, slug}: creates and returns
// the bearer token PLAINTEXT EXACTLY ONCE.
func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be {name, slug}")
		return
	}
	if !slugRe.MatchString(body.Slug) {
		writeErr(w, http.StatusBadRequest, "bad_request", "slug must match ^[a-z0-9][a-z0-9-]{1,62}$")
		return
	}
	owner, _ := auth.EffectiveUser(r.Context())
	tok, err := auth.NewProfileToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "entropy unavailable")
		return
	}
	p, err := s.Store.CreateProfile(r.Context(), body.Slug, body.Name, owner.ID, auth.HashToken(tok))
	if err != nil {
		// SQLite says "UNIQUE constraint failed"; Postgres will say
		// "duplicate key value". Either way: the slug is taken.
		if strings.Contains(err.Error(), "UNIQUE") || strings.Contains(err.Error(), "duplicate key") {
			writeErr(w, http.StatusConflict, "conflict", "slug already in use")
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal", "create profile")
		return
	}
	pid := p.ID
	s.audit(r, "admin", "profile_create", fmt.Sprintf("slug=%s", p.Slug), &pid)
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "load profile")
		return
	}
	pj.Token = tok
	writeJSON(w, http.StatusCreated, pj)
}

// handleGetProfile — GET /api/profiles/{id}: detail incl. endpoint URL and
// servers; NEVER the token.
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "load profile servers")
		return
	}
	writeJSON(w, http.StatusOK, pj)
}

// handlePatchProfile — PATCH /api/profiles/{id} {name}.
func (s *Server) handlePatchProfile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be {name}")
		return
	}
	if err := s.Store.UpdateProfileName(r.Context(), p.ID, body.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "rename profile")
		return
	}
	pid := p.ID
	s.audit(r, "admin", "profile_rename", body.Name, &pid)
	p.Name = body.Name
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "load profile")
		return
	}
	writeJSON(w, http.StatusOK, pj)
}

// handleDeleteProfile — DELETE /api/profiles/{id}: cascades profile_servers
// and tears down the runtime.
func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteProfile(r.Context(), p.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "delete profile")
		return
	}
	s.invalidate(p.ID)
	pid := p.ID
	s.audit(r, "admin", "profile_delete", fmt.Sprintf("slug=%s", p.Slug), &pid)
	w.WriteHeader(http.StatusNoContent)
}

// handlePutProfileServers — PUT /api/profiles/{id}/servers {servers[]}:
// replace-all; every name must be an installed server; invalidates the runtime.
func (s *Server) handlePutProfileServers(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	var body struct {
		Servers []string `json:"servers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be {servers: [names]}")
		return
	}
	installed, err := s.Store.ListServers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "list servers")
		return
	}
	known := map[string]bool{}
	for _, srv := range installed {
		known[srv.Name] = true
	}
	for _, n := range body.Servers {
		if !known[n] {
			writeErr(w, http.StatusBadRequest, "bad_request", "unknown server: "+n)
			return
		}
	}
	if err := s.Store.SetProfileServers(r.Context(), p.ID, body.Servers); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "set profile servers")
		return
	}
	s.invalidate(p.ID)
	pid := p.ID
	s.audit(r, "admin", "profile_servers", strings.Join(body.Servers, ","), &pid)
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "load profile")
		return
	}
	writeJSON(w, http.StatusOK, pj)
}

// handleRotateProfileToken — POST /api/profiles/{id}/token: returns the new
// plaintext once. Rotation does NOT invalidate the runtime (spec §6).
func (s *Server) handleRotateProfileToken(w http.ResponseWriter, r *http.Request) {
	p, ok := s.loadOwnedProfile(w, r)
	if !ok {
		return
	}
	tok, err := auth.NewProfileToken()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "entropy unavailable")
		return
	}
	if err := s.Store.SetProfileToken(r.Context(), p.ID, auth.HashToken(tok)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "rotate token")
		return
	}
	pid := p.ID
	s.audit(r, "admin", "profile_token_rotate", "", &pid)
	pj, err := s.toProfileJSON(r, p)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "load profile")
		return
	}
	pj.Token = tok
	writeJSON(w, http.StatusOK, pj)
}
```

In `internal/api/api.go` `Routes()`, add these lines right after the `authed.HandleFunc("GET /api/me", ...)` line:

```go
	authed.HandleFunc("GET /api/profiles", s.handleListProfiles)
	authed.HandleFunc("POST /api/profiles", s.handleCreateProfile)
	authed.HandleFunc("GET /api/profiles/{id}", s.handleGetProfile)
	authed.HandleFunc("PATCH /api/profiles/{id}", s.handlePatchProfile)
	authed.HandleFunc("DELETE /api/profiles/{id}", s.handleDeleteProfile)
	authed.HandleFunc("PUT /api/profiles/{id}/servers", s.handlePutProfileServers)
	authed.HandleFunc("POST /api/profiles/{id}/token", s.handleRotateProfileToken)
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/api/` → PASS (7 tests).

- [ ] **Step 5: Commit** — `git add internal/api/ && git commit -m "feat(api): profile CRUD with one-time tokens, ownership, bundle validation, audit"`

---

### Task 11: API — credentials (write-only, vault-encrypted, tenant = user ID)

**Files:** Create `internal/api/credentials.go`, `internal/api/credentials_test.go`. Modify `internal/store/credentials.go` + `internal/store/credentials_test.go` (additive methods — credential CRUD is frontend-owned per spec §10, keep the diff additive), `internal/store/store.go` (two interface lines), `internal/api/api.go` (route lines).

- [ ] **Step 1: Write the failing store test** — append to `internal/store/credentials_test.go`:

```go
func TestListCredentialsByTenantAndDelete(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	put := func(server, tenant string) {
		t.Helper()
		if err := st.PutCredential(ctx, store.Credential{
			Server: server, Tenant: tenant, EncryptedKey: []byte{9, 9},
			InjectHeader: "Authorization", InjectFormat: "Bearer {token}",
			Placeholder: "P", AllowedHosts: []string{"api.example.com"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("github", "7")
	put("slack", "7")
	put("github", "8")

	got, err := st.ListCredentialsByTenant(ctx, "7")
	if err != nil || len(got) != 2 {
		t.Fatalf("list: %v %d", err, len(got))
	}
	for _, c := range got {
		if c.Tenant != "7" {
			t.Fatalf("foreign tenant leaked: %+v", c)
		}
		if c.EncryptedKey != nil {
			t.Fatalf("metadata listing must NOT carry ciphertext: %+v", c)
		}
		if c.InjectHeader != "Authorization" || len(c.AllowedHosts) != 1 {
			t.Fatalf("metadata missing: %+v", c)
		}
	}

	if err := st.DeleteCredential(ctx, "github", "7"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetCredential(ctx, "github", "7"); err == nil {
		t.Fatal("deleted credential still readable")
	}
	if _, err := st.GetCredential(ctx, "github", "8"); err != nil {
		t.Fatalf("other tenant's credential must survive: %v", err)
	}
	// Deleting a missing row is not an error.
	if err := st.DeleteCredential(ctx, "github", "7"); err != nil {
		t.Fatalf("double delete: %v", err)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/store/ -run ListCredentials` → undefined `st.ListCredentialsByTenant`.

- [ ] **Step 3: Implement the store methods** — append to `internal/store/credentials.go`:

```go
// ListCredentialsByTenant returns a tenant's credentials as METADATA ONLY:
// EncryptedKey is deliberately left nil so bulk reads can never ship
// ciphertext to API responses by accident.
func (s *sqliteStore) ListCredentialsByTenant(ctx context.Context, tenant string) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT server,tenant,inject_header,inject_format,placeholder,allowed_hosts
		 FROM credentials WHERE tenant=? ORDER BY server`, tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		var hosts string
		if err := rows.Scan(&c.Server, &c.Tenant, &c.InjectHeader, &c.InjectFormat, &c.Placeholder, &hosts); err != nil {
			return nil, err
		}
		if hosts != "" {
			c.AllowedHosts = strings.Split(hosts, "\n")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteCredential removes a credential by (server, tenant). Missing rows are
// not an error (idempotent).
func (s *sqliteStore) DeleteCredential(ctx context.Context, server, tenant string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE server=? AND tenant=?`, server, tenant)
	return err
}
```

Append to the `Store` interface in `internal/store/store.go`:

```go
	// ListCredentialsByTenant lists a tenant's credentials, metadata only (no ciphertext).
	ListCredentialsByTenant(ctx context.Context, tenant string) ([]Credential, error)
	// DeleteCredential removes a credential by (server, tenant); idempotent.
	DeleteCredential(ctx context.Context, server, tenant string) error
```

Run `go test ./internal/store/` → PASS.

- [ ] **Step 4: Write the failing API test** — `internal/api/credentials_test.go`

```go
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestCredentialPutEncryptsAndScopesToUser(t *testing.T) {
	ctx := context.Background()
	srv, ts, st, _ := newTestAPI(t)
	u, cookie := seedUserSession(t, st, "alice@x", "user")

	code, body := doJSON(t, ts, cookie, "PUT", "/api/credentials/github",
		`{"secret":"ghp_real","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"PLACEHOLDER","allowed_hosts":["api.github.com"]}`)
	if code != http.StatusNoContent {
		t.Fatalf("put: %d %s", code, body)
	}

	// The row is keyed by the OWNING USER ID as decimal string (spec §3).
	cred, err := st.GetCredential(ctx, "github", strconv.FormatInt(u.ID, 10))
	if err != nil {
		t.Fatalf("row missing under user-id tenant: %v", err)
	}
	if string(cred.EncryptedKey) == "ghp_real" {
		t.Fatal("secret stored in plaintext")
	}
	plain, err := srv.Vault.Decrypt(cred.EncryptedKey)
	if err != nil || string(plain) != "ghp_real" {
		t.Fatalf("vault round trip: %v %q", err, plain)
	}
	if cred.InjectHeader != "Authorization" || cred.Placeholder != "PLACEHOLDER" {
		t.Fatalf("metadata: %+v", cred)
	}
}

func TestCredentialListNeverReturnsSecrets(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, alice := seedUserSession(t, st, "alice@x", "user")
	_, bob := seedUserSession(t, st, "bob@x", "user")

	doJSON(t, ts, alice, "PUT", "/api/credentials/github",
		`{"secret":"SUPERSECRET","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"P","allowed_hosts":["api.github.com"]}`)

	code, body := doJSON(t, ts, alice, "GET", "/api/credentials", "")
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	if strings.Contains(string(body), "SUPERSECRET") || strings.Contains(string(body), "encrypted") {
		t.Fatalf("secret material leaked: %s", body)
	}
	var list []struct {
		Server string `json:"server"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 1 || list[0].Server != "github" {
		t.Fatalf("list shape: %v %s", err, body)
	}

	// Bob's view is empty — credentials are per-user.
	_, body = doJSON(t, ts, bob, "GET", "/api/credentials", "")
	var bobList []struct{}
	json.Unmarshal(body, &bobList)
	if len(bobList) != 0 {
		t.Fatalf("cross-user credential leak: %s", body)
	}
}

func TestCredentialValidationAndDelete(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	u, cookie := seedUserSession(t, st, "alice@x", "user")

	// Empty secret → 400.
	if code, _ := doJSON(t, ts, cookie, "PUT", "/api/credentials/github", `{"secret":""}`); code != http.StatusBadRequest {
		t.Fatalf("empty secret: %d", code)
	}

	doJSON(t, ts, cookie, "PUT", "/api/credentials/github",
		`{"secret":"k","inject_header":"Authorization","inject_format":"Bearer {token}","placeholder":"P","allowed_hosts":["api.github.com"]}`)
	if code, _ := doJSON(t, ts, cookie, "DELETE", "/api/credentials/github", ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if _, err := st.GetCredential(ctx, "github", strconv.FormatInt(u.ID, 10)); err == nil {
		t.Fatal("credential not deleted")
	}

	events, _ := st.ListAudit(ctx, 0, 50, 0)
	decisions := map[string]bool{}
	for _, e := range events {
		decisions[e.Decision] = true
	}
	if !decisions["credential_put"] || !decisions["credential_delete"] {
		t.Fatalf("missing credential audit events: %v", decisions)
	}
}
```

- [ ] **Step 5: Run, verify fail** — `go test ./internal/api/ -run Credential` → 404s / undefined handlers.

- [ ] **Step 6: Implement** — `internal/api/credentials.go`

```go
package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// credentialPutBody — PUT /api/credentials/{server}.
//
// TRANSITIONAL FIELDS: inject_header, inject_format, placeholder and
// allowed_hosts populate the credential-row columns only until the registry
// workstream's manifest sourcing lands (spec §5, §10 seam "credentials
// columns"); then the body shrinks to {secret} and these inputs disappear.
type credentialPutBody struct {
	Secret       string   `json:"secret"`
	InjectHeader string   `json:"inject_header"`
	InjectFormat string   `json:"inject_format"`
	Placeholder  string   `json:"placeholder"`
	AllowedHosts []string `json:"allowed_hosts"`
}

type credentialJSON struct {
	Server       string   `json:"server"`
	InjectHeader string   `json:"inject_header"`
	InjectFormat string   `json:"inject_format"`
	Placeholder  string   `json:"placeholder"`
	AllowedHosts []string `json:"allowed_hosts"`
}

// tenantOf is the credential tenant key: the owning user ID as a decimal
// string (spec §1 decision 10 / §3).
func tenantOf(u store.User) string { return strconv.FormatInt(u.ID, 10) }

// handlePutCredential — PUT /api/credentials/{server}: vault-encrypt and
// upsert. Write-only: the plaintext secret is never returned after this.
func (s *Server) handlePutCredential(w http.ResponseWriter, r *http.Request) {
	server := r.PathValue("server")
	var body credentialPutBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Secret == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must include a non-empty secret")
		return
	}
	user, _ := auth.EffectiveUser(r.Context()) // mutations are blocked while impersonating, so effective == real
	enc, err := s.Vault.Encrypt([]byte(body.Secret))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "encrypt secret")
		return
	}
	if err := s.Store.PutCredential(r.Context(), store.Credential{
		Server:       server,
		Tenant:       tenantOf(user),
		EncryptedKey: enc,
		InjectHeader: body.InjectHeader,
		InjectFormat: body.InjectFormat,
		Placeholder:  body.Placeholder,
		AllowedHosts: body.AllowedHosts,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "store credential")
		return
	}
	s.audit(r, "admin", "credential_put", "server="+server, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleListCredentials — GET /api/credentials: metadata only, never the
// secret (the store method strips ciphertext; this handler strips the rest).
func (s *Server) handleListCredentials(w http.ResponseWriter, r *http.Request) {
	user, _ := auth.EffectiveUser(r.Context())
	creds, err := s.Store.ListCredentialsByTenant(r.Context(), tenantOf(user))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "list credentials")
		return
	}
	out := []credentialJSON{}
	for _, c := range creds {
		hosts := c.AllowedHosts
		if hosts == nil {
			hosts = []string{}
		}
		out = append(out, credentialJSON{
			Server: c.Server, InjectHeader: c.InjectHeader,
			InjectFormat: c.InjectFormat, Placeholder: c.Placeholder, AllowedHosts: hosts,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeleteCredential — DELETE /api/credentials/{server}.
func (s *Server) handleDeleteCredential(w http.ResponseWriter, r *http.Request) {
	server := r.PathValue("server")
	user, _ := auth.EffectiveUser(r.Context())
	if err := s.Store.DeleteCredential(r.Context(), server, tenantOf(user)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "delete credential")
		return
	}
	s.audit(r, "admin", "credential_delete", "server="+server, nil)
	w.WriteHeader(http.StatusNoContent)
}
```

In `internal/api/api.go` `Routes()`, add after the profile route lines:

```go
	authed.HandleFunc("GET /api/credentials", s.handleListCredentials)
	authed.HandleFunc("PUT /api/credentials/{server}", s.handlePutCredential)
	authed.HandleFunc("DELETE /api/credentials/{server}", s.handleDeleteCredential)
```

- [ ] **Step 7: Run, verify pass** — `go test ./internal/api/ ./internal/store/` → PASS.

- [ ] **Step 8: Commit** — `git add internal/api/ internal/store/ && git commit -m "feat(api): write-only credential CRUD via vault, tenant = owning user ID"`

---

### Task 12: Registry contract + servers / users / impersonation / audit endpoints

**Files:** Create `internal/registry/installer.go`, `internal/registry/installer_test.go`, `internal/api/servers.go`, `internal/api/users.go`, `internal/api/audit.go`, `internal/api/admin_test.go`. Modify `internal/api/api.go` (Server struct + route lines), `internal/api/api_test.go` (helper line).

- [ ] **Step 1: Create the registry contract** — `internal/registry/installer.go`

```go
// Package registry holds the Installer contract shared between the
// control-plane and manifest/registry workstreams.
//
// OWNERSHIP: this package belongs to the REGISTRY workstream
// (docs/handoffs/manifest-registry.md §6.3). The control plane only consumes
// the Installer interface; the registry workstream REPLACES StubInstaller
// with the real OCI-pulling implementation on its own schedule. Do not add
// control-plane logic here.
package registry

import (
	"context"
	"errors"

	"github.com/gigmcp/gigmcp/internal/store"
)

// ErrNotImplemented is returned by StubInstaller until the real installer
// lands. API handlers surface it as HTTP 501 (install/uninstall) or fall
// back to store.ListServers (list).
var ErrNotImplemented = errors.New("registry: installer not implemented yet")

// Installer is the agreed 3-method contract (identical in both handoff docs).
// ref = name@version | name (latest) | sha256:<digest>; Install is idempotent
// by (name, version) and persists the store.Server row itself.
type Installer interface {
	Install(ctx context.Context, ref string) (store.Server, error)
	Uninstall(ctx context.Context, name string) error
	List(ctx context.Context) ([]store.Server, error)
}

// StubInstaller is the placeholder implementation wired until the registry
// workstream's installer replaces it.
type StubInstaller struct{}

var _ Installer = StubInstaller{}

func (StubInstaller) Install(ctx context.Context, ref string) (store.Server, error) {
	return store.Server{}, ErrNotImplemented
}

func (StubInstaller) Uninstall(ctx context.Context, name string) error {
	return ErrNotImplemented
}

func (StubInstaller) List(ctx context.Context) ([]store.Server, error) {
	return nil, ErrNotImplemented
}
```

And `internal/registry/installer_test.go`:

```go
package registry_test

import (
	"context"
	"errors"
	"testing"

	"github.com/gigmcp/gigmcp/internal/registry"
)

func TestStubReturnsErrNotImplemented(t *testing.T) {
	ctx := context.Background()
	var inst registry.Installer = registry.StubInstaller{}
	if _, err := inst.Install(ctx, "github@1.0.0"); !errors.Is(err, registry.ErrNotImplemented) {
		t.Fatalf("install: %v", err)
	}
	if err := inst.Uninstall(ctx, "github"); !errors.Is(err, registry.ErrNotImplemented) {
		t.Fatalf("uninstall: %v", err)
	}
	if _, err := inst.List(ctx); !errors.Is(err, registry.ErrNotImplemented) {
		t.Fatalf("list: %v", err)
	}
}
```

Run `go test ./internal/registry/` → PASS. Note: the stub test is intentionally written test-first-passing because it asserts a compile-time contract (the interface is satisfied) and that `StubInstaller` returns `ErrNotImplemented`, not behavior that needs a prior failing state. Commit separately so the registry workstream can cherry-pick/inspect it cleanly: `git add internal/registry/ && git commit -m "feat(registry): Installer contract + ErrNotImplemented stub (registry workstream owns this package)"`

- [ ] **Step 2: Write the failing API tests** — `internal/api/admin_test.go`

```go
package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
)

func TestServersListFallsBackToStoreOnStub(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	_, cookie := seedUserSession(t, st, "alice@x", "user")
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}

	code, body := doJSON(t, ts, cookie, "GET", "/api/servers", "")
	if code != http.StatusOK {
		t.Fatalf("list servers: %d %s", code, body)
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 1 || list[0].Name != "echo" {
		t.Fatalf("fallback list: %v %s", err, body)
	}
}

func TestInstallEndpointsAdminOnlyAnd501OnStub(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, user := seedUserSession(t, st, "alice@x", "user")
	_, admin := seedUserSession(t, st, "admin@x", "admin")

	if code, _ := doJSON(t, ts, user, "POST", "/api/servers/install", `{"ref":"github@1.0.0"}`); code != http.StatusForbidden {
		t.Fatalf("non-admin install: %d", code)
	}
	if code, _ := doJSON(t, ts, admin, "POST", "/api/servers/install", `{"ref":"github@1.0.0"}`); code != http.StatusNotImplemented {
		t.Fatalf("stub install must 501: %d", code)
	}
	if code, _ := doJSON(t, ts, admin, "DELETE", "/api/servers/github", ""); code != http.StatusNotImplemented {
		t.Fatalf("stub uninstall must 501: %d", code)
	}
}

func TestUsersListAdminOnly(t *testing.T) {
	_, ts, st, _ := newTestAPI(t)
	_, user := seedUserSession(t, st, "alice@x", "user")
	_, admin := seedUserSession(t, st, "admin@x", "admin")

	if code, _ := doJSON(t, ts, user, "GET", "/api/users", ""); code != http.StatusForbidden {
		t.Fatalf("non-admin users list: %d", code)
	}
	code, body := doJSON(t, ts, admin, "GET", "/api/users", "")
	if code != http.StatusOK {
		t.Fatalf("admin users list: %d %s", code, body)
	}
	var list []struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &list); err != nil || len(list) != 2 {
		t.Fatalf("users: %v %s", err, body)
	}
}

func TestImpersonationLifecycle(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	target, _ := seedUserSession(t, st, "target@x", "user")
	admin, adminCookie := seedUserSession(t, st, "admin@x", "admin")
	_ = admin

	// ttl clamp: 999 minutes requested, ≤ 60 stored.
	code, body := doJSON(t, ts, adminCookie, "POST", "/api/admin/impersonate",
		`{"user_id":`+itoa(target.ID)+`,"ttl_minutes":999}`)
	if code != http.StatusNoContent {
		t.Fatalf("start impersonation: %d %s", code, body)
	}
	sess, err := st.GetSession(ctx, auth.HashToken(adminCookie.Value))
	if err != nil || sess.ImpersonatingUserID == nil || *sess.ImpersonatingUserID != target.ID {
		t.Fatalf("session not stamped: %v %+v", err, sess)
	}
	if sess.ImpersonationExpiresAt.After(time.Now().Add(61 * time.Minute)) {
		t.Fatalf("ttl not clamped to 60m: %v", sess.ImpersonationExpiresAt)
	}

	// While impersonating: /api/me shows both identities; mutations 403.
	code, body = doJSON(t, ts, adminCookie, "GET", "/api/me", "")
	if code != http.StatusOK {
		t.Fatalf("me: %d", code)
	}
	var me struct {
		Impersonating bool `json:"impersonating"`
	}
	json.Unmarshal(body, &me)
	if !me.Impersonating {
		t.Fatalf("me while impersonating: %s", body)
	}
	if code, _ := doJSON(t, ts, adminCookie, "POST", "/api/profiles", `{"name":"X","slug":"xx"}`); code != http.StatusForbidden {
		t.Fatalf("mutation while impersonating must 403: %d", code)
	}

	// Stop.
	if code, _ := doJSON(t, ts, adminCookie, "DELETE", "/api/admin/impersonate", ""); code != http.StatusNoContent {
		t.Fatalf("stop impersonation: %d", code)
	}
	sess, _ = st.GetSession(ctx, auth.HashToken(adminCookie.Value))
	if sess.ImpersonatingUserID != nil {
		t.Fatalf("not cleared: %+v", sess)
	}

	// Both directions audited, attributed to the target (their audit view).
	events, _ := st.ListAudit(ctx, 0, 50, target.ID)
	decisions := map[string]bool{}
	for _, e := range events {
		decisions[e.Decision] = true
	}
	if !decisions["impersonate_start"] || !decisions["impersonate_stop"] {
		t.Fatalf("impersonation audit events missing: %v", decisions)
	}
}

func TestAuditReadScoping(t *testing.T) {
	ctx := context.Background()
	_, ts, st, _ := newTestAPI(t)
	alice, aliceCookie := seedUserSession(t, st, "alice@x", "user")
	bob, _ := seedUserSession(t, st, "bob@x", "user")
	_, adminCookie := seedUserSession(t, st, "admin@x", "admin")

	aid, bid := alice.ID, bob.ID
	st.AppendAudit(ctx, mkEvent(&aid, "a1"))
	st.AppendAudit(ctx, mkEvent(&bid, "b1"))
	st.AppendAudit(ctx, mkEvent(&aid, "a2"))

	// Non-admin is forced to own user_id regardless of query params.
	code, body := doJSON(t, ts, aliceCookie, "GET", "/api/audit?user_id="+itoa(bob.ID), "")
	if code != http.StatusOK {
		t.Fatalf("audit: %d %s", code, body)
	}
	var page struct {
		Events []struct {
			UserID *int64 `json:"user_id"`
			Host   string `json:"host"`
		} `json:"events"`
		NextBefore int64 `json:"next_before"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Events) != 2 {
		t.Fatalf("alice events: %s", body)
	}
	for _, e := range page.Events {
		if e.UserID == nil || *e.UserID != alice.ID {
			t.Fatalf("foreign audit row leaked: %+v", e)
		}
	}

	// Admin sees all, can filter, and pages by keyset.
	code, body = doJSON(t, ts, adminCookie, "GET", "/api/audit?limit=2", "")
	if code != http.StatusOK {
		t.Fatalf("admin audit: %d", code)
	}
	json.Unmarshal(body, &page)
	if len(page.Events) != 2 || page.NextBefore == 0 {
		t.Fatalf("admin page 1: %s", body)
	}
	_, body = doJSON(t, ts, adminCookie, "GET", "/api/audit?limit=2&before="+itoa(page.NextBefore), "")
	json.Unmarshal(body, &page)
	if len(page.Events) != 1 || page.Events[0].Host != "a1" {
		t.Fatalf("admin page 2: %s", body)
	}
}
```

And add this helper to `internal/api/api_test.go` (bottom, after `itoa`), with `"github.com/gigmcp/gigmcp/internal/store"` already imported there:

```go
func mkEvent(uid *int64, host string) store.AuditEvent {
	return store.AuditEvent{Kind: "egress", UserID: uid, Server: "github", Host: host, Decision: "resolved"}
}
```

- [ ] **Step 3: Run, verify fail** — `go test ./internal/api/ -run Servers\|Install\|Users\|Impersonation\|AuditRead` → 404s / undefined handlers.

- [ ] **Step 4: Implement the handlers.**

`internal/api/servers.go`:

```go
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gigmcp/gigmcp/internal/registry"
	"github.com/gigmcp/gigmcp/internal/store"
)

type serverJSON struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

func toServerJSON(srvs []store.Server) []serverJSON {
	out := []serverJSON{}
	for _, s := range srvs {
		out = append(out, serverJSON{ID: s.ID, Name: s.Name})
	}
	return out
}

// handleListServers — GET /api/servers via Installer.List; while the stub is
// wired (or Installer is nil) it falls back to the store's installed-server list.
func (s *Server) handleListServers(w http.ResponseWriter, r *http.Request) {
	var srvs []store.Server
	var err error
	if s.Installer == nil {
		srvs, err = s.Store.ListServers(r.Context())
	} else {
		srvs, err = s.Installer.List(r.Context())
		if errors.Is(err, registry.ErrNotImplemented) {
			srvs, err = s.Store.ListServers(r.Context())
		}
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "list servers")
		return
	}
	writeJSON(w, http.StatusOK, toServerJSON(srvs))
}

// handleInstallServer — POST /api/servers/install {ref} (admin).
func (s *Server) handleInstallServer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ref string `json:"ref"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Ref == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be {ref}")
		return
	}
	srv, err := s.Installer.Install(r.Context(), body.Ref)
	if errors.Is(err, registry.ErrNotImplemented) {
		writeErr(w, http.StatusNotImplemented, "not_implemented", "server install is not available yet (registry workstream)")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, "install_failed", err.Error())
		return
	}
	s.audit(r, "admin", "server_install", "ref="+body.Ref, nil)
	writeJSON(w, http.StatusCreated, serverJSON{ID: srv.ID, Name: srv.Name})
}

// handleUninstallServer — DELETE /api/servers/{name} (admin).
func (s *Server) handleUninstallServer(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := s.Installer.Uninstall(r.Context(), name)
	if errors.Is(err, registry.ErrNotImplemented) {
		writeErr(w, http.StatusNotImplemented, "not_implemented", "server uninstall is not available yet (registry workstream)")
		return
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, "uninstall_failed", err.Error())
		return
	}
	s.audit(r, "admin", "server_uninstall", "name="+name, nil)
	w.WriteHeader(http.StatusNoContent)
}
```

`internal/api/users.go`:

```go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
)

// handleListUsers — GET /api/users (admin): read-only list — roles come from
// the IdP, there is no local user editing in v1.
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.Store.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "list users")
		return
	}
	out := []userJSON{}
	for _, u := range users {
		out = append(out, toUserJSON(u))
	}
	writeJSON(w, http.StatusOK, out)
}

// maxImpersonationTTL bounds view-as sessions (DESIGN #20).
const maxImpersonationTTL = 60 * time.Minute

// handleStartImpersonation — POST /api/admin/impersonate {user_id, ttl_minutes}.
func (s *Server) handleStartImpersonation(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID     int64 `json:"user_id"`
		TTLMinutes int   `json:"ttl_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.UserID == 0 {
		writeErr(w, http.StatusBadRequest, "bad_request", "body must be {user_id, ttl_minutes}")
		return
	}
	real, _ := auth.RealUser(r.Context())
	if body.UserID == real.ID {
		writeErr(w, http.StatusBadRequest, "bad_request", "cannot impersonate yourself")
		return
	}
	target, err := s.Store.GetUser(r.Context(), body.UserID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	ttl := time.Duration(body.TTLMinutes) * time.Minute
	if ttl <= 0 || ttl > maxImpersonationTTL {
		ttl = maxImpersonationTTL
	}
	hash, ok := auth.SessionTokenHash(r.Context())
	if !ok {
		writeErr(w, http.StatusInternalServerError, "internal", "no session in context")
		return
	}
	if err := s.Store.SetImpersonation(r.Context(), hash, target.ID, time.Now().Add(ttl)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "set impersonation")
		return
	}
	// Attributed to the TARGET so it shows in their own audit view (DESIGN #20);
	// the detail names both parties.
	tid := target.ID
	if err := s.Store.AppendAudit(r.Context(), s.impersonationEvent(real.Email, target.Email, "impersonate_start", &tid)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "audit impersonation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleStopImpersonation — DELETE /api/admin/impersonate.
func (s *Server) handleStopImpersonation(w http.ResponseWriter, r *http.Request) {
	hash, ok := auth.SessionTokenHash(r.Context())
	if !ok {
		writeErr(w, http.StatusInternalServerError, "internal", "no session in context")
		return
	}
	if err := s.Store.ClearImpersonation(r.Context(), hash); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "clear impersonation")
		return
	}
	real, _ := auth.RealUser(r.Context())
	effective, _ := auth.EffectiveUser(r.Context())
	var tid *int64
	if effective.ID != real.ID {
		v := effective.ID
		tid = &v
	}
	if err := s.Store.AppendAudit(r.Context(), s.impersonationEvent(real.Email, effective.Email, "impersonate_stop", tid)); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "audit impersonation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// impersonationEvent builds the loud DESIGN-#20 audit row naming both parties.
func (s *Server) impersonationEvent(adminEmail, targetEmail, decision string, targetID *int64) store.AuditEvent {
	return store.AuditEvent{
		Kind: "admin", UserID: targetID, Decision: decision,
		Detail: fmt.Sprintf("admin=%s target=%s", adminEmail, targetEmail),
	}
}
```

`internal/api/audit.go`:

```go
package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
)

type auditEventJSON struct {
	ID        int64     `json:"id"`
	TS        time.Time `json:"ts"`
	Kind      string    `json:"kind"`
	UserID    *int64    `json:"user_id"`
	ProfileID *int64    `json:"profile_id"`
	Server    string    `json:"server"`
	Host      string    `json:"host"`
	Decision  string    `json:"decision"`
	Detail    string    `json:"detail"`
}

// handleListAudit — GET /api/audit?before=&limit=&user_id=
// Keyset pagination newest-first. Non-admins (and admins while impersonating)
// are FORCED to their effective user's events; admins may filter freely.
func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	real, _ := auth.RealUser(r.Context())
	effective, _ := auth.EffectiveUser(r.Context())
	var userFilter int64
	switch {
	case auth.IsImpersonating(r.Context()):
		userFilter = effective.ID // view-as sees the target's audit
	case real.Role != "admin":
		userFilter = real.ID // non-admins only ever see their own
	default:
		userFilter, _ = strconv.ParseInt(q.Get("user_id"), 10, 64) // admin: optional filter
	}
	events, err := s.Store.ListAudit(r.Context(), before, limit, userFilter)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "list audit")
		return
	}
	out := []auditEventJSON{}
	var next int64
	for _, e := range events {
		out = append(out, auditEventJSON{
			ID: e.ID, TS: e.TS, Kind: e.Kind, UserID: e.UserID, ProfileID: e.ProfileID,
			Server: e.Server, Host: e.Host, Decision: e.Decision, Detail: e.Detail,
		})
		next = e.ID
	}
	if len(events) < limit {
		next = 0 // no further pages
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": out, "next_before": next})
}
```

In `internal/api/api.go`: add the `Installer` field to `Server` (with its import):

```go
import (
	"net/http"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/registry"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// Server holds the control-plane dependencies.
type Server struct {
	Store     store.Store
	Vault     *vault.Vault
	Auth      *auth.Authenticator // nil = OIDC unconfigured (auth routes unmounted)
	Installer registry.Installer  // registry workstream's contract; StubInstaller until it lands
	Profiles  ProfileInvalidator
}
```

and add the routes after the credential lines in `Routes()`:

```go
	authed.HandleFunc("GET /api/servers", s.handleListServers)
	authed.Handle("POST /api/servers/install", auth.RequireAdmin(http.HandlerFunc(s.handleInstallServer)))
	authed.Handle("DELETE /api/servers/{name}", auth.RequireAdmin(http.HandlerFunc(s.handleUninstallServer)))
	authed.Handle("GET /api/users", auth.RequireAdmin(http.HandlerFunc(s.handleListUsers)))
	authed.Handle("POST /api/admin/impersonate", auth.RequireAdmin(http.HandlerFunc(s.handleStartImpersonation)))
	authed.Handle("DELETE /api/admin/impersonate", auth.RequireAdmin(http.HandlerFunc(s.handleStopImpersonation)))
	authed.HandleFunc("GET /api/audit", s.handleListAudit)
```

In `internal/api/api_test.go` `newTestAPI`, change the `srv :=` line to wire the stub (add `"github.com/gigmcp/gigmcp/internal/registry"` to imports):

```go
	srv := &api.Server{Store: st, Vault: v, Installer: registry.StubInstaller{}, Profiles: inv}
```

- [ ] **Step 5: Run, verify pass** — `go test ./internal/api/ ./internal/registry/` → PASS.

- [ ] **Step 6: Commit** — `git add internal/api/ && git commit -m "feat(api): servers via Installer contract, admin users list, impersonation, audit read"`

---

### Task 13: spawn.go — tenant parameter (RUNTIME-OWNER SANITY CHECK)

**Files:** Modify `internal/gateway/spawn.go`, `internal/gateway/testharness.go`, `cmd/gateway/main.go`.

> **Coordination note:** this is the one near-boundary runtime edit in this plan (spec §6, handoff §10 Q10). Pure parameter threading — but flag the diff to the runtime owner for a sanity check before or at review time.

This is a pure parameter-threading refactor with no behavioral change: all existing callers pass `"default"`, so the existing test suite (`make test`) fully verifies it — no new failing test is needed or appropriate here.

- [ ] **Step 1: Thread the parameter.** In `internal/gateway/spawn.go`, change the `SpawnEgressBackend` signature by appending a `tenant` parameter:

```go
func SpawnEgressBackend(
	ctx context.Context,
	srv store.Server,
	alloc *netmgr.Allocator,
	reg *proxy.Registry,
	proxyPort int,
	caFile string,
	bootstrapPath string,
	tenant string,
) (*EgressBackend, error) {
```

and update its doc comment to mention: "tenant is the proxy identity bound to the sandbox's source IP — a profile ID (decimal string) for profile-scoped backends, or the literal `\"default\"` for the legacy path." Then replace the hardcoded Bind (spawn.go:327):

```go
	reg.Bind(sub.SandboxIP.String(), proxy.Identity{Server: srv.Name, Tenant: tenant})
```

- [ ] **Step 2: Update the two existing callers** to pass `"default"` (behavior unchanged):

In `cmd/gateway/main.go` `run()`:

```go
		eb, err := gw.SpawnEgressBackend(ctx, srv, alloc, reg, cfg.ProxyPort, caFile, cfg.BootstrapPath, "default")
```

In `internal/gateway/testharness.go` `StartEgressGatewayForTest`:

```go
	eb, err := SpawnEgressBackend(ctx, srv, alloc, reg, proxyPort, caFile, bootstrapBin, "default")
```

- [ ] **Step 3: Verify everything still passes** — `make test` (container; the egress E2E exercises the `"default"` path end-to-end and must stay green). `go vet ./...` clean.

- [ ] **Step 4: Commit** — `git add internal/gateway/ cmd/gateway/ && git commit -m "refactor(gateway): SpawnEgressBackend takes tenant param (callers pass \"default\"; flagged for runtime-owner review)"`

---

### Task 14: Resolver profile join + AuditingResolver decorator

**Files:** Modify `internal/gateway/resolver.go` (SHARED MERGE FILE — registry refactors allowlist sourcing here on their schedule; this edit only changes which tenant key feeds `GetCredential`, keep it minimal). Create `internal/gateway/resolver_test.go`, `internal/gateway/audit_resolver.go`, `internal/gateway/audit_resolver_test.go`.

- [ ] **Step 1: Write the failing resolver test** — `internal/gateway/resolver_test.go` (host-safe)

```go
package gateway_test

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

func newVaultStore(t *testing.T) (*vault.Vault, store.Store) {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return v, st
}

func putCred(t *testing.T, v *vault.Vault, st store.Store, server, tenant, secret string) {
	t.Helper()
	enc, err := v.Encrypt([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutCredential(context.Background(), store.Credential{
		Server: server, Tenant: tenant, EncryptedKey: enc,
		InjectHeader: "Authorization", InjectFormat: "Bearer {token}",
		Placeholder: "PLACEHOLDER", AllowedHosts: []string{"api.example.com"},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestResolverJoinsProfileTenantToOwner(t *testing.T) {
	ctx := context.Background()
	v, st := newVaultStore(t)
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "alice", "a@x", "Alice", "user")
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, "main", "Main", u.ID, "hash")
	if err != nil {
		t.Fatal(err)
	}
	// Credential keyed by the OWNER's user id.
	putCred(t, v, st, "github", strconv.FormatInt(u.ID, 10), "OWNER_SECRET")

	r := &gateway.CredResolver{Store: st, Vault: v}
	cred, err := r.Resolve(proxy.Identity{Server: "github", Tenant: strconv.FormatInt(p.ID, 10)}, "api.example.com")
	if err != nil {
		t.Fatalf("resolve via profile tenant: %v", err)
	}
	if cred.RealSecret != "OWNER_SECRET" {
		t.Fatalf("wrong secret: %q", cred.RealSecret)
	}
}

func TestResolverLiteralTenantStillWorks(t *testing.T) {
	v, st := newVaultStore(t)
	putCred(t, v, st, "echo", "default", "LEGACY_SECRET")

	r := &gateway.CredResolver{Store: st, Vault: v}
	cred, err := r.Resolve(proxy.Identity{Server: "echo", Tenant: "default"}, "api.example.com")
	if err != nil || cred.RealSecret != "LEGACY_SECRET" {
		t.Fatalf("legacy tenant broken: %v %q", err, cred.RealSecret)
	}
	// A numeric tenant that is NOT a profile falls back to the literal key.
	putCred(t, v, st, "echo", "424242", "NUMERIC_LITERAL")
	cred, err = r.Resolve(proxy.Identity{Server: "echo", Tenant: "424242"}, "api.example.com")
	if err != nil || cred.RealSecret != "NUMERIC_LITERAL" {
		t.Fatalf("numeric literal fallback broken: %v %q", err, cred.RealSecret)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/gateway/ -run Resolver` → the profile-tenant test fails ("credential not found": no join yet).

- [ ] **Step 3: Implement the join** — replace `internal/gateway/resolver.go`'s `Resolve` with (whole file shown; only the tenant-resolution lines are new — keep the diff this small for the registry merge):

```go
package gateway

import (
	"context"
	"strconv"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// CredResolver implements proxy.CredentialResolver over the store + vault.
type CredResolver struct {
	Store store.Store
	Vault *vault.Vault
}

// Resolve fetches and decrypts the credential for the identity.
//
// Tenant join (spec §6): if id.Tenant parses as an int64 AND names an
// existing profile, the credential lookup uses the profile OWNER's user id
// (credentials are per-user; one key serves all of that user's profiles).
// Otherwise the tenant is used literally — this keeps the legacy "default"
// tenant working until cutover.
func (c *CredResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	tenant := id.Tenant
	if pid, err := strconv.ParseInt(id.Tenant, 10, 64); err == nil {
		if p, perr := c.Store.GetProfileByID(context.Background(), pid); perr == nil {
			tenant = strconv.FormatInt(p.UserID, 10)
		}
	}
	cred, err := c.Store.GetCredential(context.Background(), id.Server, tenant)
	if err != nil {
		return proxy.Credential{}, err
	}
	secret, err := c.Vault.Decrypt(cred.EncryptedKey)
	if err != nil {
		return proxy.Credential{}, err
	}
	return proxy.Credential{
		RealSecret:   string(secret),
		InjectHeader: cred.InjectHeader,
		InjectFormat: cred.InjectFormat,
		Placeholder:  cred.Placeholder,
		AllowedHosts: cred.AllowedHosts,
	}, nil
}
```

Run `go test ./internal/gateway/ -run Resolver` → PASS.

- [ ] **Step 4: Write the failing AuditingResolver test** — `internal/gateway/audit_resolver_test.go` (host-safe)

```go
package gateway_test

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/proxy"
)

// fixedResolver returns a fixed credential or error for any identity.
type fixedResolver struct {
	cred proxy.Credential
	err  error
}

func (f fixedResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	return f.cred, f.err
}

func TestAuditingResolverRecordsDecisions(t *testing.T) {
	ctx := context.Background()
	_, st := newVaultStore(t)
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "alice", "a@x", "Alice", "user")
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, "main", "Main", u.ID, "hash")
	if err != nil {
		t.Fatal(err)
	}
	tenant := strconv.FormatInt(p.ID, 10)

	inner := &swappableResolver{}
	a := gateway.NewAuditingResolver(inner, st)

	// resolved: exact allowlist match.
	inner.set(proxy.Credential{RealSecret: "k", AllowedHosts: []string{"api.example.com"}}, nil)
	if _, err := a.Resolve(proxy.Identity{Server: "github", Tenant: tenant}, "api.example.com"); err != nil {
		t.Fatal(err)
	}
	// resolved: wildcard suffix match (mirrors proxy semantics).
	inner.set(proxy.Credential{RealSecret: "k", AllowedHosts: []string{"*.example.com"}}, nil)
	if _, err := a.Resolve(proxy.Identity{Server: "github", Tenant: tenant}, "sub.example.com"); err != nil {
		t.Fatal(err)
	}
	// denied: host not in allowlist.
	inner.set(proxy.Credential{RealSecret: "k", AllowedHosts: []string{"only.example.com"}}, nil)
	a.Resolve(proxy.Identity{Server: "github", Tenant: tenant}, "evil.example.org")
	// error: inner resolver failed (passes the error through).
	inner.set(proxy.Credential{}, errors.New("no credential"))
	if _, err := a.Resolve(proxy.Identity{Server: "github", Tenant: "default"}, "x.example.com"); err == nil {
		t.Fatal("inner error must propagate")
	}

	a.Close() // flush the writer

	events, err := st.ListAudit(ctx, 0, 10, 0)
	if err != nil || len(events) != 4 {
		t.Fatalf("events: %v %d", err, len(events))
	}
	// Newest first: error, denied, resolved, resolved.
	wantDecisions := []string{"error", "denied", "resolved", "resolved"}
	for i, want := range wantDecisions {
		if events[i].Kind != "egress" || events[i].Decision != want {
			t.Fatalf("event %d: want %s, got %+v", i, want, events[i])
		}
	}
	// Profile-tenant events carry the join: profile id + owner user id.
	for _, e := range events[1:] { // all but the "default"-tenant error event
		if e.ProfileID == nil || *e.ProfileID != p.ID || e.UserID == nil || *e.UserID != u.ID {
			t.Fatalf("profile/user join missing: %+v", e)
		}
	}
	if events[0].ProfileID != nil || events[0].UserID != nil {
		t.Fatalf("literal-tenant event must not fake a join: %+v", events[0])
	}
}

// swappableResolver lets one test reconfigure the inner result between calls.
type swappableResolver struct {
	cred proxy.Credential
	err  error
}

func (s *swappableResolver) set(c proxy.Credential, err error) { s.cred, s.err = c, err }
func (s *swappableResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	return s.cred, s.err
}

func TestAuditingResolverNeverBlocks(t *testing.T) {
	_, st := newVaultStore(t)
	inner := fixedResolver{cred: proxy.Credential{AllowedHosts: []string{"a.example.com"}}}
	a := gateway.NewAuditingResolver(inner, st)
	a.Close() // closed writer: subsequent Resolves must not panic or block
	for i := 0; i < 10; i++ {
		if _, err := a.Resolve(proxy.Identity{Server: "s", Tenant: "default"}, "a.example.com"); err != nil {
			t.Fatal(err)
		}
	}
	// All 10 events went to the closed/nil sink and must be counted as dropped.
	if got := a.Dropped(); got != 10 {
		t.Fatalf("expected 10 dropped events, got %d", got)
	}
}
```

- [ ] **Step 5: Run, verify fail** — `go test ./internal/gateway/ -run AuditingResolver` → undefined `gateway.NewAuditingResolver`.

- [ ] **Step 6: Implement** — `internal/gateway/audit_resolver.go`

```go
package gateway

import (
	"context"
	"log"
	"strconv"
	"strings"
	"sync"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
)

// auditRecord is the hot-path payload; the DB write (and the profile→owner
// join) happens on the writer goroutine, never on the egress path.
type auditRecord struct {
	server   string
	tenant   string
	host     string
	decision string
	detail   string
}

// AuditingResolver decorates a proxy.CredentialResolver with persistent
// egress auditing (spec §7) — ZERO edits to the no-touch proxy package.
// Writes go through a buffered channel to a single writer goroutine so audit
// can never block the egress hot path; on overflow events are dropped and
// counted, never blocking.
//
// It mirrors the proxy's host-allowlist semantics (exact case-insensitive
// match, or "*.suffix" wildcard suffix match — see internal/proxy/proxy.go
// allowed()) to RECORD the decision the proxy is about to make. This is an
// intentional, documented duplication: the registry workstream's lint CI
// must mirror the same rule.
//
// Lifecycle: Close() flushes pending events and stops the writer; Resolve
// remains safe (and silently drops) after Close.
type AuditingResolver struct {
	Inner proxy.CredentialResolver
	Store store.Store

	ch      chan auditRecord
	done    chan struct{}
	mu      sync.Mutex
	closed  bool
	dropped int64
}

// NewAuditingResolver starts the writer goroutine (buffer: 256 events).
func NewAuditingResolver(inner proxy.CredentialResolver, st store.Store) *AuditingResolver {
	a := &AuditingResolver{
		Inner: inner, Store: st,
		ch:   make(chan auditRecord, 256),
		done: make(chan struct{}),
	}
	go a.writer()
	return a
}

func (a *AuditingResolver) writer() {
	defer close(a.done)
	for rec := range a.ch {
		e := store.AuditEvent{
			Kind: "egress", Server: rec.server, Host: rec.host,
			Decision: rec.decision, Detail: rec.detail,
		}
		// Profile→owner join off the hot path: numeric tenants naming a
		// profile are attributed to (profile, owning user).
		if pid, err := strconv.ParseInt(rec.tenant, 10, 64); err == nil {
			if p, perr := a.Store.GetProfileByID(context.Background(), pid); perr == nil {
				id := pid
				e.ProfileID = &id
				uid := p.UserID
				e.UserID = &uid
			}
		}
		if err := a.Store.AppendAudit(context.Background(), e); err != nil {
			log.Printf("WARN: egress audit write: %v", err)
		}
	}
}

// Resolve delegates to Inner and records the outcome
// (resolved | denied | error). The inner result is returned unchanged.
func (a *AuditingResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	cred, err := a.Inner.Resolve(id, host)
	rec := auditRecord{server: id.Server, tenant: id.Tenant, host: host}
	switch {
	case err != nil:
		rec.decision = "error"
		rec.detail = err.Error()
	case hostAllowed(host, cred.AllowedHosts):
		rec.decision = "resolved"
	default:
		rec.decision = "denied"
		rec.detail = "host not in allowlist"
	}
	a.mu.Lock()
	if !a.closed {
		select {
		case a.ch <- rec:
		default:
			a.dropped++
			log.Printf("WARN: egress audit channel full; dropped %d event(s) total", a.dropped)
		}
	}
	a.mu.Unlock()
	return cred, err
}

// Dropped returns how many events were dropped on overflow.
func (a *AuditingResolver) Dropped() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropped
}

// Close flushes pending events and stops the writer. Idempotent.
func (a *AuditingResolver) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	a.mu.Unlock()
	close(a.ch)
	<-a.done
}

// hostAllowed mirrors internal/proxy's allowed() exactly (see the type
// comment for why the duplication is intentional).
func hostAllowed(host string, list []string) bool {
	for _, h := range list {
		if strings.EqualFold(host, h) {
			return true
		}
		if strings.HasPrefix(h, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(h[1:])) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 7: Run, verify pass** — `go test ./internal/gateway/` (host: Linux-only tests self-skip) → PASS. Then `make test` → full suite green (the resolver join must not disturb the `"default"` egress E2E).

- [ ] **Step 8: Commit** — `git add internal/gateway/ && git commit -m "feat(gateway): profile→owner tenant join in CredResolver + non-blocking AuditingResolver"`

---

### Task 15: ProfileHost — /mcp/p/{slug} lazy runtimes

**Files:** Create `internal/gateway/profilehost.go`, `internal/gateway/profilehost_test.go` (host-safe — fake SpawnFunc over in-memory MCP transports).

- [ ] **Step 1: Write the failing test** — `internal/gateway/profilehost_test.go`. Reuses `connectEchoBackend` (gateway_test.go) and `bearerTransport` (e2e_test.go) — both already live in package `gateway_test` with no build tag.

```go
package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// seedProfile creates a user + profile bundling the given servers and
// returns the profile and its plaintext token.
func seedProfile(t *testing.T, st store.Store, slug string, servers []string) (store.Profile, string) {
	t.Helper()
	ctx := context.Background()
	u, err := st.UpsertUserByOIDC(ctx, "https://idp", "owner-"+slug, slug+"@x", slug, "user")
	if err != nil {
		t.Fatal(err)
	}
	tok, err := auth.NewProfileToken()
	if err != nil {
		t.Fatal(err)
	}
	p, err := st.CreateProfile(ctx, slug, slug, u.ID, auth.HashToken(tok))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileServers(ctx, p.ID, servers); err != nil {
		t.Fatal(err)
	}
	return p, tok
}

// echoSpawner is a fake SpawnFunc backed by in-memory echo servers. It
// records every (server, tenant) spawn and every cleanup invocation.
type echoSpawner struct {
	t        *testing.T
	spawns   []string // "name:tenant"
	cleanups int
}

func (e *echoSpawner) spawn(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
	e.spawns = append(e.spawns, srv.Name+":"+tenant)
	sess := connectEchoBackend(e.t, ctx)
	return &gateway.EgressBackend{Session: sess, Cleanup: func() { e.cleanups++ }}, nil
}

func connectProfileClient(t *testing.T, ctx context.Context, baseURL, slug, token string) *mcp.ClientSession {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "profile-test", Version: "0"}, nil)
	sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   baseURL + "/mcp/p/" + slug,
		HTTPClient: &http.Client{Transport: &bearerTransport{token: token}},
	}, nil)
	if err != nil {
		t.Fatalf("connect profile %s: %v", slug, err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func TestProfileHostAuthAndRouting(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}
	p, tok := seedProfile(t, st, "alpha", []string{"echo"})

	sp := &echoSpawner{t: t}
	host := &gateway.ProfileHost{Store: st, Spawn: sp.spawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	defer ts.Close()

	// Missing / wrong token and wrong slug → 401, and nothing is spawned.
	for _, c := range []struct{ path, token string }{
		{"/mcp/p/alpha", ""},
		{"/mcp/p/alpha", "gig_wrongtoken"},
		{"/mcp/p/nosuch", tok},
	} {
		req, _ := http.NewRequest("POST", ts.URL+c.path, strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%+v: want 401, got %d", c, resp.StatusCode)
		}
	}
	if len(sp.spawns) != 0 {
		t.Fatalf("unauthorized requests must not spawn: %v", sp.spawns)
	}

	// Valid token: lazy spawn with Tenant = profile ID, aggregator serves echo_echo.
	sess := connectProfileClient(t, ctx, ts.URL, "alpha", tok)
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo_echo" {
		t.Fatalf("tools: %+v", tools.Tools)
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "echo_echo", Arguments: map[string]any{"message": "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if text, ok := res.Content[0].(*mcp.TextContent); !ok || text.Text != "echo: hi" {
		t.Fatalf("call: %+v", res.Content[0])
	}
	wantTenant := strconv.FormatInt(p.ID, 10)
	if len(sp.spawns) != 1 || sp.spawns[0] != "echo:"+wantTenant {
		t.Fatalf("spawns: %v (want echo:%s)", sp.spawns, wantTenant)
	}

	// Second session reuses the runtime — no new spawn.
	sess2 := connectProfileClient(t, ctx, ts.URL, "alpha", tok)
	if _, err := sess2.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(sp.spawns) != 1 {
		t.Fatalf("runtime not reused: %v", sp.spawns)
	}
}

func TestProfileHostInvalidateTearsDownAndRespawns(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "ph2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "echo", "/bin/echo-mcp"); err != nil {
		t.Fatal(err)
	}
	p, tok := seedProfile(t, st, "beta", []string{"echo"})

	sp := &echoSpawner{t: t}
	host := &gateway.ProfileHost{Store: st, Spawn: sp.spawn, Version: "test"}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	defer ts.Close()

	sess := connectProfileClient(t, ctx, ts.URL, "beta", tok)
	if _, err := sess.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(sp.spawns) != 1 || sp.cleanups != 0 {
		t.Fatalf("initial: spawns=%v cleanups=%d", sp.spawns, sp.cleanups)
	}

	host.Invalidate(p.ID)
	if sp.cleanups != 1 {
		t.Fatalf("invalidate must run cleanups: %d", sp.cleanups)
	}

	// Next request lazily respawns.
	sess2 := connectProfileClient(t, ctx, ts.URL, "beta", tok)
	if _, err := sess2.ListTools(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(sp.spawns) != 2 {
		t.Fatalf("no respawn after invalidate: %v", sp.spawns)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/gateway/ -run ProfileHost` → undefined `gateway.ProfileHost`.

- [ ] **Step 3: Implement** — `internal/gateway/profilehost.go`

```go
package gateway

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SpawnFunc launches one backend MCP server for a profile runtime. In
// production it closes over SpawnEgressBackend (cmd/gateway wiring); tests
// substitute in-memory backends.
type SpawnFunc func(ctx context.Context, srv store.Server, tenant string) (*EgressBackend, error)

// profileRuntime is one profile's live aggregator + sandbox cleanups.
type profileRuntime struct {
	handler  http.Handler
	cleanups []func()
}

// ProfileHost serves the per-profile MCP endpoints at /mcp/p/{slug}
// (spec §6). Runtimes are LAZY (DESIGN #5): the first authorized request to
// a profile spawns its bundle (each server with Tenant = the profile ID) and
// builds the aggregator; later requests reuse it. Invalidate tears a runtime
// down after bundle edits or deletion (token rotation does NOT invalidate).
//
// Idle reaping is out of v1 scope: the sandbox count is bounded by
// profiles × servers (documented limitation).
type ProfileHost struct {
	Store   store.Store
	Spawn   SpawnFunc
	Version string

	mu       sync.Mutex
	runtimes map[int64]*profileRuntime
}

// Handler routes /mcp/p/{slug}. No method in the pattern: streamable HTTP
// uses POST, GET and DELETE on the same URL.
func (h *ProfileHost) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp/p/{slug}", h.serve)
	return mux
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (h *ProfileHost) serve(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		unauthorized(w)
		return
	}
	// Hash-then-index-lookup needs no constant-time comparison: the attacker
	// does not control the stored hash, and the timing of a B-tree lookup on
	// SHA-256(token) reveals nothing useful about the token bytes (unlike
	// comparing a raw secret, where prefix-match timing leaks).
	p, err := h.Store.GetProfileBySlugAndTokenHash(r.Context(), r.PathValue("slug"), auth.HashToken(tok))
	if err != nil {
		unauthorized(w)
		return
	}
	rt, err := h.getOrCreate(p)
	if err != nil {
		log.Printf("profile %q runtime: %v", p.Slug, err)
		http.Error(w, "backend unavailable", http.StatusBadGateway)
		return
	}
	rt.handler.ServeHTTP(w, r)
}

// getOrCreate returns the profile's runtime, lazily spawning it.
func (h *ProfileHost) getOrCreate(p store.Profile) (*profileRuntime, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.runtimes == nil {
		h.runtimes = map[int64]*profileRuntime{}
	}
	if rt, ok := h.runtimes[p.ID]; ok {
		return rt, nil
	}

	// Sandboxes outlive the triggering request: Background, not r.Context().
	ctx := context.Background()
	names, err := h.Store.GetProfileServers(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	all, err := h.Store.ListServers(ctx)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]store.Server, len(all))
	for _, s := range all {
		byName[s.Name] = s
	}

	tenant := strconv.FormatInt(p.ID, 10)
	var backends []Backend
	var cleanups []func()
	fail := func(err error) (*profileRuntime, error) {
		for _, c := range cleanups {
			c()
		}
		return nil, err
	}
	for _, name := range names {
		srv, ok := byName[name]
		if !ok {
			return fail(fmt.Errorf("profile %d references unknown server %q", p.ID, name))
		}
		eb, err := h.Spawn(ctx, srv, tenant)
		if err != nil {
			return fail(fmt.Errorf("spawn %q: %w", name, err))
		}
		cleanups = append(cleanups, eb.Cleanup)
		backends = append(backends, Backend{Name: srv.Name, Session: eb.Session})
	}
	agg, err := New(ctx, h.Version, backends)
	if err != nil {
		return fail(err)
	}
	rt := &profileRuntime{
		handler:  mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return agg }, nil),
		cleanups: cleanups,
	}
	h.runtimes[p.ID] = rt
	return rt, nil
}

// Invalidate tears down one profile's runtime (bundle change or delete);
// the next request rebuilds it lazily. Implements api.ProfileInvalidator.
func (h *ProfileHost) Invalidate(profileID int64) {
	h.mu.Lock()
	rt := h.runtimes[profileID]
	delete(h.runtimes, profileID)
	h.mu.Unlock()
	if rt == nil {
		return
	}
	for _, c := range rt.cleanups {
		c()
	}
}

// Close tears down all runtimes (gateway shutdown).
func (h *ProfileHost) Close() {
	h.mu.Lock()
	rts := h.runtimes
	h.runtimes = nil
	h.mu.Unlock()
	for _, rt := range rts {
		for _, c := range rt.cleanups {
			c()
		}
	}
}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/gateway/ -run ProfileHost` → PASS (2 tests); `go test ./internal/gateway/` all green on host.

- [ ] **Step 5: Commit** — `git add internal/gateway/ && git commit -m "feat(gateway): ProfileHost — /mcp/p/{slug} with lazy per-profile runtimes, tenant = profile ID"`

---

### Task 16: cmd/gateway wiring — buildMux, dual-path serve, compose env

**Files:** Create `cmd/gateway/serve.go`, `cmd/gateway/serve_test.go`. Modify `cmd/gateway/main.go` (`run()` — SHARED MERGE FILE: keep additions as separate lines/helpers, do not restructure the existing flow), `docker-compose.yml`.

- [ ] **Step 1: Write the failing test** — `cmd/gateway/serve_test.go` (host-safe; exercises mux routing precedence without OIDC)

```go
package main

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	gw "github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/registry"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

func TestBuildMuxRouting(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	kek := make([]byte, 32)
	rand.Read(kek)
	v, _ := vault.New(kek)

	profiles := &gw.ProfileHost{
		Store: st, Version: "test",
		Spawn: func(ctx context.Context, srv store.Server, tenant string) (*gw.EgressBackend, error) {
			t.Fatal("no spawn expected in routing test")
			return nil, nil
		},
	}
	legacy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // sentinel for "legacy handler reached"
	})

	// OIDC unconfigured: authn == nil → /api is NOT mounted.
	mux := buildMux(st, v, nil, registry.StubInstaller{}, profiles, legacy)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	if resp, _ := http.Post(ts.URL+"/mcp", "application/json", strings.NewReader("{}")); resp.StatusCode != http.StatusTeapot {
		t.Fatalf("/mcp must reach legacy handler: %d", resp.StatusCode)
	}
	// "/" catch-all must also reach the legacy handler (backward compat for README-documented URL).
	if resp, _ := http.Get(ts.URL + "/"); resp.StatusCode != http.StatusTeapot {
		t.Fatalf("/ catch-all must reach legacy handler: %d", resp.StatusCode)
	}
	if resp, _ := http.Post(ts.URL+"/mcp/p/some-slug", "application/json", strings.NewReader("{}")); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("/mcp/p/{slug} without token must 401: %d", resp.StatusCode)
	}
	if resp, _ := http.Get(ts.URL + "/api/me"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("/api disabled without OIDC must 404: %d", resp.StatusCode)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./cmd/gateway/` → undefined `buildMux`.

- [ ] **Step 3: Implement** — `cmd/gateway/serve.go`

```go
package main

import (
	"net/http"

	"github.com/gigmcp/gigmcp/internal/api"
	"github.com/gigmcp/gigmcp/internal/auth"
	gw "github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/registry"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// buildMux assembles the single :8080 mux (spec §2):
//
//	/mcp        → legacy aggregator + RequireBearer (transitional until cutover)
//	/mcp/p/     → ProfileHost (per-profile bearer tokens)
//	/api/       → REST control plane (only when OIDC is configured)
//	/           → legacy fallback (same handler as /mcp — preserves the README
//	              documented endpoint "http://localhost:8080" until cutover)
//
// Go 1.22+ ServeMux uses path-specificity: "/mcp/p/" and "/api/" are more
// specific than "/mcp" (exact) which in turn takes precedence over "/" (the
// catch-all). Verify with the serve_test.go routing assertions.
//
// At Task 18 cutover: "/mcp" and "/" mounts are BOTH removed, the canonical
// client endpoint becomes /mcp/p/<slug>, and README.md must be updated
// (see Task 18 Step 3a).
//
// Kept as the one run() helper so the registry workstream's run() additions
// merge cleanly (handoff §6.2).
func buildMux(
	st store.Store,
	v *vault.Vault,
	authn *auth.Authenticator, // nil = OIDC unconfigured, /api unmounted
	installer registry.Installer,
	profiles *gw.ProfileHost,
	legacy http.Handler,
) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/mcp", legacy)
	// "/" is the catch-all fallback: it catches the bare "http://localhost:8080"
	// that the README documents (claude mcp add … http://localhost:8080).
	// /mcp/p/ and /api/ take precedence by ServeMux specificity, so this
	// fallback only fires for paths not otherwise matched, keeping backward
	// compatibility until Task 18 cutover.
	mux.Handle("/", legacy)
	mux.Handle("/mcp/p/", profiles.Handler())
	if authn != nil {
		apiSrv := &api.Server{Store: st, Vault: v, Auth: authn, Installer: installer, Profiles: profiles}
		mux.Handle("/api/", apiSrv.Routes())
	}
	return mux
}
```

- [ ] **Step 4: Run, verify pass** — `go test ./cmd/gateway/` → PASS.

- [ ] **Step 5: Wire `run()`** — in `cmd/gateway/main.go`, three additive changes (add `"github.com/gigmcp/gigmcp/internal/auth"` and `"github.com/gigmcp/gigmcp/internal/registry"` to imports):

(a) Wrap the resolver in the auditing decorator — replace

```go
	resolver := &gw.CredResolver{Store: st, Vault: v}
	egProxy, err := proxy.New(reg, resolver)
```

with

```go
	resolver := gw.NewAuditingResolver(&gw.CredResolver{Store: st, Vault: v}, st)
	// NOTE: defer resolver.Close() (and defer profiles.Close()) are best-effort
	// flushes only — http.ListenAndServe blocks until process death, so these
	// defers only run on a clean return (e.g. early startup error). Audit writes
	// must never rely on Close() being called for correctness.
	defer resolver.Close()
	egProxy, err := proxy.New(reg, resolver)
```

(b) After the existing backend spawn loop (which now passes `"default"` from Task 13) and before the final `return http.ListenAndServe(...)`, build the profile host and (conditionally) the authenticator:

```go
	profiles := &gw.ProfileHost{
		Store:   st,
		Version: version,
		Spawn: func(ctx context.Context, srv store.Server, tenant string) (*gw.EgressBackend, error) {
			return gw.SpawnEgressBackend(ctx, srv, alloc, reg, cfg.ProxyPort, caFile, cfg.BootstrapPath, tenant)
		},
	}
	defer profiles.Close()

	var authn *auth.Authenticator
	if cfg.OIDCEnabled() {
		authn, err = auth.NewAuthenticator(ctx, cfg, st)
		if err != nil {
			return fmt.Errorf("oidc setup: %w", err)
		}
		log.Printf("OIDC configured (issuer %s) — /api control plane enabled", cfg.OIDCIssuer)
	} else {
		log.Printf("WARN: GIG_OIDC_* not configured — /api control plane disabled (legacy /mcp still served)")
	}
```

(c) Replace the final line

```go
	return http.ListenAndServe(cfg.Listen, gw.RequireBearer(cfg.BearerToken, handler))
```

with

```go
	legacy := gw.RequireBearer(cfg.BearerToken, handler)
	return http.ListenAndServe(cfg.Listen, buildMux(st, v, authn, registry.StubInstaller{}, profiles, legacy))
```

- [ ] **Step 6: docker-compose.yml** — add to the gateway service `environment:` block (all optional pass-throughs; the gateway boots without them):

```yaml
      # OIDC control plane (optional — unset disables /api; /mcp keeps working).
      GIG_OIDC_ISSUER: ${GIG_OIDC_ISSUER:-}
      GIG_OIDC_CLIENT_ID: ${GIG_OIDC_CLIENT_ID:-}
      GIG_OIDC_CLIENT_SECRET: ${GIG_OIDC_CLIENT_SECRET:-}
      GIG_OIDC_REDIRECT_URL: ${GIG_OIDC_REDIRECT_URL:-}
      GIG_OIDC_ADMIN_ROLE: ${GIG_OIDC_ADMIN_ROLE:-gigmcp-admin}
      GIG_SESSION_TTL: ${GIG_SESSION_TTL:-168h}
      GIG_PUBLIC_URL: ${GIG_PUBLIC_URL:-http://localhost:8080}
```

- [ ] **Step 7: Full verification** — `make test` → entire suite green (legacy E2E unchanged, new host tests pass in the container too). `go vet ./...` clean.

- [ ] **Step 8: Commit** — `git add cmd/gateway/ docker-compose.yml && git commit -m "feat(gateway): single-mux wiring — legacy /mcp, /mcp/p, conditional /api; audit decorator"`

---

### Task 17: Container E2E — two users, two profiles, two credentials (`make test` only)

**Files:** Create `internal/gateway/profile_e2e_test.go` (`//go:build linux`). Reuses `buildBin` (egress_e2e_test.go) and `bearerTransport` (e2e_test.go) from package `gateway_test`.

- [ ] **Step 1: Write the test** — `internal/gateway/profile_e2e_test.go`

```go
//go:build linux

package gateway_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/netmgr"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/sandbox"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestProfileScopedEgressE2E proves the multi-tenant path end to end:
// (a) profile A's token cannot reach profile B's endpoint,
// (b) egress through each profile injects ITS OWNER's credential,
// (c) audit rows exist for both tenants.
func TestProfileScopedEgressE2E(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("profile E2E requires Linux + NET_ADMIN — run `make test`")
	}
	ctx := context.Background()

	// 1. Upstream TLS server recording Authorization headers.
	var mu sync.Mutex
	var sawAuth []string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()
	upstreamInfo, err := gateway.NewTLSServerInfo(upstream.URL, &upstream.TLS.Certificates[0])
	if err != nil {
		t.Fatal(err)
	}

	// 2. Static binaries.
	fetchBin := buildBin(t, "cmd/fetch-mcp")
	bootstrapBin := buildBin(t, "cmd/bootstrap")

	// 3. Vault + store.
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "pe2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.EnsureServer(ctx, "fetch", fetchBin); err != nil {
		t.Fatal(err)
	}

	// 4. Two users with DIFFERENT credentials (tenant = user ID), one profile each.
	seed := func(sub, slug, secret string) (store.Profile, string) {
		t.Helper()
		u, err := st.UpsertUserByOIDC(ctx, "https://idp", sub, sub+"@x", sub, "user")
		if err != nil {
			t.Fatal(err)
		}
		enc, err := v.Encrypt([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.PutCredential(ctx, store.Credential{
			Server: "fetch", Tenant: strconv.FormatInt(u.ID, 10), EncryptedKey: enc,
			InjectHeader: "Authorization", InjectFormat: "Bearer {token}",
			Placeholder: "PLACEHOLDER", AllowedHosts: []string{upstreamInfo.Host},
		}); err != nil {
			t.Fatal(err)
		}
		tok, err := auth.NewProfileToken()
		if err != nil {
			t.Fatal(err)
		}
		p, err := st.CreateProfile(ctx, slug, slug, u.ID, auth.HashToken(tok))
		if err != nil {
			t.Fatal(err)
		}
		if err := st.SetProfileServers(ctx, p.ID, []string{"fetch"}); err != nil {
			t.Fatal(err)
		}
		return p, tok
	}
	profA, tokA := seed("alice", "alice-main", "REALKEY_A")
	profB, tokB := seed("bob", "bob-main", "REALKEY_B")

	// 5. Proxy with the auditing resolver.
	reg := proxy.NewRegistry()
	auditing := gateway.NewAuditingResolver(&gateway.CredResolver{Store: st, Vault: v}, st)
	p, err := proxy.New(reg, auditing)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(upstreamInfo.Certificate)
	p.SetUpstreamRoots(pool)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	proxyPort := ln.Addr().(*net.TCPAddr).Port
	p.SetAddr(ln.Addr().String())
	go p.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, p.CACertPEM(), 0644); err != nil {
		t.Fatal(err)
	}
	alloc := netmgr.NewAllocator("10.88.0.0/16")

	// 6. ProfileHost with the REAL spawner — Tenant = profile ID.
	host := &gateway.ProfileHost{
		Store: st, Version: "e2e",
		Spawn: func(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
			return gateway.SpawnEgressBackend(ctx, srv, alloc, reg, proxyPort, caFile, bootstrapBin, tenant)
		},
	}
	t.Cleanup(host.Close)
	ts := httptest.NewServer(host.Handler())
	defer ts.Close()

	// (a) Cross-profile token rejection: token A against B's endpoint → 401.
	req, _ := http.NewRequest("POST", ts.URL+"/mcp/p/bob-main", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tokA)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token A on profile B must 401, got %d", resp.StatusCode)
	}

	// (b) Each profile injects its OWNER's key.
	callFetch := func(slug, token string) string {
		t.Helper()
		c := mcp.NewClient(&mcp.Implementation{Name: "pe2e", Version: "0"}, nil)
		sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
			Endpoint:   ts.URL + "/mcp/p/" + slug,
			HTTPClient: &http.Client{Transport: &bearerTransport{token: token}},
		}, nil)
		if err != nil {
			t.Fatalf("connect %s: %v", slug, err)
		}
		defer sess.Close()
		res, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      "fetch_fetch", // aggregator namespaces fetch's "fetch" tool
			Arguments: map[string]any{"url": upstream.URL},
		})
		if err != nil {
			t.Fatalf("call fetch via %s: %v", slug, err)
		}
		text, ok := res.Content[0].(*mcp.TextContent)
		if !ok {
			t.Fatalf("content: %+v", res.Content[0])
		}
		return text.Text
	}

	lastAuth := func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(sawAuth) == 0 {
			return ""
		}
		return sawAuth[len(sawAuth)-1]
	}

	if out := callFetch("alice-main", tokA); !strings.Contains(out, "upstream-ok") {
		t.Fatalf("fetch via A failed: %q", out)
	}
	if got := lastAuth(); got != "Bearer REALKEY_A" {
		t.Fatalf("profile A egress injected %q, want Bearer REALKEY_A", got)
	}
	if out := callFetch("bob-main", tokB); !strings.Contains(out, "upstream-ok") {
		t.Fatalf("fetch via B failed: %q", out)
	}
	if got := lastAuth(); got != "Bearer REALKEY_B" {
		t.Fatalf("profile B egress injected %q, want Bearer REALKEY_B", got)
	}

	// (c) Audit rows exist for both tenants. Close the host FIRST so no
	// late Resolve races the auditor shutdown, then flush.
	host.Close()
	auditing.Close()
	events, err := st.ListAudit(ctx, 0, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	var gotA, gotB bool
	for _, e := range events {
		if e.Kind != "egress" || e.Decision != "resolved" || e.ProfileID == nil {
			continue
		}
		if *e.ProfileID == profA.ID {
			gotA = true
		}
		if *e.ProfileID == profB.ID {
			gotB = true
		}
	}
	if !gotA || !gotB {
		t.Fatalf("missing egress audit rows: A=%v B=%v (%d events)", gotA, gotB, len(events))
	}
}
```

- [ ] **Step 2: Run** — `make test` → `TestProfileScopedEgressE2E` passes alongside the legacy `TestEgressEndToEnd`; full suite green. (`make test-local` on macOS: the file does not even compile in, `//go:build linux`.)

- [ ] **Step 3: Commit** — `git add internal/gateway/profile_e2e_test.go && git commit -m "test(gateway): profile-scoped egress E2E — token isolation, per-owner injection, audit"`

---

### Task 18: Cutover — retire RequireBearer + the spawn-all loop (GATED)

**Files:** Modify `internal/gateway/e2e_test.go`, `internal/gateway/testharness.go`, `cmd/gateway/main.go`, `cmd/gateway/serve.go`, `cmd/gateway/serve_test.go`, `internal/config/config.go`, `internal/config/config_test.go`, `docker-compose.yml`. Delete `internal/gateway/auth.go`, `internal/gateway/auth_test.go`.

> **GATE — DO NOT START THIS TASK UNILATERALLY.** Two preconditions, both confirmed with the human first:
> 1. **Ask the human for explicit go-ahead** (this removes the legacy auth path — operators must have OIDC + a profile before upgrading).
> 2. **Coordinate with the registry workstream**: they merge into `resolver.go`, `store.go`, `sqlite.go` and `run()`; agree on sequencing so this cutover doesn't land mid-flight under their changes.

- [ ] **Step 0: Confirm the gate.** Ask the human; record their answer in the commit message body. Check `git log` for registry-workstream activity on the shared files and resolve sequencing with them.

- [ ] **Step 1: Migrate `e2e_test.go` to a seeded profile + token.** Replace the `RequireBearer` block (lines ~61–63) in `TestEndToEnd`:

```go
	handler := gateway.RequireBearer("sekrit",
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return gw }, nil))
	ts := httptest.NewServer(handler)
	defer ts.Close()
```

with a ProfileHost fed by the already-spawned sandboxed backend (add imports `"path/filepath"`, `"github.com/gigmcp/gigmcp/internal/auth"`, `"github.com/gigmcp/gigmcp/internal/store"`):

```go
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.EnsureServer(ctx, "echo", bin); err != nil {
		t.Fatal(err)
	}
	owner, err := st.UpsertUserByOIDC(ctx, "https://idp", "e2e", "e2e@x", "E2E", "user")
	if err != nil {
		t.Fatal(err)
	}
	profileToken, err := auth.NewProfileToken()
	if err != nil {
		t.Fatal(err)
	}
	prof, err := st.CreateProfile(ctx, "e2e", "E2E", owner.ID, auth.HashToken(profileToken))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetProfileServers(ctx, prof.ID, []string{"echo"}); err != nil {
		t.Fatal(err)
	}
	host := &gateway.ProfileHost{
		Store: st, Version: "e2e",
		Spawn: func(ctx context.Context, srv store.Server, tenant string) (*gateway.EgressBackend, error) {
			// The sandboxed backend was already started above; hand its session over.
			return &gateway.EgressBackend{Session: backendSess, Cleanup: func() {}}, nil
		},
	}
	defer host.Close()
	ts := httptest.NewServer(host.Handler())
	defer ts.Close()
```

Then update the two client touchpoints: the unauthenticated POST goes to `ts.URL+"/mcp/p/e2e"` (still expects 401), and the MCP client connects to `Endpoint: ts.URL + "/mcp/p/e2e"` with `&bearerTransport{token: profileToken}`. Remove the now-unused `gw, err := gateway.New(...)` aggregator block (the ProfileHost builds its own) and delete `defer backendSess.Close()` double-closing if the cleanup path now owns it (keep the `defer`; the no-op Cleanup avoids a double close).

- [ ] **Step 2: Migrate `testharness.go` to a seeded profile tenant.** In `StartEgressGatewayForTest`: after the existing `EnsureServer` call, seed an owner + profile and use the profile ID as tenant — replace the credential's `Tenant: "default"` and the spawn call:

```go
	owner, err := st.UpsertUserByOIDC(ctx, "https://idp", "harness", "harness@x", "Harness", "user")
	if err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	prof, err := st.CreateProfile(ctx, "harness", "Harness", owner.ID, "unused-hash")
	if err != nil {
		t.Fatalf("seed profile: %v", err)
	}
```

credential: `Tenant: strconv.FormatInt(owner.ID, 10)` (add `"strconv"` import); spawn: `SpawnEgressBackend(ctx, srv, alloc, reg, proxyPort, caFile, bootstrapBin, strconv.FormatInt(prof.ID, 10))`. This proves the egress E2E through the profile→owner resolver join instead of the literal tenant.

- [ ] **Step 3: Delete the legacy auth path.**

```bash
git rm internal/gateway/auth.go internal/gateway/auth_test.go
```

In `internal/config/config.go`: delete the `BearerToken` field, its `FromEnv` assignment, and the `if cfg.BearerToken == "" { ... }` validation. In `internal/config/config_test.go` `setBaseEnv`, drop the `t.Setenv("GIG_BEARER_TOKEN", "tok")` line. In `docker-compose.yml`, delete the `GIG_BEARER_TOKEN:` line.

- [ ] **Step 3a: Delete dead demo credential code.**

In `cmd/gateway/main.go`: delete `seedDemoCredential` and any call to it (introduced pre-cutover to seed the default bearer-token tenant for development). In `docker-compose.yml`: delete the `GIG_DEMO_TOKEN:` and `GIG_DEMO_ALLOW:` environment variable lines. In `internal/config/config.go`: delete the `DemoToken` and `DemoAllow` fields and their `FromEnv` assignments. Run `go build ./cmd/gateway/` to confirm no compile errors before proceeding.

- [ ] **Step 3b: Update README.md.**

  1. Remove `GIG_BEARER_TOKEN` from the environment variable table (approximately lines 19 and 28 of README.md).
  2. Change the example client command from `claude mcp add … http://localhost:8080` to `claude mcp add … http://localhost:8080/mcp/p/<slug>` (approximately line 51), noting that `<slug>` is the profile slug and the bearer token is the profile token shown at `POST /api/profiles`.
  3. Run `grep -rn "GIG_BEARER_TOKEN\|localhost:8080\"" README.md` to confirm no stale references remain.

- [ ] **Step 4: Retire the startup spawn-all loop in `run()`.** Delete from `cmd/gateway/main.go`: the `servers, err := st.ListServers(ctx)` block, the `var backends ...; for _, srv := range servers { SpawnEgressBackend ... }` loop with its `cleanups` defer, the `gwServer, err := gw.New(...)` + `handler := mcp.NewStreamableHTTPHandler(...)` lines, and the `legacy := gw.RequireBearer(...)` line. Sandboxes are now exclusively lazy-spawned by the ProfileHost. Drop the `legacy http.Handler` parameter from `buildMux` (and its `mux.Handle("/mcp", legacy)` line) in `cmd/gateway/serve.go`; the final wiring becomes:

```go
	return http.ListenAndServe(cfg.Listen, buildMux(st, v, authn, registry.StubInstaller{}, profiles))
```

Remove the now-unused `mcp` import from `main.go` if nothing else uses it. Update `cmd/gateway/serve_test.go`: drop the `legacy` handler and the `/mcp` teapot assertion; assert `/mcp` now 404s and `/mcp/p/{slug}` still 401s.

- [ ] **Step 5: Verify** — `make test` → full suite green: migrated `TestEndToEnd` (profile token), `TestEgressEndToEnd` (profile tenant via harness), `TestProfileScopedEgressE2E`, and zero references to `RequireBearer`/`GIG_BEARER_TOKEN`/`seedDemoCredential` remain (`grep -rn "RequireBearer\|GIG_BEARER_TOKEN\|seedDemoCredential\|GIG_DEMO_TOKEN\|GIG_DEMO_ALLOW" --include="*.go" --include="*.yml" --include="*.md" .` → empty).

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat!: cutover to profile tokens — remove RequireBearer, GIG_BEARER_TOKEN, startup spawn-all loop"` (include the human's go-ahead note in the body).

---

## Done criteria

- `make test` green end-to-end, including `TestProfileScopedEgressE2E`: profile A's token cannot reach profile B's endpoint; egress through each profile injects that owner's credential (REALKEY_A vs REALKEY_B); egress audit rows exist for both tenants.
- A human can: `docker compose -f docker-compose.dev.yml up` Zitadel → log in via `/api/auth/login` → land with a `gig_session` cookie and a JIT user row whose role reflects the `gigmcp-admin` claim → create a profile via `POST /api/profiles` (token shown once) → store a credential (vault-encrypted, tenant = own user ID) → point an MCP client at `/mcp/p/<slug>` → read the audit trail at `GET /api/audit`.
- Impersonation is view-as only: GETs resolve against the target, every mutation 403s except stop, both directions audited and visible to the target.
- Secrets never leave: credential GET returns metadata only; profile tokens and session tokens exist at rest only as SHA-256.
- The registry workstream can replace `registry.StubInstaller` without touching any control-plane file; install endpoints flip from 501 to live behavior automatically.
- After Task 18 (gated): no `RequireBearer`, no `GIG_BEARER_TOKEN`, no startup spawn-all loop; all MCP access is per-profile.

## Explicitly out of scope (second plan / other workstream)

Next.js dashboard (`web/`, spec §8) and the compose `web` service · catalog browse + real install (registry workstream replaces the stub) · manifest-driven allowlists (registry's `resolver.go` refactor; the credential-row columns stay transitional) · RP-initiated Zitadel logout · idle reaping of profile runtimes (bounded by profiles × servers, documented) · Postgres driver · meta-tools mode (schema flag only) · local passwords / invitations (dropped per spec §1).

## Coordination flags (raise with the other workstream / human, do not just merge)

1. **Task 13** spawn.go tenant param → runtime-owner sanity check (handoff §10 Q10).
2. **Task 14** resolver.go join → sequence against the registry's allowlist-sourcing refactor (spec §10: whoever lands second rebases over the first; both edits are small).
3. **Task 18** is human-gated and registry-coordinated (see its gate block).
4. `store.go`/`sqlite.go`/`run()` merges are expected and small — keep every addition append-only.
