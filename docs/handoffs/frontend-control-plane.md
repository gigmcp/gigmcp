# Handoff: Frontend + Control-Plane Workstream

> **Audience:** the engineer/agent building gigemcp's control plane (REST API, auth,
> multi-user data model, profile-scoped MCP endpoints) and the Next.js dashboard.
> You work **in parallel** with a separate agent building the **manifest/registry**
> workstream. This doc is the contract that keeps you two from colliding.
>
> Read `DESIGN.md` (root) end-to-end first — this doc assumes it. Written 2026-06-06
> against the repo at commit `6a1f8d0`.

---

> **Parallel workstream notice:** This doc covers the **frontend / control-plane**
> workstream. The companion workstream is documented in
> [docs/handoffs/manifest-registry.md](manifest-registry.md). The two workstreams
> run in parallel sharing three coordination seams: `store.Store` interface (additive,
> separate files), `cmd/gateway/main.go run()` wiring (additive helpers), and the
> proxy resolver allowlist(from manifest)+secret(from vault) split. ONE cross-boundary
> item needs joint agreement before either goes deep: the sandbox currently mounts a
> single binary at `/app/server`, but OCI images (Node/Python) are full rootfses, so
> real images require a coordinated extension to the otherwise-stable `internal/sandbox`
> — prove the pipeline with static-binary images first, then agree the rootfs-mount
> extension.

---

## 1. Mission

gigemcp is an AGPL, security-first MCP gateway: it runs untrusted community MCP
servers in kernel-enforced sandboxes and injects credentials at the network
boundary so a compromised tool can never read your keys (the Composio
alternative that can run *anyone's* server). The secure **runtime** already
works end-to-end. **Your job is the human-facing half**: turn the
single-static-token, single-tenant skeleton into a real multi-user product — a Go
REST control plane (auth, users, profiles, credentials, audit), Go-owned
authentication (local + OIDC), a multi-user data model, profile-scoped MCP
endpoints with per-profile tokens, and a Composio-style Next.js dashboard that
talks only to that API. The registry agent makes "install a community server"
real; you make "log in, create a profile, add credentials, point Claude Code at
it, watch the audit log" real.

---

## 2. Current repo state (verified against the tree)

**DONE and working** (do not rebuild):

- **MCP aggregator** behind a bearer-authed streamable-HTTP endpoint on `:8080`.
  `internal/gateway/gateway.go` (`New`) connects to backends and re-exposes each
  backend tool as `<backend>_<tool>`. `cmd/gateway/main.go` `run()` is the wiring.
- **Single static bearer token** auth: `internal/gateway/auth.go` `RequireBearer`
  — one token from `GIGE_BEARER_TOKEN`, constant-time compared. This is the ONLY
  auth that exists today.
- **SQLite store** (`internal/store`): `Store` interface in `store.go`, sqlite
  impl in `sqlite.go`, credentials in `credentials.go`. Pure-Go driver
  (`modernc.org/sqlite`), `CGO_ENABLED=0`. Schema is created additively in
  `OpenSQLite` (runs `schema` then `credSchema`). **No Postgres driver yet** (the
  interface is designed for it per decision #14, but only sqlite is implemented).
- **Egress proxy + encrypted vault** (`internal/proxy`, `internal/vault`,
  `internal/netmgr`, `internal/seccomp`, `cmd/bootstrap`): per-sandbox netns,
  veth/IP identity, MITM CONNECT proxy that resolves `source-IP → (server,tenant)`,
  checks an allowlist, and swaps a placeholder for the vault-decrypted real key.
  Untrusted servers run uid 65534, zero caps, route-isolated. Scoped seccomp-BPF
  filter closes the nested-userns escape. Gateway needs `--cap-add NET_ADMIN`.
- **Sandbox spawn** (`internal/gateway/spawn.go` `SpawnEgressBackend`): the full
  bwrap + uid/gid-map + veth-injection + handshake dance.

**ABSENT (your scope, plus registry's):**

- No REST API of any kind. No `internal/api`, no `internal/auth`.
- No users, no sessions, no login, no OIDC, no RBAC, no impersonation.
- No profiles. The aggregator serves ONE implicit profile; `Tenant` is hardcoded
  to the literal string `"default"` (see `spawn.go` `reg.Bind(... Tenant: "default")`
  and `main.go` `seedDemoCredential` `Tenant: "default"`).
- No per-profile tokens — just the one static bearer.
- No dashboard, no `web/` directory, no Next.js anywhere.
- The `Server` struct (`store.go`) has only `ID, Name, Binary` — no manifest
  fields, no `user_id`. The registry agent will extend it.

**Key facts about how it runs:** Linux-only (bwrap/netns don't exist on macOS).
Tests run in a Linux container via `make test`; `make test-local` runs the
host-safe subset (sandbox tests self-skip on macOS via `sandbox.Available()`).
The gateway needs `--cap-add NET_ADMIN` + `seccomp/apparmor/systempaths=unconfined`
to run egress (see Makefile + docker-compose.yml).

---

## 3. Relevant DESIGN decisions (quote # + gist)

- **#11 Client surface:** one streamable-HTTP MCP endpoint **per profile**
  (`/mcp/p/<profile>`), **per-profile bearer tokens**. A profile = a named bundle
  of servers exposing a curated tool subset (`default: true/false` in manifests).
  Meta-tools mode is a per-profile opt-in flag. **You own profiles and the
  routing/token change.**
- **#14 Storage:** repository interface, SQLite (zero-config default) + Postgres
  drivers; **no Postgres-only features in core**. Add tables additively.
- **#15 Vault:** envelope encryption (XChaCha20-Poly1305, per-secret DEK wrapped
  by a master KEK from `GIGE_MASTER_KEY`). Already built — you **consume**
  `internal/vault` for credential CRUD; you never touch its internals.
- **#17 Frontend:** **Next.js** dashboard as a **pure frontend in a separate
  `web` container**, modeled visually on Composio's dashboard. Astro reserved for
  future marketing/marketplace — not your concern.
- **#18 Auth:** the Go gateway is the **sole auth authority**. Local email+password
  **plus** a generic **OIDC client** (`coreos/go-oidc`) covering social login
  (Google/GitHub) and enterprise SSO (Okta/Entra/Authentik/Authelia) with one
  config block. Go issues an **httpOnly session** after the OIDC callback; Next.js
  forwards it. **No Auth.js session ownership** — Next never mints or validates
  sessions itself.
- **#19 Multi-user (v1):** `user_id` on every table; roles `admin`/`user`; OIDC +
  local login; admin user management; invitations.
- **#20 Impersonation (config-only, option B):** admin sees the user's view
  (profiles, server status, logs) but **cannot execute tools or touch secrets**.
  Time-boxed, banner-visible, emits a loud audit event the impersonated user also
  sees. Full impersonation is post-v1, off by default.

---

## 4. What you own — concrete deliverables

### 4.1 Go REST API (new `internal/api` package)
JSON endpoints the dashboard calls. Suggested surface (firm up in brainstorming):

- **Session/auth:** `POST /api/login` (local), OIDC start + callback (see 4.2),
  `POST /api/logout`, `GET /api/me` (current user + role).
- **Users (admin only):** CRUD + invitations (`POST /api/users/invite`, accept
  flow). RBAC-gated.
- **Profiles:** CRUD. A profile = named bundle of servers → maps to
  `/mcp/p/<profile>` + a per-profile bearer token (decision #11). Endpoints to
  add/remove servers from a profile and to rotate/reveal-once the profile token.
- **Credentials:** CRUD that **encrypt via `internal/vault` and persist via
  `store.PutCredential`** (the real secret goes through `vault.Encrypt`; the row
  stores ciphertext + injection metadata). Never return the plaintext secret back
  to the client after creation.
- **Audit-log read:** paginated read of the per-request audit events the proxy
  produces (proxy currently logs via `log.Printf`; persisting them to a table is
  part of your work — see open questions).
- **Servers list/install/uninstall:** list available/installed servers;
  install/uninstall **delegate to the registry workstream's `Installer`**
  (section 6). You implement the HTTP handler and persistence linkage; you do NOT
  implement install.

Wrap handlers in middleware for session auth + RBAC + (later) impersonation
context. Keep the API server as its own goroutine in `run()` (section 6).

### 4.2 Auth (new `internal/auth`)
Go is the sole authority (decision #18).

- Local email+password (hash with a strong KDF — bcrypt/argon2id; decide in
  brainstorming).
- Generic OIDC client via `coreos/go-oidc` + `golang.org/x/oauth2` (oauth2 is
  already an indirect dep — see go.mod; go-oidc is **not yet** a dependency, you'll
  add it). One config block drives social + enterprise SSO.
- On successful login/OIDC callback, issue an **httpOnly session cookie** (or a
  JWT in an httpOnly cookie — open question #10). Next.js forwards the cookie; it
  never owns the session.
- RBAC: roles `admin` / `user`, enforced in API middleware.
- **Config-only impersonation (decision #20):** an admin can enter a time-boxed,
  banner-visible, audited "view-as" mode that grants read of the target user's
  profiles/status/logs but **blocks tool execution and any secret access**. The
  impersonated user sees the audit event too.

### 4.3 Multi-user data model (decision #19)
Extend the store additively: `users`, `profiles`, `sessions` tables (+ profile↔
server join, invitations, and an `audit` table if you persist audit). Add
`user_id` to credential ownership. **Protocol:** add your methods to the `Store`
interface and put implementations in **new files** — e.g. `internal/store/users.go`,
`profiles.go`, `sessions.go` — mirroring the `credentials.go` pattern. Add each
new `CREATE TABLE IF NOT EXISTS` block and run it in `OpenSQLite` additively
(see section 6 for the merge protocol on that one shared file).

### 4.4 Profile-scoped MCP endpoints
Replace the single static `RequireBearer` with **per-profile** routing +
per-profile bearer tokens: `/mcp/p/<profile>` authenticated by that profile's
token, serving only that profile's bundle of servers, with `Tenant` resolved from
the profile (not the hardcoded `"default"`). **Do this without breaking the
existing egress E2E / skeleton tests during the transition** — keep
`RequireBearer` + the implicit single profile working until profile tokens fully
replace it (decision: dual-path then cut over).

### 4.5 Next.js dashboard (`web/`, separate container — decision #17)
Pure frontend, Composio-style UI, talks **only** to the Go REST API. **No Auth.js
session ownership.** Screens: servers (browse/install/uninstall), profiles
(create, bundle servers, copy token), credentials (add/edit, BYO-OAuth flow
later), users/admin (manage + invite + impersonate), audit log. Add a `web`
service to `docker-compose.yml`.

---

## 5. What you must NOT touch (and why)

- `internal/sandbox`, `internal/netmgr`, `internal/proxy`, `internal/vault`,
  `internal/seccomp`, `cmd/bootstrap` — **STABLE**. These are the security
  boundary; they were proven by spikes and an E2E suite. You **consume** vault and
  the proxy resolver contract; you don't modify them. (One coordinated exception:
  the proxy's `CredentialResolver` semantics around allowlist sourcing — section
  6 — but that's a contract discussion, not a free edit.) **Cross-boundary finding:**
  the sandbox currently mounts a single binary, but OCI images for Node/Python are
  full rootfses — a coordinated extension to `internal/sandbox` is needed (registry
  doc §6.E). Start with static-binary images to avoid touching sandbox initially.
- The **manifest schema**, the `gigemcp-registry` repo, OCI image pulling, and the
  actual "install a server" implementation — **owned by the registry workstream.**
  Your server-install API endpoint **calls** their `Installer` interface; it does
  not implement install.
- The **`Server` struct's manifest fields** — registry owns adding those. You
  reference `Server` **read-only** (name, binary, and whatever fields registry
  adds). Don't add fields to `Server` yourself; coordinate if you think you need
  one.

---

## 6. Shared seams & coordination protocol (the contract)

### 6.1 `store.Store` interface — both workstreams extend it
Current interface (`internal/store/store.go`): `EnsureServer`, `ListServers`,
`PutCredential`, `GetCredential`, `Close`.

**Protocol:**
- Each workstream adds its own methods to the `Store` interface **and** puts the
  impl in a **new file** (the `credentials.go` pattern). You add user/profile/
  session methods → `internal/store/users.go`, `profiles.go`, `sessions.go`.
  Registry adds server/manifest methods in its own files.
- Each defines its own `const xSchema = ...` and the impl file owns its tables.
- The one genuinely shared line is **`OpenSQLite`**, which runs each schema block.
  Keep additions additive (`CREATE TABLE IF NOT EXISTS`) and append your
  `db.ExecContext(ctx, xSchema)` calls; expect a small merge here and keep diffs
  minimal.
- The `Server` struct: **registry owns its manifest fields**; you reference it
  read-only. If you need a new `Server` field, ask the registry agent — don't both
  edit the struct.

### 6.2 `cmd/gateway/main.go` `run()` — both extend the wiring
Today `run()` does: config → vault → store → seed echo → build proxy → spawn
backends → build aggregator → `http.ListenAndServe(... RequireBearer ...)`.

**Protocol:** keep your additions in **separate helper functions/files** (e.g. a
`startAPIServer(...)` helper, possibly in a new `cmd/gateway/api.go` or wired from
`internal/api`). `run()` gains an **API server goroutine** alongside the existing
proxy + MCP listeners. The registry agent also extends `run()` (install wiring).
**Expect a merge touchpoint here** — keep changes small and additive, prefer new
helpers over rewriting the existing linear flow.

### 6.3 Server install operation — the `Installer` interface (you CONSUME, registry IMPLEMENTS)
You need an interface the registry workstream provides and your install/uninstall
API endpoints call. **This is the agreed shared contract with manifest-registry.md:
the registry workstream IMPLEMENTS it, the frontend CONSUMES it.**

```go
type Installer interface {
    Install(ctx context.Context, ref string) (store.Server, error)  // ref = name@version | name(latest) | sha256:<digest>; idempotent by (name,version)
    Uninstall(ctx context.Context, name string) error
    List(ctx context.Context) ([]store.Server, error)
}
```

Notes for the agreement with the registry agent:
- `Install` returns the **`store.Server`** the frontend then references read-only
  (and attaches to profiles). Whether `Install` itself persists the row or returns
  an unsaved struct for the caller to persist is a coordination point — propose
  **Install persists** (it owns the `Server` manifest fields).
- `ref` is an opaque string the registry resolves; the frontend treats it as a
  user-chosen identifier from the catalog list (a separate registry-provided "list
  available" call feeds the dashboard's install picker).
- Define the interface in a shared location both can import without a cycle (e.g.
  `internal/registry` owned by the registry agent, or a small `internal/installer`
  contract package). Agree on the package home before either side imports it.

### 6.4 `proxy.CredentialResolver` / `proxy.Credential` — the allowlist split
The proxy resolves `(Identity{Server,Tenant}, host) → proxy.Credential{RealSecret,
InjectHeader, InjectFormat, Placeholder, AllowedHosts}` via
`internal/gateway/resolver.go` (`CredResolver` over store + vault). Today the
`AllowedHosts` come from the **credential row** (`store.Credential.AllowedHosts`).

**The intended end state:** the per-credential **secret** is owned by you
(frontend CRUD → vault → `store.PutCredential`), while the **egress allowlist +
injection metadata** become **manifest-driven** (registry-owned), replacing the
credential-row `AllowedHosts`. The resolver must then **merge**: per-credential
secret (yours) + per-server manifest allowlist/injection (registry's).

**Coordination point:** decide together who edits `resolver.go` for the merge and
where the manifest allowlist is read from. Until that lands, the existing
credential-row allowlist keeps working — don't break it. This is the one place
your data (secrets) and registry's data (allowlist/inject metadata) meet inside a
stable package, so treat it as a joint change, not a unilateral one.

### 6.5 Auth vs MCP bearer — don't break the runtime during transition
`RequireBearer` (single static token) **stays working** until per-profile tokens
replace it. The existing egress E2E and skeleton tests (`internal/gateway/
e2e_test.go`, `egress_e2e_test.go`) authenticate with the single token and assume
`Tenant: "default"`. Introduce profile tokens **alongside** the static path, keep
the old tests green (or migrate them deliberately as part of the cutover), and
flip the default only once profiles are real.

---

## 7. Suggested approach

Use the same discipline that produced the working runtime: **brainstorm first,
spike the risky integration before building, then TDD task-by-task with
subagents.** The prior two plans (`docs/superpowers/plans/`) each opened with
empirically-validated spikes ("validated by spikes on 2026-06-06", "do not
re-derive") — that paid off (bwrap-in-Docker, netns/veth, MITM all landed without
thrash). Do the same: the OIDC callback + session/cookie flow and the
profile-token routing cutover are your equivalent risky seams.

Recommended sub-skills: `superpowers:brainstorming` (before any design),
`superpowers:writing-plans`, `superpowers:test-driven-development`,
`superpowers:subagent-driven-development` (execute the plan task-by-task).

**First 3–5 concrete steps:**

1. **Brainstorm + write a plan** (`docs/superpowers/plans/`) covering auth model,
   data model, REST surface, profile-token design, and the dashboard scope.
   Resolve the section-10 open questions with the human in this step.
2. **Spike the OIDC flow** with `coreos/go-oidc` + `x/oauth2` against one real
   provider (Google or GitHub-via-OIDC) in the Linux container: prove
   start → callback → token verify → httpOnly cookie. Record the verified API
   surface the way the prior plans do.
3. **Multi-user store schema (TDD):** add `users`/`profiles`/`sessions` (+ joins,
   invitations, audit) as new `store` files + interface methods; test against
   sqlite. Follow the `credentials.go` pattern.
4. **REST API skeleton + session middleware (TDD):** `internal/api` with
   login/logout/me, RBAC middleware, and the users/profiles/credentials handlers;
   wire an API-server goroutine into `run()` via a new helper.
5. **Profile-scoped MCP endpoint + per-profile tokens**, keeping `RequireBearer`/
   the existing E2E green; **then** build the Next.js dashboard (`web/`) against
   the now-stable API.

---

## 8. How to build & test

- **Go, full suite (incl. sandbox/egress):** `make test` — runs in a Linux
  container with `--cap-add NET_ADMIN` and `seccomp/apparmor/systempaths=
  unconfined`. Required for anything touching sandbox/netns/proxy.
- **Go, host subset:** `make test-local` — Linux-only tests self-skip on macOS.
  Use for pure store/api/auth logic that doesn't need the kernel boundary.
- **Your API/auth/store code** is mostly host-testable (`make test-local`) since it
  doesn't need bwrap; only end-to-end runs that spawn sandboxes need `make test`.
- **Gateway runtime** still needs `--cap-add NET_ADMIN` to exercise egress (see
  `docker-compose.yml`). The dashboard runs as a **separate `web` container** you
  add to compose.
- **Next.js (`web/`):** standard Node/Next toolchain in its own container; it must
  reach the Go API over the compose network (set the API base URL via env).

---

## 9. Key file pointers & libraries in play

**Files you'll read or extend:**
- `internal/store/store.go` — `Store` interface + `Server` struct (read-only for you).
- `internal/store/sqlite.go` — `OpenSQLite` (shared, additive schema wiring).
- `internal/store/credentials.go` — the pattern to mirror for new tables.
- `internal/gateway/auth.go` — `RequireBearer` (the thing profile tokens replace).
- `internal/gateway/gateway.go` — `New` aggregator (profile-scoped variant builds on this).
- `internal/gateway/resolver.go` — `CredResolver` (the allowlist-merge seam, 6.4).
- `internal/gateway/spawn.go` — `SpawnEgressBackend`; note hardcoded `Tenant:"default"`.
- `cmd/gateway/main.go` — `run()` wiring (shared merge touchpoint, 6.2).
- `internal/config/config.go` — env config (you'll add auth/OIDC config keys).
- `internal/proxy/proxy.go`, `registry.go` — `Credential`, `CredentialResolver`,
  `Identity` (read to understand the resolver contract; don't modify).

**Libraries already in the module (go.mod):** Go 1.26, MCP `modelcontextprotocol/
go-sdk` **v1.6.1**, `modernc.org/sqlite` v1.52 (pure-Go), `golang.org/x/crypto`,
`golang.org/x/oauth2` **already present (indirect)**, `vishvananda/netlink`,
`elastic/go-seccomp-bpf`.

**Libraries you'll add:** `github.com/coreos/go-oidc/v3` (per decision #18; not yet
in go.mod), a password KDF if you choose one not already pulled in (bcrypt is in
`golang.org/x/crypto/bcrypt`, already available), and the Next.js stack under
`web/`.

---

## 10. Open questions to resolve with the human before building

1. **Session storage: cookie-session vs JWT.** Decision #18 says "httpOnly
   session" without committing — opaque server-side session (DB-backed, easy
   revocation) vs signed JWT in an httpOnly cookie (stateless, harder to revoke).
   Recommend opaque DB sessions for clean impersonation + revocation; confirm.
2. **Profile tokens: opaque random vs JWT.** #11 says "per-profile bearer tokens"
   but not the format. Opaque random (stored hashed, simple, revocable) vs JWT
   (carries claims). Recommend opaque random, stored as a hash, shown once.
3. **Password hashing:** bcrypt (already vendored via x/crypto) vs argon2id
   (also in x/crypto). Pick one.
4. **Audit log persistence:** the proxy currently `log.Printf`s audit lines. Do we
   add an `audit` table + a write path the proxy/gateway calls, so the dashboard
   can read it? (Likely yes — confirm who owns the write hook, since the proxy is
   a no-touch package; the resolver or a callback may be the injection point.)
5. **Dashboard component library** for the Composio look (shadcn/ui + Tailwind is
   the common default) — confirm the stack.
6. **OIDC providers for v1:** which to support/test first (Google, GitHub) and
   whether enterprise SSO (Okta/Entra/Authentik) ships in v1 or is config-only-
   ready.
7. **Invitation flow:** email-based (needs SMTP config) vs admin-generated invite
   link/code. Recommend invite link/code for v1 (no SMTP dependency).
8. **`Installer` package home** (section 6.3): where the shared interface lives so
   neither side gets an import cycle. Settle with the registry agent.
9. **Allowlist merge ownership** (section 6.4): who edits `resolver.go` and when
   the manifest-driven allowlist replaces the credential-row `AllowedHosts`.
10. **Tenant identity shape:** today `Identity.Tenant` is the string `"default"`.
    Profiles introduce real tenancy — confirm `Tenant` becomes the profile id (or
    `user:profile`) and how that threads through `spawn.go`'s `reg.Bind` (a
    spawn.go change you'll need the runtime owner to sanity-check, since spawn is
    near the stable boundary).
