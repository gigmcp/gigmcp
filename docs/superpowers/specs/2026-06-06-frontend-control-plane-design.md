# Frontend + Control-Plane Design

> Spec for the frontend/control-plane workstream (docs/handoffs/frontend-control-plane.md):
> Go REST API, Zitadel-backed auth, multi-user data model, profile-scoped MCP
> endpoints, Next.js dashboard. Brainstormed and approved 2026-06-06. Runs in
> parallel with the manifest/registry workstream
> (docs/handoffs/manifest-registry.md); coordination seams are §10.

---

## 1. Resolved decisions (handoff §10 open questions)

| # | Question | Decision |
|---|----------|----------|
| 1 | Session storage | Opaque DB-backed sessions; random 256-bit cookie value, SHA-256 stored |
| 2 | Profile token format | Opaque random, SHA-256-hashed at rest, plaintext shown once at create/rotate |
| 3 | Password KDF | Moot for v1 — Zitadel-only auth, no local passwords (argon2id if local auth ever ships) |
| 4 | Audit persistence | Yes: `audit` table; egress events via a resolver decorator, auth/admin events from API handlers |
| 5 | Dashboard stack | Next.js (App Router, TS) + Tailwind + shadcn/ui |
| 6 | IdP | **Zitadel as sole IdP** via the generic OIDC client (`coreos/go-oidc/v3`); social login (Google/GitHub) federated inside Zitadel |
| 7 | Invitations | Dropped from gigmcp v1 — users managed in the Zitadel console; JIT provisioning on first login |
| 8 | Installer package home | `internal/registry` (registry-owned); API handlers import `registry.Installer` |
| 9 | Allowlist merge ownership | Registry owns the `resolver.go` allowlist-sourcing refactor (their §6.C); credential row shrinks to secret-only on their schedule |
| 10 | Tenant identity | `Identity.Tenant` = **profile ID**; resolver joins profile → owning user for credential lookup |

**Deviation from DESIGN.md decision #19:** "local email+password login + invitations"
is superseded by Zitadel-only auth. Local login, password hashing, and the
invitation flow drop out of v1. RBAC roles are mapped from Zitadel project-role
claims at each login (cached locally, not editable in gigmcp). DESIGN.md should
be amended when this lands.

**Build approach (approved):** inside-out, dual-path. Store → OIDC/session spike
against real Zitadel → REST API → profile-scoped MCP routing alongside the
existing static path → dashboard last. The existing static-token path and
`Tenant:"default"` E2E tests stay green throughout; cutover is one deliberate
final task.

---

## 2. Architecture & HTTP topology

**New packages** (all new files; zero overlap with the registry agent's files):

- `internal/auth` — OIDC client, session manager, JIT provisioning, role-claim
  mapping, impersonation context.
- `internal/api` — REST handlers + session/RBAC middleware.
- `internal/store/{users,profiles,sessions,audit}.go` — additive store
  extensions following the `credentials.go` pattern.
- `web/` — Next.js dashboard, separate container.
- Compose gains `web` and (dev) `zitadel` + its database.

**One listener, one mux** on the existing `:8080` (replaces the bare
`ListenAndServe` in `run()` via a new `buildMux(...)` helper — minimal merge
surface):

```
/mcp                 → existing aggregator + RequireBearer (transitional, until cutover)
/mcp/p/{slug}        → profile-scoped aggregator, per-profile bearer token
/api/auth/login      → 302 to Zitadel authorize (state+nonce+PKCE)
/api/auth/callback   → code exchange, ID-token verify, JIT provision, session cookie
/api/*               → REST, session-cookie auth + RBAC middleware
```

Rationale for one port (vs. the handoff's "API goroutine on its own port"): one
public endpoint to secure, no CORS — the Next.js container rewrites `/api/*`
server-side to the gateway, so browser cookies are same-origin.

---

## 3. Data model (additive; SQLite-first, Postgres-compatible per DESIGN #14)

```sql
users:    id PK, issuer TEXT, subject TEXT, email, display_name,
          role TEXT CHECK(role IN ('admin','user')), created_at, last_login_at,
          UNIQUE(issuer, subject)

sessions: token_hash TEXT PK,            -- SHA-256 of the cookie value
          user_id FK, created_at, expires_at,
          impersonating_user_id NULL, impersonation_expires_at NULL

profiles: id PK, slug TEXT UNIQUE,       -- the <slug> in /mcp/p/<slug>
          name, user_id FK (owner),
          token_hash TEXT,               -- SHA-256 of the profile bearer token
          meta_tools INTEGER DEFAULT 0,  -- DESIGN #11 opt-in flag (schema only; impl deferred post-v1)
          created_at

profile_servers: profile_id FK, server_name, PK(profile_id, server_name)

audit:    id PK, ts, kind TEXT CHECK(kind IN ('egress','auth','admin')),
          user_id NULL, profile_id NULL, server TEXT, host TEXT,
          decision TEXT, detail TEXT
```

Each table's DDL lives in its own file as a `const xSchema`, executed additively
in `OpenSQLite` (`CREATE TABLE IF NOT EXISTS`), per the coordination protocol.
New `Store` interface methods live beside their impls in the new files.

**Credential semantics change:** `credentials.tenant` starts holding the owning
**user ID** (as a string) instead of `"default"`. Credentials are per-user, so
one key serves all of that user's profiles — no duplication. The legacy
`"default"` tenant keeps working for the existing E2E until cutover.

**Roles are a cache of Zitadel claims**, refreshed at every login. No local
role editing in v1; the users screen is read-only + impersonate.

---

## 4. Auth, sessions, impersonation (`internal/auth`)

**Config** (new keys in `internal/config`): `GIG_OIDC_ISSUER`,
`GIG_OIDC_CLIENT_ID`, `GIG_OIDC_CLIENT_SECRET` (+ `_FILE` variants),
`GIG_OIDC_REDIRECT_URL`, `GIG_OIDC_ADMIN_ROLE` (Zitadel role name mapping to
`admin`; default `gigmcp-admin`), `GIG_SESSION_TTL` (default 168h),
`GIG_PUBLIC_URL`.

**Login flow:** Authorization Code + PKCE via `go-oidc`/`x/oauth2`. State +
nonce + PKCE verifier travel in a short-lived (10 min) signed httpOnly cookie —
no DB row for pending logins. The callback verifies state, exchanges the code,
verifies the ID token (signature, nonce, issuer, audience), reads
`sub`/`email`/`name` + the Zitadel roles claim
(`urn:zitadel:iam:org:project:roles`), JIT-upserts the user by `(issuer,
subject)`, writes a session row, sets `gig_session` (httpOnly, `SameSite=Lax`,
`Secure` when `GIG_PUBLIC_URL` is https), and redirects to `/`. Logout deletes
the session row and clears the cookie (local logout only in v1; RP-initiated
Zitadel logout is a follow-up).

**Middleware chain:** `Session → Impersonation → RBAC`, attaching
`(RealUser, EffectiveUser, role)` to the request context.

**Impersonation (DESIGN #20, view-as only):**
`POST /api/admin/impersonate {user_id, ttl ≤ 60m}` stamps the admin's session
row (`impersonating_user_id`, `impersonation_expires_at`); `DELETE` clears it.
While active: GET endpoints resolve against the target user; **all mutations
are 403** except stop-impersonation; credential endpoints never return secrets
anyway (write-only). Start/stop each emit an `admin` audit event naming both
parties — visible to the impersonated user in their own audit view.
`GET /api/me` returns both identities so the dashboard renders the banner.
MCP endpoints use profile tokens, not sessions, so tool execution during
impersonation is structurally impossible, not just policy-blocked.

---

## 5. REST surface (`internal/api`)

```
GET    /api/me                          → user, role, impersonation state
GET    /api/auth/login | /api/auth/callback,  POST /api/auth/logout

GET    /api/profiles                    → own (admin: all)
POST   /api/profiles {name, slug}       → creates + returns token PLAINTEXT ONCE
GET    /api/profiles/{id}               → detail incl. endpoint URL, servers, NO token
PATCH  /api/profiles/{id}  | DELETE /api/profiles/{id}
PUT    /api/profiles/{id}/servers {names[]}
POST   /api/profiles/{id}/token         → rotate, returns plaintext once

GET    /api/credentials                 → metadata only — never the secret
PUT    /api/credentials/{server}        → vault.Encrypt → store.PutCredential(tenant=userID)
       body: {secret, inject_header, inject_format, placeholder, allowed_hosts[]}
       (the non-secret fields are transitional: they populate the credential-row
        columns until the registry's manifest sourcing replaces them — then the
        body shrinks to {secret} and the UI drops those inputs)
DELETE /api/credentials/{server}

GET    /api/servers                     → installed (registry.Installer.List)
POST   /api/servers/install {ref}       → registry.Installer.Install   (admin)
DELETE /api/servers/{name}              → registry.Installer.Uninstall (admin)

GET    /api/users                       → admin; read-only list
POST   /api/admin/impersonate | DELETE  → admin
GET    /api/audit?cursor&limit          → own events; admin: all, filterable
```

Until the registry agent's `Installer` lands, the install endpoints compile
against the `internal/registry` interface with a stub returning "not yet
available". Errors are a uniform `{error: {code, message}}`. All mutations emit
audit events.

---

## 6. Profile-scoped MCP endpoints

**Request path:** `POST /mcp/p/{slug}` → extract bearer → SHA-256 → look up
profile by `(slug, token_hash)` → get-or-create that profile's runtime → serve.

**Profile runtime** (new in `internal/gateway`): a `ProfileHost` keeps a
mutex-guarded map `profileID → *profileRuntime{server *mcp.Server, backends,
cleanups}`. On first request to a profile (lazy spawn, per DESIGN #5): for each
server in the profile's bundle, `SpawnEgressBackend` with `Tenant = profile ID`,
then build the aggregator via the existing `gw.New`. Subsequent requests reuse
the runtime. Profile edits (bundle change, delete, token rotation does NOT)
invalidate the runtime — sandboxes torn down via existing cleanups, rebuilt on
next request. Idle-reaping is out of v1 scope for this workstream (sandbox count
bounded by profiles × servers; documented limitation).

**Near-boundary change:** `spawn.go`'s hardcoded `reg.Bind(..., Tenant:
"default")` becomes a `tenant` parameter on `SpawnEgressBackend`. Pure
parameter-threading; existing callers pass `"default"`. Flagged for a
runtime-owner sanity check per the handoff.

**Resolver join (my edit, small):** `CredResolver.Resolve` resolves
`id.Tenant` → if it names a profile, look up the owner's user ID for the
`GetCredential` call; otherwise treat it as a literal tenant (keeps `"default"`
E2E working). Orthogonal to the registry's allowlist-sourcing refactor in the
same file: I change *which tenant key* feeds the secret lookup; they change
*where allowlist/injection metadata come from*. Coordinated file — see §10.

**Transition:** `/mcp` + `RequireBearer` + the startup spawn-all loop stay
untouched until the final cutover task (§9).

---

## 7. Audit pipeline

- **Egress events** — a decorator I own, zero proxy edits:
  `AuditingResolver{Inner, Sink}` wraps `CredResolver`; each `Resolve` logs
  `(server, profileID → userID, host, resolved|denied)`. It mirrors the proxy's
  exact-match + single-label `*.suffix` host-matching semantics to record the
  decision — an intentional, documented duplication (the registry's lint CI
  must mirror the same rule). Writes are async through a buffered channel so
  audit can never block the egress hot path; overflow drops are counted and
  logged, never blocking.
- **Auth/admin events** — written synchronously by API handlers: login, logout,
  impersonate start/stop, profile create/delete, token rotate, credential
  put/delete, install/uninstall.
- **Read side:** keyset pagination (`cursor` = last id). Users see rows where
  `user_id` = self; admins see all with filters.

---

## 8. Dashboard (`web/`)

Next.js App Router + TypeScript + Tailwind + shadcn/ui; Composio-style dark
sidebar shell, data-table-centric pages.

Routes: `/login` (button → `/api/auth/login`), `/` (overview), `/servers`
(installed + install-by-ref; catalog browse arrives when the registry index API
lands), `/profiles` + `/profiles/[id]` (bundle editor, endpoint URL, one-time
token reveal/rotate with copy), `/credentials` (write-only secret form),
`/users` (admin: read-only list + impersonate), `/audit`.

Data fetching: client-side via TanStack Query against same-origin `/api/*`; a
Next.js rewrite proxies `/api/*` to the gateway container
(`GATEWAY_INTERNAL_URL` env), so cookies flow same-origin and there is no CORS.
Auth gate: Next middleware checks `/api/me`, bounces 401 to `/login`.
Impersonation banner driven by `/api/me`, rendered in the shell. Compose: new
`web` service.

---

## 9. Testing & cutover

- **Store/API/auth:** host-testable (`make test-local`). API tests via
  `httptest` over a temp SQLite store. OIDC unit tests against a local fake
  issuer (httptest server serving JWKS + signed ID tokens — standard go-oidc
  pattern).
- **OIDC spike first** (plan step): against real Zitadel in compose — prove
  start → callback → verify → cookie; record the verified API surface in the
  plan doc, as the prior runtime plans did.
- **Profile routing E2E** (container, `make test`): two profiles, distinct
  tokens and tenants — prove token A cannot reach profile B, and the proxy
  injects each owner's credential.
- **Existing E2E stays green** until the explicit cutover task: migrate
  `e2e_test.go`/`egress_e2e_test.go` to a seeded profile + token, then delete
  `RequireBearer`, `GIG_BEARER_TOKEN`, and the implicit-default-profile spawn
  loop.
- **Web:** lint + typecheck + production build in CI; Playwright deferred.

---

## 10. Coordination seams with the registry workstream

| Seam | Agreement |
|------|-----------|
| `store.Store` / `OpenSQLite` | Each side adds methods + schema consts in its own files; `OpenSQLite` gains additive `ExecContext` lines (small expected merge) |
| `store.Server` struct | Registry owns its fields; I read it read-only |
| `cmd/gateway/main.go run()` | Both add separate helper functions; I add `buildMux(...)` + auth/API wiring, they add install wiring (small expected merge) |
| `Installer` | Lives in `internal/registry` (theirs); 3-method interface as written in both handoffs; my install endpoints consume it, stubbed until it lands |
| `resolver.go` | Registry refactors allowlist/injection sourcing (manifest); I add the profile→user tenant join for the secret lookup. Sequence whichever lands second over the first; both edits are small |
| `credentials` columns | I keep writing injection/allowlist columns until their manifest sourcing lands, then stop (columns become ignored, dropped later on their schedule) |
| `spawn.go` tenant param | My edit, runtime-owner sanity check requested |
| Sandbox rootfs extension | Not mine — joint item flagged in both handoffs; I only consume static-binary servers meanwhile |
