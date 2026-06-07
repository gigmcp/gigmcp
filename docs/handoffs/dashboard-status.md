# Dashboard Status Handoff

**Date:** 2026-06-07  
**Branch:** main  
**Commits:** T10 `940de56`, T11 `<see git log>`

---

## What is built

A full Next.js 16.2.7 (App Router, TypeScript, Tailwind, shadcn/base-ui) dashboard in `web/` that drives the gigmcp control plane on `:8080`. All seven spec-§8 screens are implemented:

| Screen | Route | Notes |
|---|---|---|
| Login | `/login` | Detects `control_plane_disabled` (OIDC not configured) and shows setup hint; login is `window.location.href` to trigger gateway's OIDC redirect chain |
| Overview | `/` | Stat cards (profiles/servers/credentials/users) + recent audit table |
| Servers | `/servers` | Install (admin-only) + uninstall with confirm dialog |
| Profiles list | `/profiles` | Create profile (slug validation, one-time token reveal) + table |
| Profile detail | `/profiles/[id]` | Endpoint URL copy, server bundle editor, rename, token rotate, delete |
| Credentials | `/credentials` | Add/update/delete write-only secrets; Advanced (transitional) collapsible |
| Users | `/users` | Admin-only; impersonate / stop impersonation |
| Audit log | `/audit` | Infinite-scroll keyset pagination; kind filter chips; admin user_id filter |

**Architecture summary:** Browser talks only to `:3000`. Next.js `rewrites` in `next.config.ts` server-side proxy `/api/*` and `/mcp/*` to `GATEWAY_INTERNAL_URL` (default `http://localhost:8080`), so the `gig_session` httpOnly cookie flows same-origin with zero CORS code. All data is fetched client-side via TanStack Query v5.

**Key implemented features:**
- `useReadOnly()` hook (`lib/queries.ts`) — returns `me.impersonating`; consumed on every page with mutation buttons to disable/tooltip them with "Read-only while viewing as another user"
- Skeleton loading states on all list pages (servers, profiles, credentials, users, audit, overview)
- Empty states on all list pages (when data is loaded but array is empty)
- `isPending` disables on all mutating buttons and confirm dialog confirm buttons
- Impersonation banner (amber) with inline Stop button
- Admin-gated sidebar items (Users link hidden for non-admins)
- Token reveal dialog (one-time display with copy button; used on profile create and token rotate)

---

## One-command full-stack bring-up (verified 2026-06-07)

Everything containerized; login flows entirely through `http://localhost:3000`.

### The issuer-reachability trick

The gateway's OIDC issuer is `http://localhost:8082` (the exact string go-oidc
verifies, set by the Zitadel dev fixture's ExternalDomain/Port — do NOT change
it; that would require re-initializing Zitadel). At boot the gateway fatally
fails if it can't fetch `http://localhost:8082/.well-known/openid-configuration`
*from inside its own container*, where `localhost` is the container itself.

Solution in `docker-compose.yml`: an **`issuer-proxy` sidecar** (`alpine/socat`)
owns the network namespace; the gateway joins it via
`network_mode: service:issuer-proxy`. Inside that shared netns, socat listens on
`localhost:8082` and forwards to the `zitadel` service. Both compose files live
in this directory, so they share one compose project (`gigmcp`) and one default
network — service DNS resolves across files. The same shim covers the token and
JWKS endpoints (also issuer-host URLs). Because the sidecar starts before the
gateway (`depends_on` + netns ownership), there is no race against the
gateway's fatal 10s discovery timeout. Port `8080:8080` is published on the
sidecar (only the netns owner can publish), and the web container's rewrite
target is `http://issuer-proxy:8080` (the gateway has no DNS name of its own).

### .env template (repo root; gitignored — never commit)

```bash
GIG_BEARER_TOKEN=<openssl rand -hex 32>
GIG_MASTER_KEY=<openssl rand -hex 32>
GIG_OIDC_ISSUER=http://localhost:8082
GIG_OIDC_CLIENT_ID=376420779513937923
# No GIG_OIDC_CLIENT_SECRET — PKCE public client.
GIG_OIDC_REDIRECT_URL=http://localhost:3000/api/auth/callback
GIG_PUBLIC_URL=http://localhost:3000
```

### Bring-up

```bash
# 1. Zitadel dev fixture first (skip if already running — do not recreate, it
#    holds clicked console config):
docker compose -f docker-compose.dev.yml up -d

# 2. Gateway (+ issuer-proxy sidecar) and web:
docker compose up -d --build
```

**Never pass `--remove-orphans`** — both files share the project, so it would
tear down the Zitadel containers.

The gateway image build needs the sibling checkout `../gigmcp-registry`
(go.mod `replace`); compose supplies it as a named build context
(`additional_contexts: registry: ../gigmcp-registry`).

Two gotchas found during verification:
- `GATEWAY_INTERNAL_URL` is evaluated by `next.config.ts` rewrites **at build
  time** and baked into `.next/routes-manifest.json` — the standalone server
  ignores the runtime env var. It is now a web **build arg**
  (`http://issuer-proxy:8080` in compose); changing it requires a rebuild.
- A stray host process can squat IPv4 `*:3000` (an `npx open-websearch` MCP
  server was doing so during verification). Docker Desktop still publishes
  `[::]:3000`, and `localhost` resolves to `::1` first, so curl/browser hit the
  dashboard — but if you ever get an Express 404 from `:3000`, check
  `lsof -nP -iTCP:3000 -sTCP:LISTEN`.

### HUMAN STEP (Zitadel console — required before first login)

In the Zitadel console (`http://localhost:8082/ui/console`, admin@zitadel.localhost) →
project **gigmcp** → the PKCE web app (client ID `376420779513937923`) →
**Redirect URIs**: **add** `http://localhost:3000/api/auth/callback`
(keep the existing `http://localhost:8080/api/auth/callback` too). Development
Mode is already on, so plain-http URIs are accepted. Save.

Then open `http://localhost:3000` → `/login` → Sign in → Zitadel → back to the
dashboard.

---

## How to run (dev)

### Prerequisites

1. **Zitadel** — a Zitadel instance (local docker or hosted) configured with an OIDC application. See the spike notes in `docs/handoffs/frontend-control-plane.md`. The gateway needs:
   - `GIG_OIDC_ISSUER` — e.g. `https://your-zitadel.cloud`
   - `GIG_OIDC_CLIENT_ID` — the OIDC client ID
   - `GIG_OIDC_CLIENT_SECRET` — the OIDC client secret
   - `GIG_OIDC_REDIRECT_URL` — must be `http://localhost:3000/api/auth/callback` when using the web dashboard
   - `GIG_PUBLIC_URL` — set to `http://localhost:3000` (the browser-facing origin)
   - `GIG_BEARER_TOKEN` — any string (legacy MCP auth, still required)
   - `GIG_MASTER_KEY` — 32-byte hex key for the credential vault (`openssl rand -hex 32`)

2. **Node v22 + pnpm 10.30.3** — available locally.

### Steps

```bash
# 1. Start the gateway (with OIDC env vars set or in .env):
# Option A: via docker compose (builds gateway image):
GIG_BEARER_TOKEN=... GIG_MASTER_KEY=... GIG_OIDC_ISSUER=... GIG_OIDC_CLIENT_ID=... \
  GIG_OIDC_CLIENT_SECRET=... GIG_OIDC_REDIRECT_URL=http://localhost:3000/api/auth/callback \
  GIG_PUBLIC_URL=http://localhost:3000 \
  docker compose up gateway

# Option B: run gateway binary directly:
GIG_BEARER_TOKEN=... GIG_MASTER_KEY=... GIG_OIDC_ISSUER=... GIG_OIDC_CLIENT_ID=... \
  GIG_OIDC_CLIENT_SECRET=... GIG_OIDC_REDIRECT_URL=http://localhost:3000/api/auth/callback \
  GIG_PUBLIC_URL=http://localhost:3000 \
  go run ./cmd/gateway

# 2. Start the Next.js dev server:
cd web
pnpm dev
# Open http://localhost:3000 — will redirect to /login
```

The dashboard talks to the gateway via Next.js rewrites. Opening `http://localhost:3000/api/auth/login` in the browser will initiate the OIDC flow.

### Docker compose (both services)

```bash
# Requires all GIG_* env vars set (see above; or in .env). The web service
# rewrites to http://issuer-proxy:8080 internally (baked at image build — see
# the bring-up section above). GIG_OIDC_REDIRECT_URL must be
# http://localhost:3000/api/auth/callback (browser-facing).
GIG_BEARER_TOKEN=... GIG_MASTER_KEY=... GIG_OIDC_ISSUER=... \
  GIG_OIDC_CLIENT_ID=... GIG_OIDC_CLIENT_SECRET=... \
  GIG_OIDC_REDIRECT_URL=http://localhost:3000/api/auth/callback \
  GIG_PUBLIC_URL=http://localhost:3000 \
  docker compose up --build
```

---

## What is pending / gated

### Zitadel console setup (human-in-the-loop — T1 spike)

**Verified 2026-06-07 against Zitadel v2.71.0 (issuer http://localhost:8082).** Use `ghcr.io/zitadel/zitadel:v2.x` — v3+ splits the login UI into a separate container; latest (v4) returns `{"code":5,"message":"Not Found"}` on login. The `docker-compose.dev.yml` fixture is already pinned correctly.

Before the dashboard can perform a first login, an admin must:

1. Create a Zitadel project named `gigmcp` and an OIDC web application (type **Web**, auth method **PKCE**, redirect URI = `http://localhost:3000/api/auth/callback` for dev, **Development Mode** on).
2. Three switches that must ALL be on for the roles claim to appear in the ID token:
   - Project **General Settings** → **"Assert Roles on Authentication"** (embeds `urn:zitadel:iam:org:project:roles` in the ID token).
   - App **Token Settings** → **"User roles inside ID Token"**.
   - Project **Authorizations** → grant the user the `gigmcp-admin` role and ensure the ROLES column is non-empty (an authorization row with an empty ROLES column yields no claim).
3. Set the role `gigmcp-admin` on the first user (or configure `GIG_OIDC_ADMIN_ROLE` to match your Zitadel role name).
4. Set the env vars listed above on the gateway.
5. Open `http://localhost:3000` → will redirect to `/login` → click "Sign in" → Zitadel → callback → overview.

The `control_plane_disabled` error (shown on `/login` when OIDC is not configured) is handled gracefully with a setup hint.

### T18 — retire `RequireBearer` (gated on human)

Once OIDC is verified end-to-end, `RequireBearer` middleware on `/mcp/*` can be retired so the cookie-based session is the sole auth path. This is tracked as task T18 and must not be merged until the first login spike (T1) is completed and verified.

### Component tests / Playwright

Explicitly out of scope for v1. Verification is `tsc --noEmit` + lint + `next build` + `docker build`.

---

## Verification outputs (T10 + T11)

```
tsc --noEmit    → clean (0 errors)
pnpm run lint   → clean (0 warnings)
pnpm run build  → all 10 routes compiled, static/dynamic as expected
docker build    → image builds successfully (multi-stage, standalone output)
smoke test      → docker run -p 3001:3000; curl http://localhost:3001/login → HTTP 200
```
