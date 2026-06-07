# Dashboard Status Handoff

**Date:** 2026-06-07  
**Branch:** main  
**Commits:** T10 `940de56`, T11 `<see git log>`

---

## What is built

A full Next.js 15 (App Router, TypeScript, Tailwind, shadcn/base-ui) dashboard in `web/` that drives the gigmcp control plane on `:8080`. All seven spec-§8 screens are implemented:

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
# Requires all GIG_* env vars set (see above). The web service rewrites to
# http://gateway:8080 internally. GIG_OIDC_REDIRECT_URL must be
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

Before the dashboard can perform a first login, an admin must:

1. Create a Zitadel project and OIDC web application (redirect URI = `http://localhost:3000/api/auth/callback` for dev).
2. Set the role `gigmcp-admin` on the first user (or configure `GIG_OIDC_ADMIN_ROLE` to match your Zitadel role name).
3. Set the env vars listed above on the gateway.
4. Open `http://localhost:3000` → will redirect to `/login` → click "Sign in" → Zitadel → callback → overview.

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
