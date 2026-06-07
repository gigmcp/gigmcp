# Dashboard Implementation Plan (Next.js + shadcn, `web` container)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Each task ends with the build green (`tsc --noEmit` + lint + `next build`) and a commit.

**Goal:** A Next.js (App Router, TS) dashboard — `web/`, its own container — that drives the as-built Go control plane on `:8080`. It renders the seven spec-§8 screens (login, overview, servers, profiles + profile detail, credentials, users, audit), authenticates purely via the gateway's `gig_session` httpOnly cookie (no Auth.js), and talks to the API **same-origin** through Next.js rewrites so cookies flow with zero CORS code. Composio-style dark sidebar shell; admin-only nav/actions hidden for non-admins; impersonation banner driven by `/api/me`.

**Architecture:** The browser only ever talks to the Next.js origin (`:3000`). `next.config` rewrites `/api/:path*` and `/mcp/:path*` to `GATEWAY_INTERNAL_URL` (default `http://gateway:8080` in compose, `http://localhost:8080` for local dev). Because a Next rewrite is a server-side reverse-proxy on the **same browser origin**, the `gig_session` cookie set by the gateway's callback (Path `/`, httpOnly, SameSite=Lax) is sent by the browser to `:3000` and forwarded by Next to the gateway — no `Access-Control-*` headers, no `credentials: 'include'` cross-origin dance, no CORS preflight. All data fetching is **client-side** via TanStack Query against relative `/api/*` URLs (so `fetch` is same-origin and cookies attach automatically). Login is a **full-page navigation** to `/api/auth/login` (not a fetch) so the gateway's 302→Zitadel→callback→`Set-Cookie`→302 `/` chain runs in the top-level browsing context. `/api/me` is the session probe: 200 = signed in, 401 = bounce to `/login`. A TanStack Query global error handler intercepts 401 and client-redirects to `/login`.

**Tech Stack (locked):** Next.js 15 (App Router) + TypeScript + Tailwind CSS + shadcn/ui (Radix primitives); `@tanstack/react-query` v5 for all data; `sonner` (shadcn toast) for one-time-token reveal + error toasts; `lucide-react` icons (ships with shadcn). No Auth.js, no axios (native `fetch`), no state lib beyond Query. Node v22.22.0 / **pnpm 10.30.3** (verified present on the build host — use pnpm throughout; if a future host lacks it, swap `pnpm`→`npm` and `pnpm dlx`→`npx`). Next `output: "standalone"` for a minimal multi-stage Docker image.

**Critical environment facts (verified against the as-built Go — trust over spec):**
- The gateway mux paths are **case-sensitive**: `/api/...` lowercase only. `/API/*` silently falls to the legacy `/` handler. The rewrite must preserve lowercase (it does — we hardcode lowercase `/api`). (`cmd/gateway/serve.go` buildMux note.)
- When OIDC is **unconfigured**, every `/api/*` returns **HTTP 404** with body `{"error":{"code":"control_plane_disabled","message":"control plane disabled: set GIG_OIDC_ISSUER, GIG_OIDC_CLIENT_ID, GIG_OIDC_REDIRECT_URL"}}`. The `/login` page must detect this exact code and show a setup hint instead of a dead login button.
- The error envelope is uniform: `{"error":{"code":string,"message":string}}` on every non-2xx. Codes seen in the handlers: `unauthenticated`(401), `forbidden`(403), `impersonating`(403, mutations blocked while view-as), `not_found`(404), `method_not_allowed`(405), `invalid`(400), `conflict`(409), `internal`(500), `install_failed`/`uninstall_failed`(502), `control_plane_disabled`(404).
- Session cookie name: `gig_session` (httpOnly — JS can NEVER read it; the app's only signed-in signal is a 200 from `/api/me`). Logout is **POST** `/api/auth/logout` → 204, then route to `/login`.
- Mutations while impersonating return **403 `impersonating`** for everything except `DELETE /api/admin/impersonate`. The UI disables mutating controls while the banner is up.
- Audit is **NOT** a bare array — it is `{"events":[…],"next_before":<id>}`; `next_before:0` means no more pages. Pagination param is `before` (the last row's id), plus `limit`, plus admin-only `user_id`.

---

## Verified API surface (as-built — trust over spec)

Base path `/api` (lowercase). All responses JSON; errors are `{"error":{"code","message"}}`. Auth = `gig_session` cookie (forwarded same-origin by the Next rewrite). Source files cited per row.

**Auth / session** (`internal/auth/oidc.go`, `session.go`)
| Method | Path | Request | Response | Notes |
|---|---|---|---|---|
| GET | `/api/auth/login` | — | **302** → Zitadel | Full-page nav, NOT fetch. |
| GET | `/api/auth/callback` | code/state (from IdP) | 302 → `/`, sets `gig_session` | Browser-driven; UI never calls directly. |
| POST | `/api/auth/logout` | — | **204** | Deletes session row + clears cookie. |
| GET | `/api/me` | — | `{user, impersonating, real_user?}` | Session probe. 401 if no/invalid cookie. |

`me` shape (`internal/api/me.go`): `user: {id:number, email:string, display_name:string, role:"admin"|"user"}`, `impersonating: boolean`, `real_user?: same-shape-as-user` (present ONLY while impersonating).

**Profiles** (`internal/api/profiles.go`)
| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/api/profiles` | — | `profileJSON[]` (own; admin sees all) |
| POST | `/api/profiles` | `{name, slug}` | **201** `profileJSON` **with `token`** (plaintext ONCE) |
| GET | `/api/profiles/{id}` | — | `profileJSON` (no `token`) |
| PATCH | `/api/profiles/{id}` | `{name}` | `profileJSON` |
| DELETE | `/api/profiles/{id}` | — | **204** |
| PUT | `/api/profiles/{id}/servers` | `{servers: string[]}` | `profileJSON` (replace-all; each name must be installed) |
| POST | `/api/profiles/{id}/token` | — | `profileJSON` **with `token`** (rotate; plaintext ONCE) |

`profileJSON`: `{id:number, slug:string, name:string, user_id:number, endpoint:string ("/mcp/p/<slug>"), servers:string[], token?:string}`. `token` is present ONLY on create + rotate responses. Create errors: 400 `invalid` (name 1–128, slug `^[a-z0-9][a-z0-9-]{1,62}$`), 409 `conflict` (slug taken). PUT servers: 400 `invalid` `"unknown server: <n>"`.

**Credentials** (`internal/api/credentials.go`) — write-only secret; never returned.
| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/api/credentials` | — | `credentialJSON[]` (metadata only) |
| PUT | `/api/credentials/{server}` | `credentialPutBody` | **204** |
| DELETE | `/api/credentials/{server}` | — | **204** |

`credentialJSON`: `{server:string, inject_header:string, inject_format:string, placeholder:string, allowed_hosts:string[]}` (NO secret). `credentialPutBody`: `{secret:string (required, non-empty), inject_header?:string (^[A-Za-z0-9-]+$, ≤64), inject_format?:string (must contain "{token}", ≤256), placeholder?:string (8–256), allowed_hosts?:string[] (≤64, each ≤253, ^(\*\.)?[a-z0-9.-]+$, no whitespace)}`. `{server}` path: `^[a-z0-9][a-z0-9_-]{0,63}$`. The non-secret fields are **transitional** (manifest sourcing will replace them) — render them in a collapsible "Advanced (transitional)" section. Validation 400 message form: `"<field>: <msg>"`.

**Servers** (`internal/api/servers.go`)
| Method | Path | Request | Response | Auth |
|---|---|---|---|---|
| GET | `/api/servers` | — | `serverJSON[]` | any |
| POST | `/api/servers/install` | `{ref}` | **201** `serverJSON` | **admin** |
| DELETE | `/api/servers/{name}` | — | **204** | **admin** |

`serverJSON`: `{id:number, name:string}`. Install failure → **502 `install_failed`** (message = installer error). Uninstall failure → **502 `uninstall_failed`**. When the installer backend is absent, install/uninstall return **501 `internal`** "installer unavailable" (handle gracefully: show the message). GET falls back to the store list, so it always works.

**Users + impersonation** (`internal/api/users.go`) — admin only.
| Method | Path | Request | Response |
|---|---|---|---|
| GET | `/api/users` | — | `userJSON[]` |
| POST | `/api/admin/impersonate` | `{user_id:number, ttl_minutes:number}` | **204** |
| DELETE | `/api/admin/impersonate` | — | **204** (the ONE mutation allowed while impersonating) |

`userJSON`: `{id, email, display_name, role}`. `ttl_minutes` ≤ 60 (server clamps; ≤0 → 60). Cannot impersonate self (400). Non-admin hitting any of these → 403 `forbidden`.

**Audit** (`internal/api/audit.go`)
| Method | Path | Query | Response |
|---|---|---|---|
| GET | `/api/audit` | `before?`, `limit?` (≤200, default 50), `user_id?` (admin, non-impersonating only) | `{events: auditEventJSON[], next_before: number}` |

`auditEventJSON`: `{id:number, ts:string (RFC3339), kind:"egress"|"auth"|"admin", user_id:number|null, profile_id:number|null, server:string, host:string, decision:string, detail:string}`. Keyset: pass the previous page's `next_before` as `before` for the next page; `next_before === 0` → no more pages. Non-admins are server-forced to their own events regardless of query.

---

## File Structure

```
web/
├── package.json                  # T1 (generated)
├── pnpm-lock.yaml                # T1 (generated)
├── tsconfig.json                 # T1 (generated)
├── next.config.ts                # T1 → T2 (rewrites + standalone)
├── tailwind.config.ts           # T1 — only present if generated (Tailwind v3); v4 uses CSS-first config in globals.css
├── postcss.config.mjs           # T1 (generated)
├── components.json              # T2 (shadcn init)
├── .eslintrc / eslint.config.mjs# T1 (generated)
├── Dockerfile                   # T10
├── .dockerignore                # T10
├── app/
│   ├── globals.css              # T1/T2 (shadcn theme tokens)
│   ├── layout.tsx               # T3 root layout (html/body, providers)
│   ├── providers.tsx            # T3 QueryClientProvider + Toaster + 401 interceptor
│   ├── (auth)/login/page.tsx    # T4 login (+ control_plane_disabled state)
│   ├── (app)/layout.tsx         # T3 sidebar shell + impersonation banner + auth gate
│   ├── (app)/page.tsx           # T4 overview
│   ├── (app)/servers/page.tsx   # T5
│   ├── (app)/profiles/page.tsx  # T6
│   ├── (app)/profiles/[id]/page.tsx # T6
│   ├── (app)/credentials/page.tsx   # T7
│   ├── (app)/users/page.tsx     # T8
│   └── (app)/audit/page.tsx     # T9
├── lib/
│   ├── api.ts                   # T3 fetch wrapper + ApiError + endpoint fns
│   ├── types.ts                 # T3 as-built JSON types
│   ├── queries.ts               # T3 TanStack query/mutation hooks
│   └── utils.ts                 # T2 (shadcn cn())
└── components/
    ├── ui/                      # T2 shadcn primitives (button, dialog, …)
    ├── app-sidebar.tsx          # T3 nav (admin-gated items)
    ├── impersonation-banner.tsx # T3
    ├── data-table.tsx           # T3 thin table helper
    ├── token-reveal-dialog.tsx  # T6 one-time token reveal + copy
    └── confirm-dialog.tsx       # T5 reusable destructive confirm
```

---

## Tasks

### T1 — Scaffold Next.js app

- [ ] From the repo root, scaffold into `web/` (non-interactive flags so no prompts):
  ```bash
  pnpm dlx create-next-app@latest web \
    --ts --app --tailwind --eslint --no-src-dir \
    --import-alias "@/*" --use-pnpm --no-turbopack --yes
  ```
  > **Version-sensitive flag spellings:** Boolean CLI flags for `create-next-app` use `--no-<flag>` form (e.g. `--no-src-dir`, `--no-turbopack`). These spellings can change between Next.js minor releases. The T1 verify step (`pnpm run build`) is the arbiter — if the scaffold fails or produces unexpected output, inspect `pnpm dlx create-next-app@latest --help` and adjust flags to match the installed CLI version.

  Expected: `web/` created with `app/`, `next.config.ts`, `tsconfig.json` (paths `@/* → ./*`), `package.json` (scripts `dev/build/start/lint`), `pnpm-lock.yaml`. Next 15, React 19. Note: Tailwind v4 (which ships with Next 15) uses CSS-first config via `app/globals.css`; a `tailwind.config.ts` file may not be generated — see T2 for details.
- [ ] Verify the toolchain inside `web/`:
  ```bash
  (cd web && pnpm install && pnpm exec tsc --noEmit && pnpm run lint && pnpm run build)
  ```
  Expected: install clean, `tsc` no errors, lint clean, `next build` prints a route table and "Compiled successfully".
- [ ] Commit: `chore(web): scaffold Next.js app (TS, App Router, Tailwind)`.

### T2 — shadcn/ui init + base components + theme + rewrites

- [ ] Initialize shadcn (non-interactive; pick the slate/neutral base with CSS variables):
  ```bash
  (cd web && pnpm dlx shadcn@latest init -d -b neutral)
  ```
  Expected: `components.json` written, `lib/utils.ts` (`cn`), `app/globals.css` updated with the CSS-variable theme block. `-d` accepts defaults; `-b neutral` sets the base color.

  > **Tailwind v4 (CSS-first config):** Next 15 ships with Tailwind v4, which uses a CSS-first configuration model — theme tokens are declared via `@theme` in `globals.css` rather than in a `tailwind.config.ts` file. `shadcn init` generates a `.dark { … }` CSS-variable block inside `globals.css`. **Do not assume `tailwind.config.ts` exists or attempt to extend it.** After running `shadcn init`, inspect the actual `app/globals.css` that was generated and use its `.dark { … }` block as the source of truth for all theme tokens. If `tailwind.config.ts` was not generated, that is correct for v4.

- [ ] Add every primitive the screens use, in one call:
  ```bash
  (cd web && pnpm dlx shadcn@latest add -y \
    button card dialog input label table badge \
    dropdown-menu sonner checkbox separator skeleton \
    alert tooltip)
  ```
  Expected: files appear under `components/ui/`. `sonner` provides the `<Toaster/>` + `toast()`.
- [ ] Force dark mode app-wide (Composio-style). Edit `app/layout.tsx` so the root `<html>` has `className="dark"` and `<body>` uses `bg-background text-foreground`. Dark mode is driven by shadcn's generated `.dark { … }` CSS-variable block in `globals.css` activated by the `dark` class on `<html>` — no additional Tailwind config is required. (Full layout lands in T3; for now just confirm the dark class compiles.)
- [ ] Write the rewrites + standalone config. Replace `web/next.config.ts` with:
  ```ts
  import type { NextConfig } from "next";

  // GATEWAY_INTERNAL_URL: where the Go gateway listens. In compose the service
  // name resolves to the gateway container; locally it's localhost:8080.
  // The rewrite makes /api/* and /mcp/* same-origin from the browser's view,
  // so the httpOnly gig_session cookie is sent to :3000 and forwarded here —
  // no CORS, no credentials:'include' needed. Paths stay lowercase because the
  // gateway mux is case-sensitive (/API/* would hit the legacy handler).
  const GATEWAY =
    process.env.GATEWAY_INTERNAL_URL ?? "http://localhost:8080";

  const nextConfig: NextConfig = {
    output: "standalone",
    async rewrites() {
      return [
        { source: "/api/:path*", destination: `${GATEWAY}/api/:path*` },
        { source: "/mcp/:path*", destination: `${GATEWAY}/mcp/:path*` },
      ];
    },
  };

  export default nextConfig;
  ```
- [ ] Verify: `(cd web && pnpm exec tsc --noEmit && pnpm run lint && pnpm run build)` green.
- [ ] Commit: `feat(web): shadcn init, base components, dark theme, /api rewrites`.

### T3 — API client, types, query layer, shell, auth gate

- [ ] Create `web/lib/types.ts` with the exact as-built shapes:
  ```ts
  export type Role = "admin" | "user";

  export interface User {
    id: number;
    email: string;
    display_name: string;
    role: Role;
  }

  export interface Me {
    user: User;
    impersonating: boolean;
    real_user?: User;
  }

  export interface Profile {
    id: number;
    slug: string;
    name: string;
    user_id: number;
    endpoint: string; // "/mcp/p/<slug>"
    servers: string[];
    token?: string; // plaintext, ONLY on create/rotate
  }

  export interface Server {
    id: number;
    name: string;
  }

  export interface Credential {
    server: string;
    inject_header: string;
    inject_format: string;
    placeholder: string;
    allowed_hosts: string[];
  }

  export interface CredentialPutBody {
    secret: string;
    inject_header?: string;
    inject_format?: string;
    placeholder?: string;
    allowed_hosts?: string[];
  }

  export interface AuditEvent {
    id: number;
    ts: string;
    kind: "egress" | "auth" | "admin";
    user_id: number | null;
    profile_id: number | null;
    server: string;
    host: string;
    decision: string;
    detail: string;
  }

  export interface AuditPage {
    events: AuditEvent[];
    next_before: number; // 0 == no more pages
  }

  export interface ApiErrorBody {
    error: { code: string; message: string };
  }
  ```
- [ ] Create `web/lib/api.ts` — the fetch wrapper. It parses the uniform error envelope, exposes `code`/`status`, and provides every endpoint fn:
  ```ts
  import type {
    Me, User, Profile, Server, Credential, CredentialPutBody, AuditPage, ApiErrorBody,
  } from "@/lib/types";

  export class ApiError extends Error {
    constructor(
      public status: number,
      public code: string,
      message: string,
    ) {
      super(message);
      this.name = "ApiError";
    }
  }

  async function request<T>(
    path: string,
    init?: RequestInit & { json?: unknown },
  ): Promise<T> {
    const { json, headers, ...rest } = init ?? {};
    const res = await fetch(path, {
      ...rest,
      headers: {
        ...(json !== undefined ? { "Content-Type": "application/json" } : {}),
        ...headers,
      },
      body: json !== undefined ? JSON.stringify(json) : rest.body,
      // Same-origin rewrite forwards the cookie automatically; this is the
      // default but we state it for clarity.
      credentials: "same-origin",
      cache: "no-store",
    });
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    const data = text ? JSON.parse(text) : undefined;
    if (!res.ok) {
      const body = data as ApiErrorBody | undefined;
      throw new ApiError(
        res.status,
        body?.error?.code ?? "unknown",
        body?.error?.message ?? res.statusText,
      );
    }
    return data as T;
  }

  export const api = {
    me: () => request<Me>("/api/me"),
    logout: () => request<void>("/api/auth/logout", { method: "POST" }),

    listProfiles: () => request<Profile[]>("/api/profiles"),
    getProfile: (id: number) => request<Profile>(`/api/profiles/${id}`),
    createProfile: (body: { name: string; slug: string }) =>
      request<Profile>("/api/profiles", { method: "POST", json: body }),
    renameProfile: (id: number, name: string) =>
      request<Profile>(`/api/profiles/${id}`, { method: "PATCH", json: { name } }),
    deleteProfile: (id: number) =>
      request<void>(`/api/profiles/${id}`, { method: "DELETE" }),
    setProfileServers: (id: number, servers: string[]) =>
      request<Profile>(`/api/profiles/${id}/servers`, {
        method: "PUT",
        json: { servers },
      }),
    rotateProfileToken: (id: number) =>
      request<Profile>(`/api/profiles/${id}/token`, { method: "POST" }),

    listServers: () => request<Server[]>("/api/servers"),
    installServer: (ref: string) =>
      request<Server>("/api/servers/install", { method: "POST", json: { ref } }),
    uninstallServer: (name: string) =>
      request<void>(`/api/servers/${encodeURIComponent(name)}`, {
        method: "DELETE",
      }),

    listCredentials: () => request<Credential[]>("/api/credentials"),
    putCredential: (server: string, body: CredentialPutBody) =>
      request<void>(`/api/credentials/${encodeURIComponent(server)}`, {
        method: "PUT",
        json: body,
      }),
    deleteCredential: (server: string) =>
      request<void>(`/api/credentials/${encodeURIComponent(server)}`, {
        method: "DELETE",
      }),

    listUsers: () => request<User[]>("/api/users"),
    impersonate: (user_id: number, ttl_minutes: number) =>
      request<void>("/api/admin/impersonate", {
        method: "POST",
        json: { user_id, ttl_minutes },
      }),
    stopImpersonation: () =>
      request<void>("/api/admin/impersonate", { method: "DELETE" }),

    listAudit: (params: { before?: number; limit?: number; user_id?: number }) => {
      const q = new URLSearchParams();
      if (params.before) q.set("before", String(params.before));
      if (params.limit) q.set("limit", String(params.limit));
      if (params.user_id) q.set("user_id", String(params.user_id));
      const qs = q.toString();
      return request<AuditPage>(`/api/audit${qs ? `?${qs}` : ""}`);
    },
  };
  ```
- [ ] Create `web/lib/queries.ts` — TanStack hooks built on `api`:
  ```ts
  "use client";
  import {
    useQuery,
    useMutation,
    useQueryClient,
  } from "@tanstack/react-query";
  import { api } from "@/lib/api";
  import type { CredentialPutBody } from "@/lib/types";

  export const keys = {
    me: ["me"] as const,
    profiles: ["profiles"] as const,
    profile: (id: number) => ["profile", id] as const,
    servers: ["servers"] as const,
    credentials: ["credentials"] as const,
    users: ["users"] as const,
    audit: ["audit"] as const,
  };

  export const useMe = () =>
    useQuery({ queryKey: keys.me, queryFn: api.me, retry: false });

  export const useProfiles = () =>
    useQuery({ queryKey: keys.profiles, queryFn: api.listProfiles });
  export const useProfile = (id: number) =>
    useQuery({ queryKey: keys.profile(id), queryFn: () => api.getProfile(id) });

  export const useServers = () =>
    useQuery({ queryKey: keys.servers, queryFn: api.listServers });
  export const useCredentials = () =>
    useQuery({ queryKey: keys.credentials, queryFn: api.listCredentials });
  export const useUsers = () =>
    useQuery({ queryKey: keys.users, queryFn: api.listUsers });

  export function useInvalidate() {
    const qc = useQueryClient();
    return (key: readonly unknown[]) =>
      qc.invalidateQueries({ queryKey: key });
  }

  export const useCreateProfile = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: api.createProfile,
      onSuccess: () => qc.invalidateQueries({ queryKey: keys.profiles }),
    });
  };
  export const useDeleteProfile = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: api.deleteProfile,
      onSuccess: () => qc.invalidateQueries({ queryKey: keys.profiles }),
    });
  };
  export const useRenameProfile = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: ({ id, name }: { id: number; name: string }) =>
        api.renameProfile(id, name),
      onSuccess: (_d, v) => {
        qc.invalidateQueries({ queryKey: keys.profile(v.id) });
        qc.invalidateQueries({ queryKey: keys.profiles });
      },
    });
  };
  export const useSetProfileServers = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: ({ id, servers }: { id: number; servers: string[] }) =>
        api.setProfileServers(id, servers),
      onSuccess: (_d, v) => qc.invalidateQueries({ queryKey: keys.profile(v.id) }),
    });
  };
  export const useRotateToken = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: (id: number) => api.rotateProfileToken(id),
      onSuccess: (_d, id) => qc.invalidateQueries({ queryKey: keys.profile(id) }),
    });
  };

  export const useInstallServer = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: (ref: string) => api.installServer(ref),
      onSuccess: () => qc.invalidateQueries({ queryKey: keys.servers }),
    });
  };
  export const useUninstallServer = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: (name: string) => api.uninstallServer(name),
      onSuccess: () => qc.invalidateQueries({ queryKey: keys.servers }),
    });
  };

  export const usePutCredential = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: ({ server, body }: { server: string; body: CredentialPutBody }) =>
        api.putCredential(server, body),
      onSuccess: () => qc.invalidateQueries({ queryKey: keys.credentials }),
    });
  };
  export const useDeleteCredential = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: (server: string) => api.deleteCredential(server),
      onSuccess: () => qc.invalidateQueries({ queryKey: keys.credentials }),
    });
  };

  export const useImpersonate = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: ({ userId, ttl }: { userId: number; ttl: number }) =>
        api.impersonate(userId, ttl),
      onSuccess: () => qc.invalidateQueries(),
    });
  };
  export const useStopImpersonation = () => {
    const qc = useQueryClient();
    return useMutation({
      mutationFn: api.stopImpersonation,
      onSuccess: () => qc.invalidateQueries(),
    });
  };
  ```
- [ ] Create `web/app/providers.tsx` — QueryClient with the **401 → /login interceptor** and a global error toast:
  ```tsx
  "use client";
  import {
    QueryClient,
    QueryClientProvider,
    MutationCache,
    QueryCache,
  } from "@tanstack/react-query";
  import { useRouter } from "next/navigation";
  import { useState } from "react";
  import { Toaster } from "@/components/ui/sonner";
  import { toast } from "sonner";
  import { ApiError } from "@/lib/api";

  export function Providers({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const [client] = useState(() => {
      const onError = (err: unknown) => {
        if (err instanceof ApiError) {
          // Session gone (or control plane disabled probed via /api/me): bounce.
          if (err.status === 401) {
            router.replace("/login");
            return;
          }
          toast.error(err.message);
          return;
        }
        toast.error("Unexpected error");
      };
      return new QueryClient({
        queryCache: new QueryCache({ onError }),
        mutationCache: new MutationCache({ onError }),
        defaultOptions: { queries: { staleTime: 10_000, retry: false } },
      });
    });
    return (
      <QueryClientProvider client={client}>
        {children}
        <Toaster richColors position="top-right" />
      </QueryClientProvider>
    );
  }
  ```
- [ ] Replace `web/app/layout.tsx` (root) — dark, wraps `Providers`:
  ```tsx
  import type { Metadata } from "next";
  import "./globals.css";
  import { Providers } from "./providers";

  export const metadata: Metadata = {
    title: "gigmcp",
    description: "gigmcp control plane",
  };

  export default function RootLayout({
    children,
  }: {
    children: React.ReactNode;
  }) {
    return (
      <html lang="en" className="dark">
        <body className="bg-background text-foreground antialiased">
          <Providers>{children}</Providers>
        </body>
      </html>
    );
  }
  ```
- [ ] Create `web/components/app-sidebar.tsx` — Composio-style dark left rail; admin items gated on `role`:
  ```tsx
  "use client";
  import Link from "next/link";
  import { usePathname } from "next/navigation";
  import {
    LayoutDashboard, Boxes, Layers, KeyRound, Users, ScrollText, LogOut,
  } from "lucide-react";
  import { cn } from "@/lib/utils";
  import { Button } from "@/components/ui/button";
  import { api } from "@/lib/api";
  import { useRouter } from "next/navigation";

  const NAV = [
    { href: "/", label: "Overview", icon: LayoutDashboard, admin: false },
    { href: "/servers", label: "Servers", icon: Boxes, admin: false },
    { href: "/profiles", label: "Profiles", icon: Layers, admin: false },
    { href: "/credentials", label: "Credentials", icon: KeyRound, admin: false },
    { href: "/users", label: "Users", icon: Users, admin: true },
    { href: "/audit", label: "Audit", icon: ScrollText, admin: false },
  ];

  export function AppSidebar({ role }: { role: "admin" | "user" }) {
    const pathname = usePathname();
    const router = useRouter();
    const items = NAV.filter((n) => !n.admin || role === "admin");
    return (
      <aside className="flex h-screen w-60 shrink-0 flex-col border-r border-border bg-card">
        <div className="px-5 py-5 text-lg font-semibold tracking-tight">gigmcp</div>
        <nav className="flex-1 space-y-1 px-3">
          {items.map((n) => {
            const active = n.href === "/" ? pathname === "/" : pathname.startsWith(n.href);
            return (
              <Link
                key={n.href}
                href={n.href}
                className={cn(
                  "flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
                  active && "bg-accent text-foreground",
                )}
              >
                <n.icon className="h-4 w-4" />
                {n.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-border p-3">
          <Button
            variant="ghost"
            className="w-full justify-start gap-3 text-muted-foreground"
            onClick={async () => {
              await api.logout();
              router.replace("/login");
            }}
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </Button>
        </div>
      </aside>
    );
  }
  ```
- [ ] Create `web/components/impersonation-banner.tsx`:
  ```tsx
  "use client";
  import { Button } from "@/components/ui/button";
  import { useStopImpersonation } from "@/lib/queries";
  import type { Me } from "@/lib/types";

  export function ImpersonationBanner({ me }: { me: Me }) {
    const stop = useStopImpersonation();
    if (!me.impersonating || !me.real_user) return null;
    return (
      <div className="flex items-center justify-between gap-4 bg-amber-500/15 px-6 py-2 text-sm text-amber-200">
        <span>
          Viewing as <strong>{me.user.email}</strong> (you are{" "}
          {me.real_user.email}). All changes are blocked while impersonating.
        </span>
        <Button
          size="sm"
          variant="outline"
          disabled={stop.isPending}
          onClick={() => stop.mutate()}
        >
          Stop
        </Button>
      </div>
    );
  }
  ```
- [ ] Create `web/components/data-table.tsx` — a thin generic table over shadcn `Table` (columns: `{header, cell}`), and `web/components/confirm-dialog.tsx` — a reusable destructive confirm using shadcn `Dialog`. Keep both small and prop-driven; used by later tasks.
- [ ] Create `web/app/(app)/layout.tsx` — the **client-side auth gate** + shell:
  ```tsx
  "use client";
  import { useEffect } from "react";
  import { useRouter } from "next/navigation";
  import { useMe } from "@/lib/queries";
  import { AppSidebar } from "@/components/app-sidebar";
  import { ImpersonationBanner } from "@/components/impersonation-banner";
  import { Skeleton } from "@/components/ui/skeleton";

  export default function AppLayout({ children }: { children: React.ReactNode }) {
    const me = useMe();
    const router = useRouter();

    // Bounce to /login on ANY error from /api/me — including:
    //   • 401 unauthenticated (no/expired session)
    //   • 404 control_plane_disabled (OIDC not configured)
    //   • network / other failures
    // The /login page is the single place that renders the setup hint for the
    // disabled-state case. The global Providers error handler also catches 401s
    // from other queries, but this gate must not depend solely on that path.
    useEffect(() => {
      if (me.isError) {
        router.replace("/login");
      }
    }, [me.isError, router]);

    if (me.isLoading) {
      return (
        <div className="flex h-screen">
          <Skeleton className="h-screen w-60" />
          <div className="flex-1 p-8">
            <Skeleton className="h-8 w-48" />
          </div>
        </div>
      );
    }
    if (!me.data) return null; // redirect in flight (error path above fires)
    return (
      <div className="flex h-screen overflow-hidden">
        <AppSidebar role={me.data.user.role} />
        <div className="flex flex-1 flex-col overflow-hidden">
          <ImpersonationBanner me={me.data} />
          <main className="flex-1 overflow-y-auto p-8">{children}</main>
        </div>
      </div>
    );
  }
  ```
- [ ] Add a tiny page-header helper if useful, then verify: `(cd web && pnpm exec tsc --noEmit && pnpm run lint && pnpm run build)` green. (The `(app)` pages don't exist yet — create temporary placeholder `app/(app)/page.tsx` returning a heading so the route group builds; it's replaced in T4.)
- [ ] Commit: `feat(web): api client, query layer, dark shell, any-error auth gate`.

### T4 — Login screen + Overview

- [ ] `web/app/(auth)/login/page.tsx` — login button (full-page nav) + `control_plane_disabled` detection. Probe `/api/me` on mount; if it returns the `control_plane_disabled` code, show the setup hint instead:
  ```tsx
  "use client";
  import { useEffect, useState } from "react";
  import { Button } from "@/components/ui/button";
  import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
  import { Alert } from "@/components/ui/alert";
  import { api, ApiError } from "@/lib/api";

  export default function LoginPage() {
    const [disabled, setDisabled] = useState<string | null>(null);
    const [checked, setChecked] = useState(false);
    useEffect(() => {
      // If already signed in, /api/me 200s → go home. If the control plane is
      // off, the gateway returns 404 control_plane_disabled → show the hint.
      api
        .me()
        .then(() => {
          window.location.href = "/";
        })
        .catch((e) => {
          if (e instanceof ApiError && e.code === "control_plane_disabled") {
            setDisabled(e.message);
          }
        })
        .finally(() => setChecked(true));
    }, []);
    return (
      <div className="flex min-h-screen items-center justify-center bg-background p-6">
        <Card className="w-full max-w-sm">
          <CardHeader>
            <CardTitle className="text-center">Sign in to gigmcp</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {disabled ? (
              <Alert variant="destructive">
                <p className="text-sm">{disabled}</p>
              </Alert>
            ) : (
              <Button
                className="w-full"
                disabled={!checked}
                onClick={() => {
                  // Full-page navigation, NOT fetch: the browser must follow the
                  // 302 → Zitadel → callback (Set-Cookie) → 302 / chain itself.
                  window.location.href = "/api/auth/login";
                }}
              >
                Continue with Zitadel
              </Button>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }
  ```
- [ ] `web/app/(app)/page.tsx` — Overview: counts (profiles, servers, credentials; users + admin only) as `Card`s, plus a "Recent activity" table from `useQuery(keys.audit, () => api.listAudit({ limit: 10 }))` rendering `events` with kind/decision `Badge`s. Use `useMe()` for the user greeting and admin gating of the users count card.
- [ ] Verify build green. Manually sanity: with the gateway up + OIDC unset, `/login` shows the setup hint.
- [ ] Commit: `feat(web): login (with control_plane_disabled hint) + overview`.

### T5 — Servers screen

- [ ] `web/app/(app)/servers/page.tsx`:
  - List installed servers (`useServers()`) in a table (name + id).
  - "Install" button → `Dialog` with a single `ref` input → `useInstallServer()`; on success toast + close; surface `install_failed`/`501` messages via the global error toast (already wired). **Admin-only**: hide the Install button + per-row Uninstall unless `useMe().data.user.role === "admin"`.
  - Per-row "Uninstall" → `confirm-dialog` → `useUninstallServer(name)`.
- [ ] Verify build green.
- [ ] Commit: `feat(web): servers list + install/uninstall (admin-gated)`.

### T6 — Profiles list + detail

- [ ] `web/components/token-reveal-dialog.tsx` — a controlled `Dialog` that shows a one-time token (monospace, read-only `Input`), a "Copy" button (`navigator.clipboard.writeText` + toast), and a warning that it won't be shown again. Props: `{open, token, onClose}`.
- [ ] `web/app/(app)/profiles/page.tsx`:
  - List profiles (`useProfiles()`): name, slug, endpoint, server count; row links to `/profiles/[id]`.
  - "Create profile" `Dialog` (name + slug inputs) → `useCreateProfile()`; on success, open `token-reveal-dialog` with the returned `profile.token`, then invalidate. Show inline 400/409 messages (`invalid`/`conflict`) from `ApiError`.
- [ ] `web/app/(app)/profiles/[id]/page.tsx`:
  - `useProfile(id)` detail. Show endpoint URL `/mcp/p/<slug>` with a copy button.
  - **Bundle editor**: checklist of installed servers (`useServers()`), each a `Checkbox` checked when in `profile.servers`; "Save bundle" → `useSetProfileServers({id, servers})`.
  - **Rename**: inline name field → `useRenameProfile`.
  - **Rotate token**: button → `useRotateToken(id)` → open `token-reveal-dialog` with the new `token`.
  - **Delete**: `confirm-dialog` → `useDeleteProfile(id)` → `router.push("/profiles")`.
  - Read `id` via `useParams()`; coerce to number.
- [ ] Verify build green.
- [ ] Commit: `feat(web): profiles list + detail (bundle editor, one-time token, rotate, delete)`.

### T7 — Credentials screen

- [ ] `web/app/(app)/credentials/page.tsx`:
  - List credential metadata (`useCredentials()`): server, inject_header, placeholder, allowed_hosts count. **Never** a secret.
  - "Add / update credential" `Dialog` with a PUT form: required `secret` (`type="password"`, textarea acceptable since secrets can be long JSON), `server` input (regex-hinted), and a collapsible **"Advanced (transitional)"** `Separator`-divided section with `inject_header`, `inject_format` (hint: must contain `{token}`), `placeholder` (8–256), `allowed_hosts` (comma/newline-split into `string[]`). Submit → `usePutCredential({server, body})`; omit empty optional fields. Surface 400 `invalid` messages (form-level) from `ApiError`.
  - Per-row "Delete" → `confirm-dialog` → `useDeleteCredential(server)`.
- [ ] Verify build green.
- [ ] Commit: `feat(web): credentials write-only PUT form + metadata list + delete`.

### T8 — Users + impersonation

- [ ] `web/app/(app)/users/page.tsx` (admin route; the nav item is already gated, and the API 403s non-admins — so render an "Admins only" message if `role !== "admin"`):
  - `useUsers()` table: email, display_name, role `Badge`.
  - Per-row "Impersonate" (hidden for self via `useMe()` real user id) → small dialog choosing `ttl_minutes` (default 30, max 60) → `useImpersonate({userId, ttl})`; on success the global `invalidateQueries()` re-runs `/api/me`, the banner appears, and mutating controls disable.
  - Stop is handled by the banner (T3).
- [ ] Verify build green.
- [ ] Commit: `feat(web): users list + impersonation start (admin)`.

### T9 — Audit screen

- [ ] `web/app/(app)/audit/page.tsx`:
  - Keyset table using local state for accumulated rows + the current `before` cursor. First load `api.listAudit({ limit: 50 })`; "Load more" calls `api.listAudit({ before: nextBefore, limit: 50 })` and appends `events`; hide the button when `next_before === 0`. (Use `useQuery` for page 1 and a manual `useState`-driven accumulator + `useMutation`/`refetch` pattern, or `useInfiniteQuery` keyed on `before` with `getNextPageParam: (last) => last.next_before || undefined` — prefer `useInfiniteQuery`.)
  - Columns: ts (formatted), kind `Badge` (egress/auth/admin → color variants), decision `Badge`, server/host, detail.
  - Admins (non-impersonating) get a `user_id` filter input; non-admins see only their own (server-enforced — no client gate needed).
- [ ] Verify build green.
- [ ] Commit: `feat(web): audit table with keyset load-more (before cursor) + badges`.

### T10 — Dockerfile + compose `web` service

- [ ] `web/.dockerignore`:
  ```
  node_modules
  .next
  npm-debug.log
  .git
  ```
- [ ] `web/Dockerfile` — multi-stage pnpm build → Next standalone:
  ```dockerfile
  # syntax=docker/dockerfile:1
  FROM node:22-alpine AS deps
  WORKDIR /app
  RUN corepack enable
  COPY package.json pnpm-lock.yaml ./
  RUN pnpm install --frozen-lockfile

  FROM node:22-alpine AS builder
  WORKDIR /app
  RUN corepack enable
  COPY --from=deps /app/node_modules ./node_modules
  COPY . .
  # GATEWAY_INTERNAL_URL is read at runtime by next.config rewrites, not baked.
  RUN pnpm run build

  FROM node:22-alpine AS runner
  WORKDIR /app
  ENV NODE_ENV=production
  ENV PORT=3000
  ENV HOSTNAME=0.0.0.0
  COPY --from=builder /app/public ./public
  COPY --from=builder /app/.next/standalone ./
  COPY --from=builder /app/.next/static ./.next/static
  EXPOSE 3000
  CMD ["node", "server.js"]
  ```
- [ ] Build the image to prove the standalone output works:
  ```bash
  docker build -t gigmcp-web ./web
  ```
  Expected: image builds; `server.js` present in standalone.
- [ ] Add the `web` service to `docker-compose.yml` (alongside `gateway`):
  ```yaml
    web:
      build: ./web
      ports:
        - "3000:3000"
      environment:
        # Server-side rewrite target; service DNS resolves to the gateway.
        GATEWAY_INTERNAL_URL: http://gateway:8080
      depends_on:
        - gateway
  ```
  (Reminder: for the OIDC callback to land back on the right origin, the gateway's `GIG_OIDC_REDIRECT_URL` / `GIG_PUBLIC_URL` should point at the browser-facing origin, i.e. `http://localhost:3000` when the dashboard is the entry point. Note this in the compose comment; no code change needed in `web/`.)
- [ ] Verify: `(cd web && pnpm exec tsc --noEmit && pnpm run lint && pnpm run build)` green; `docker compose config` parses.
- [ ] Commit: `feat(web): Dockerfile (standalone) + compose web service on :3000`.

### T11 — Final polish + verification

- [ ] Empty/loading/error states: every list page renders a `Skeleton` while loading and an empty-state line when the list is `[]`.
- [ ] Mutation buttons disable while `isPending`; confirm dialogs disable their confirm button while pending.
- [ ] While impersonating (`me.impersonating`), disable all mutating controls across screens (pass a `readOnly` flag down from the `(app)` layout via context or a small `useMe()` check in each mutation component) — the API 403s anyway, but the UI should not invite the failure.
- [ ] Final verification, all green:
  ```bash
  (cd web && pnpm exec tsc --noEmit && pnpm run lint && pnpm run build && docker build -t gigmcp-web .)
  ```
- [ ] Self-review pass: every spec-§8 screen present; zero placeholders; route/shape match the as-built cheat sheet above.
- [ ] Commit: `chore(web): polish loading/empty/error + impersonation read-only guard`.

---

## Coordination notes

- **Why no CORS:** every browser request hits the Next origin (`:3000`); `next.config` `rewrites` reverse-proxy `/api/*` and `/mcp/*` to the gateway **server-side**. From the browser's perspective the request is same-origin, so the `gig_session` cookie (Path `/`, httpOnly, SameSite=Lax, set by the gateway callback) is attached automatically and forwarded by Next. No `Access-Control-*` headers and no `credentials:'include'` cross-origin handling are needed anywhere.
- **Login must be a navigation, not a fetch:** `/api/auth/login` 302s to Zitadel and the whole chain ends with a `Set-Cookie` + 302 `/`. `fetch` cannot follow a cross-site auth redirect and set a top-level cookie, so the login button uses `window.location.href`.
- **Component tests are out of scope for v1** (per the brief): verification is `tsc --noEmit` + lint + `next build` (+ `docker build` in T10/T11). Playwright/unit deferred.
- **Transitional credential fields** (`inject_header`/`inject_format`/`placeholder`/`allowed_hosts`) live behind an "Advanced (transitional)" disclosure; when the registry manifest sourcing lands and the PUT body shrinks to `{secret}`, delete that section only.
