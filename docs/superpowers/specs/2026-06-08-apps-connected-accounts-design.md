# Apps & Connected Accounts — Design Spec

**Status:** Approved (brainstorm), pending implementation plan
**Date:** 2026-06-08
**Goal:** Evolve the Gig'MCP dashboard toward a Composio-style product — a friendlier Apps catalog, a stats-driven Overview, and a per-user **Connected Accounts** subsystem (API-key today, OAuth broker added) — while keeping Gig'MCP's security model (sandboxed execution, egress MITM proxy, secrets injected at the network boundary, vault encryption).

---

## 1. Background & motivation

Compared against Composio's dashboard, Gig'MCP already has every concept Composio exposes — sometimes with better bones — but the vocabulary and UX are developer-facing. This redesign makes it legible to a normal user and adds the one capability we lack: brokered third-party auth (OAuth) so apps like Gmail can be connected with a click.

A registry survey (221 connectors) established the key facts this design relies on:

- **Auth is already declared per connector.** Each manifest carries a `credentials[]` block: `type` ∈ {`none`, `api_key`, `basic`, `oauth2`}, `provider`, `scopes`, and an `inject` spec (header/format or env). Distribution: **1 none, 111 api_key, 7 basic, 102 oauth2.**
- **OAuth collapses to ~76 vendor registrations.** The 102 oauth2 connectors map to 76 distinct OAuth clients; the top 6 vendor apps (Google, Zoho, Microsoft, Atlassian, Meta, Slack) cover 32 connectors.
- **Registry gaps (coordination, not blockers):** OAuth *flow* endpoints + client_id are absent (and must be operator-side anyway), `provider` is the connector slug rather than a shared vendor identity, and there is **no branding** (icon/displayName/description/category) on any manifest.

## 2. Naming & information architecture

| Old | New | Notes |
|---|---|---|
| Servers | **Apps** | An integration = one MCP server. "Tools" stays reserved for the actions an app exposes (matches MCP + Composio). |
| Credentials | **Connected Accounts** | Where both OAuth connections and API keys live, per user. |
| Profiles | **Profiles** (unchanged) | Named, scoped MCP endpoints bundling apps. Our differentiator. |

**Nav:** Overview · Apps · Profiles · Connected Accounts · Users *(admin)* · Audit.

- **Apps page** shows **installed apps only**, for everyone. Cards show icon + name + category + auth badge + state-aware action. Admins get an **"Install app"** button opening a **registry-browser modal** (icons; the ~215 uninstalled apps; *Install* pulls the OCI image — admin-gated).
- **App detail page** — header (icon/name/category/description/auth badge), a **connect block auto-rendered from the manifest's auth type**, a **"Network access (enforced)"** panel (manifest egress hosts + "your token is injected at the proxy; the sandboxed app never sees it"), an **Available tools** list, and **Use in profiles** checkboxes.
- **Connected Accounts page** — manage your connections (OAuth per-vendor, API-key per app/vendor) with status.
- **Overview** — stat row (Tool calls / Apps / Connected / Profiles) → full-width **activity heatmap** → two columns (Recent activity + Suggested apps). All derived from the audit log.

## 3. Roles

- **Admin:** install/uninstall apps (OCI pull), manage **Auth Configs** (provider client credentials), plus everything a user can do.
- **User:** connect their own accounts, add apps to their own profiles, manage their own connected accounts. Users never install apps; uninstalled apps are not shown to them.

## 4. Data model

Three concepts; two evolve what exists.

### 4.1 Auth Config *(new; deployment-level; admin/operator)*
One row per OAuth **vendor**:
```
vendor          TEXT   -- canonical: google | microsoft | slack | atlassian | zoho | meta | notion | ...
authorize_url   TEXT
token_url       TEXT
client_id       TEXT
client_secret   BLOB   -- vault-encrypted
default_scopes  TEXT   -- space/comma list
pkce            BOOL
mode            TEXT   -- managed | byo
```
- **Managed** rows are seeded by the hosted operator (our verified OAuth apps). **BYO** rows are entered by self-hosters (their own Google project, etc.).
- **Bootstrap:** a single global provider may be set via `.env` (e.g. `GIG_OAUTH_GOOGLE_CLIENT_ID/SECRET/...`); the DB table is the scalable home and the source of truth when present.
- Client credentials are **operator-side by necessity** (managed = our secrets, BYO = the self-hoster's) and therefore never live in the shared/public registry.

### 4.2 Connected Account *(evolves today's Credentials; per-user)*
- **OAuth kind** — keyed by **vendor**, so one row covers all of that vendor's apps:
  ```
  user_id, vendor, refresh_token (vault), access_token (vault, cached),
  expires_at, granted_scopes
  ```
- **API-key / basic kind** — essentially today's credential, relabeled:
  ```
  user_id, app (or vendor), secret (vault), inject-spec (from manifest)
  ```

### 4.3 Manifest *(existing + registry additions)*
Already declares `type/provider/scopes/inject`. Registry **adds** (coordination track): canonical **vendor** identity and **branding** (`icon`, `displayName`, `description`, `category`). OAuth flow endpoints + client creds stay operator-side.

### 4.4 Resolver mapping (reuses the proxy-injection layer)
At resolve time, keyed by `(app, user)`:
- `oauth2` → look up the user's Connected Account for the manifest's **vendor**; ensure a fresh access token (refresh via Auth Config if expired); return a `proxy.Credential` injecting `Authorization: Bearer <token>` with `AllowedHosts` = manifest entitlements.
- `api_key` / `basic` → today's static-secret injection, keyed to the user's account.
- `none` → credential-less egress (the manifest-entitlement path already shipped).

In every case the secret/token is **injected at the egress proxy and never enters the sandbox**.

## 5. OAuth broker flow

Generalizes the existing Zitadel OIDC machinery (state, PKCE, nonce, callback) to arbitrary providers configured per Auth Config.

1. User clicks **Connect <vendor>** (app detail page or Connected Accounts).
2. Gateway computes required scopes = union of the relevant apps' manifest scopes for that vendor (start with this app's scopes).
3. Redirect to the vendor's `authorize_url` with `client_id`, the gateway callback `redirect_uri`, scopes, `state` + PKCE.
4. Consent → `/api/connections/callback` exchanges the code at `token_url` → store `refresh_token` + `access_token` (vault) + `granted_scopes` on the per-vendor Connected Account.
5. **Incremental consent:** adding a new app for an already-connected vendor whose scopes exceed `granted_scopes` triggers a re-prompt with the scope union.
6. **Refresh:** on use, if `access_token` is expired, mint a new one from `refresh_token` + the Auth Config client creds; update the cached token + `expires_at`.

## 6. Proxy token injection

The resolver supplies the egress proxy a `Credential` per outbound request (existing mechanism). For OAuth, the "secret" is the **current** access token, fetched/refreshed at resolve time. The sandboxed app sends a placeholder `Authorization` header; the proxy swaps in the real bearer on the way out. Long-lived sessions are handled because resolution is per-request (refresh-on-expiry, or refresh-on-upstream-401 as a fallback). This extends — rather than replaces — the static-secret injection already in place, and preserves the property that **no third-party token is ever present inside the sandbox**.

## 7. Overview statistics

All derived from the `audit` table:
- **Tool calls** — count of tool-call/egress events for the user.
- **Most-used app** — group-by server.
- **Activity heatmap** — per-day counts over a trailing window.
- **Connected / Apps / Profiles** — counts.
- **Suggested apps** — a curated slice of the installed/available catalog.

If a discrete per-tool-call audit event does not already exist, add one (egress events exist today; tool-call granularity may need a new audit kind).

## 8. Registry coordination (parallel track, registry team owns)

A requirements note to the registry/toolpack workstream:
1. **Vendor identity:** add a canonical `vendor` to OAuth credentials (or normalize `provider`), keeping per-connector `scopes`, so a vendor's many connectors map to one Auth Config.
2. **Branding:** optional `icon` (recommended: repo-hosted `icons/<slug>.svg` for signed provenance over third-party URLs), plus `displayName`, `description`, `category`.
3. **Explicitly out of registry:** OAuth flow endpoints and client credentials (operator-side).

The dashboard degrades gracefully where branding is absent (fallback to a generated monogram icon and the slug as name).

## 9. Phasing (within this single spec)

- **P1 — UI/IA + non-OAuth Connected Accounts (ships without registry changes):**
  rename Servers→Apps & Credentials→Connected Accounts; new Overview; installed-only catalog + admin install modal; app detail page; **API-key/basic + no-auth Connected Accounts working end-to-end** (uses existing proxy injection). OAuth apps render a "Connect (coming soon)" state until P2.
- **P2 — OAuth broker:** Auth Configs (managed seed + BYO + `.env` bootstrap), connect flow, token storage + refresh, per-vendor accounts, incremental consent, proxy bearer injection. Managed top-vendor seeding lands as each provider passes security review.
- **Registry coordination** (icons + vendor identity) runs alongside; P1 consumes branding opportunistically as it appears.

## 10. Security

- Auth Config client secrets and all OAuth refresh/access tokens are **vault-encrypted** (existing XChaCha20-Poly1305 envelope).
- Tokens/secrets are **injected at the egress proxy**; they never enter the sandbox environment.
- OAuth flows use `state` + PKCE + `nonce` (reusing the OIDC implementation's patterns).
- **Scope minimization:** request only the scopes the manifests declare.
- Admin-gated: Auth Config management and app installation.
- Egress remains default-deny, scoped to each manifest's declared entitlement hosts.

## 11. Testing strategy

- **Unit:** Auth Config CRUD + vault round-trip; token refresh (expired → minted); scope union / incremental-consent decision; resolver OAuth path (per-vendor lookup → bearer credential); proxy injection with an empty-placeholder swap.
- **Integration / E2E:** a **fake OAuth provider** fixture (mirroring the test OIDC issuer) — connect a vendor, call a tool, and assert the **upstream receives the real bearer while the sandbox process never held the token**; plus default-deny egress for a non-entitled host.
- **UI:** catalog state-machine rendering (each auth type → correct connect block), admin-vs-user gating, i18n completeness for new strings across all five locales.

## 12. Open items / non-goals

- **Non-goals (this spec):** multi-credential-per-app rewrite; org/team-shared connected accounts (per-user only for now); non-OAuth/non-key auth schemes (`custom_env` is declared but unused in the corpus).
- **Dependencies:** P2 managed one-click depends on external provider verification timelines; registry branding/vendor fields depend on the registry team.
