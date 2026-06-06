# gigemcp — Design Decision Record

> Open-source, security-first MCP gateway: a marketplace-backed runtime that runs
> community MCP servers **sandboxed**, with **credential injection at the network
> boundary**, so one compromised MCP tool can never expose your keys.
>
> Produced from a /grill-me design interview, 2026-06-06.

---

## 1. Vision & Positioning

**Problem.** MCP management is disjointed (per-client config sprawl) and MCP servers
are a security liability: today every server you install holds your raw API keys and
has unrestricted network/filesystem access. Composio solves the management/auth side
but is closed-source and does not run third-party code at all (see §6).

**Product.** An open-source (AGPL-3.0) gateway that:
- aggregates MCP servers behind one endpoint per *profile*,
- runs each community server in a kernel-enforced sandbox,
- keeps credentials **outside** the sandbox, injected per-tenant at an egress proxy,
- is fed by a curated, digest-pinned manifest registry (the future marketplace).

**Key differentiator vs Composio:** Composio's security model is "we wrote all the
connectors, trust us." gigemcp's model is "run *anyone's* server; the sandbox and
proxy make trust unnecessary." Credentials can also stay entirely on user hardware
(self-host), which Composio cannot offer.

---

## 2. Decision Summary

| # | Decision | Choice |
|---|----------|--------|
| 1 | v1 product slice | Secure runtime/gateway. Marketplace UI deferred (registry repo is the interim marketplace). |
| 2 | Deployment target | Docker-native from the start; Linux-only runtime. Runs on homelab/VPS; on Mac dev machines it runs inside Docker. |
| 3 | Sandbox provisioning | **No Docker socket.** Gateway spawns MCP servers as bwrap-style sandboxed child processes inside its own container (user/pid/mount/net namespaces + seccomp + Landlock + cgroups). Requires a documented custom seccomp profile allowing unprivileged user namespaces. |
| 4 | Hosted product shape | Hosted control plane is fine holding keys (users who object can self-host). Same codebase self-hosts. |
| 5 | Multi-tenancy granularity | Shared **code/image**, never shared **process**: one sandboxed instance per (server × user/profile), idle-reaped, spawned in milliseconds. |
| 6 | Credential model | **Tier 1 "Sealed"** (default): placeholder token in sandbox env; embedded MITM egress proxy swaps in the real key per tenant. Key never enters the sandbox. **Tier 2 "Entrusted"**: real secret in sandbox env (DB strings, cert-pinned clients), egress allowlist still applies. **Tier 3 / local-resource servers: out of scope** (catalog targets SaaS APIs: Ubiquiti, Google, Slack, GitHub...). |
| 7 | Entitlements manifests | Author-declared, PR-gated into a registry repo (owner approves), enforced as a hard cap by the proxy. Lint CI blocks wildcards/known exfil domains. Manifest changes on update ⇒ re-consent. |
| 8 | Registry topology | GitHub org, two repos: `gigemcp` (gateway monorepo) + `gigemcp-registry` (manifests). CI compiles manifests → **signed `index.json`** artifact; runners consume the index, never the raw repo. |
| 9 | Packaging | **OCI images**, built by registry CI from the author's tagged source, **pinned by digest** in the manifest. Runner pulls, verifies digest, extracts rootfs, runs entrypoint under bwrap. `npx`/`uvx` only as a clearly-marked untrusted self-host escape hatch (post-v1). |
| 10 | Credential acquisition | v1: BYO keys + BYO OAuth apps (client id/secret via compose env / `*_FILE` Docker secrets), runner executes the OAuth flow, per-provider setup guides. Hosted managed OAuth broker later — manifest credential schema is source-agnostic so it bolts on. |
| 11 | Client surface | One streamable-HTTP MCP endpoint per **profile** (`/mcp/p/<profile>`), per-profile bearer tokens. Meta-tools mode (search/load tools) as per-profile opt-in flag. Manifests mark tools `default: true/false` so installs expose a curated subset (Composio-style). |
| 12 | Gateway language | **Go.** Single static binary, scratch image. |
| 13 | Egress proxy | **Embedded** in the gateway binary (martian/goproxy MITM). Identity binding is network-level: each sandbox netns gets a unique veth/IP recorded at spawn; proxy resolves `source IP → (server, user, profile)` — unforgeable from inside the sandbox. Per-request audit log falls out of this lookup. CA cert injected via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`. |
| 14 | Storage | Repository interface with **SQLite** (zero-config default) and **Postgres** drivers. Rule: no Postgres-only features in core. |
| 15 | Vault encryption | Envelope encryption: per-secret DEKs, XChaCha20-Poly1305 (libsodium primitives via `golang.org/x/crypto`), wrapped by master KEK from `GIGE_MASTER_KEY` env / `_FILE` secret. Versioned key IDs in ciphertext header for rotation. KEK never in DB. |
| 16 | License & protection | **Unmodified AGPL-3.0** (gateway/control plane). Name/logo protected by **trademark policy** (TRADEMARK.md; register later), not license edits. **DCO** for contributions; copyright kept concentrated to preserve dual-licensing of the hosted product. Apache-2.0 for manifest schema/SDKs when they exist. |
| 17 | Frontend | **Next.js** dashboard as pure frontend (separate `web` container). Visual style: model after **Composio's dashboard UI**. Astro reserved for future marketing/docs/marketplace static site. |
| 18 | Auth | Go gateway is the **sole auth authority**: local email+password + generic **OIDC client** (`coreos/go-oidc`) covering social login (Google/GitHub) and enterprise SSO (Okta/Entra/Authentik/Authelia) with one config block. Go issues httpOnly session after OIDC callback; Next.js forwards it. No Auth.js session ownership. |
| 19 | Multi-user | Multi-user **in v1**: `user_id` on every table, roles `admin`/`user`, OIDC + local login, admin user management, invitations. |
| 20 | Impersonation | **Config-only (option B)**: admin sees the user's view (profiles, server status, logs) but cannot execute tools or touch secrets. Time-boxed, banner-visible, loud audit event visible to the impersonated user too. Full impersonation = deliberate org-level toggle, off by default, post-v1. |

---

## 3. Architecture

```
                            ┌──────────────────────────── docker compose ───────────────────────────┐
                            │                                                                        │
 Claude Code / Cursor ──────┼─▶ :443 /mcp/p/<profile>   ┌────────────── gateway (Go, 1 binary) ───┐ │
   (bearer token,           │                           │  MCP aggregator / router                 │ │
    streamable HTTP)        │                           │  Auth authority (OIDC client, sessions)  │ │
                            │                           │  REST API  ◀──────────────┐              │ │
 Browser ───────────────────┼─▶ web (Next.js, pure FE) ─┼──────────────────────────┘              │ │
                            │                           │  Vault (envelope enc, SQLite/Postgres)   │ │
                            │                           │  Supervisor ──spawns──▶ sandboxes        │ │
                            │                           │  Egress MITM proxy ◀──only route── netns │ │
                            │                           └───────────┬───────────────┬──────────────┘ │
                            │                                       │ veth/IP per   │                │
                            │                          ┌────────────▼───┐  ┌────────▼───────┐        │
                            │                          │ slack-mcp      │  │ unifi-mcp      │  ...   │
                            │                          │ (user A inst.) │  │ (user A inst.) │        │
                            │                          │ bwrap: userns/ │  │  placeholder   │        │
                            │                          │ netns/seccomp/ │  │  token only    │        │
                            │                          │ landlock/cgroup│  │                │        │
                            │                          └────────────────┘  └────────────────┘        │
                            └────────────────────────────────────────────────────────────────────────┘

 gigemcp-registry repo ──CI──▶ lint manifests ▶ build OCI images ▶ sign index.json ──▶ runner pulls by digest
```

**Request flow (Tier 1):** client calls tool → gateway routes to the user's sandbox
instance (spawning it if cold) → server code makes HTTPS call with placeholder token →
only route is the proxy → proxy resolves identity from source IP → checks domain against
manifest allowlist → swaps placeholder for the user's real key from the vault → forwards
→ logs (user, server, domain, method, ts) to audit log.

**Threat model in one line:** gateway is trusted infrastructure; MCP servers are
untrusted; the kernel (namespaces/seccomp/Landlock) is the boundary between them; keys
live only on the trusted side.

**Known residual risks (accepted, documented):**
- Tier 2 servers can exfiltrate their own secret *through* an allowed domain (e.g. write it into a gist). Tier label surfaces this.
- Shared-kernel isolation: a kernel 0-day breaks tenant separation. Acceptable for self-host / curated catalog; revisit (gVisor/microVMs) if hosting truly hostile workloads.
- Compose env vars are visible via `docker inspect`; `*_FILE` secrets supported for everything sensitive.

---

## 4. Manifest schema (sketch)

```yaml
name: slack-mcp
version: 1.4.2
source:
  repo: github.com/author/slack-mcp
  tag: v1.4.2
image:
  ref: ghcr.io/gigemcp/slack-mcp
  digest: sha256:…            # what was approved is what runs
tier: sealed                   # sealed | entrusted
entitlements:
  egress:
    - slack.com
    - "*.slack.com"            # wildcards lint-restricted to single-suffix
credentials:
  - id: slack_bot_token
    type: oauth2               # oauth2 | api_key | basic | custom_env
    provider: slack
    scopes: [chat:write, channels:read]
    inject:                    # how the proxy rewrites (Tier 1)
      header: Authorization
      format: "Bearer {token}"
tools:
  - name: send_message
    default: true
  - name: admin_set_workspace_settings
    default: false
```

Registry CI lints: no bare `*` egress, denylist (pastebin/webhook.site/raw IPs/...),
digest present, schema valid. Manifest diff on version bump ⇒ runner forces re-consent.

---

## 5. v1 Scope (single release — deliberately large, per owner's call)

1. Go gateway: streamable-HTTP MCP endpoint, profile routing, per-profile bearer tokens
2. Sandbox runtime: OCI pull → digest verify → rootfs extract → bwrap spawn; per (server×user×profile) instances; idle reaping
3. Embedded egress proxy: IP identity binding, allowlists, Tier-1 injection, Tier-2 env injection, audit log
4. Vault: envelope encryption; SQLite + Postgres backends
5. `gigemcp-registry`: schema, lint CI, image build CI, signed `index.json`, ~8–10 launch manifests (Ubiquiti, Slack, GitHub, Google, …)
6. Auth & multi-user: OIDC + local login, admin/user roles, user management, invitations, config-only impersonation
7. Next.js dashboard: servers, profiles, credentials (incl. BYO OAuth flow), users/admin, audit log — ruthlessly minimal
8. BYO OAuth: provider client id/secret via compose env / Docker secrets; per-provider setup guides
9. Compose file: `gateway` + `web` (+ optional `postgres`)

**Known follow-ups (from skeleton code review):** `gateway.New` needs tool-namespace
collision handling once multiple backends exist — reject/deduplicate duplicate backend
names and backend names containing `_` (ambiguous `backend_tool` parsing). Deferred to the
multi-backend/registry plan; harmless at skeleton stage (single hardcoded backend).

**Explicit roadmap (NOT v1):** hosted control plane & managed OAuth broker, marketplace
website, meta-tools mode default-on, npx escape hatch, full impersonation toggle,
groups/RBAC beyond two roles, gVisor/microVM isolation option, trademark registration.

---

## 6. How Composio actually works (competitive note)

Composio does not run third-party code. Its catalog is first-party declarative
connectors: a "tool" is a schema mapping to an HTTP call; their shared backend executes
it, injecting the user's OAuth token from their managed store. Isolation is logical, not
physical — defensible only because no untrusted code executes; also why it's cheap.
Their MCP product is C-shaped (dashboard-configured tool subsets per endpoint); their
Rube product is D-shaped (universal meta-tool router). Their moat is ~300 verified OAuth
apps — bureaucracy, not code. gigemcp's answers: sandbox makes untrusted code safe
(breadth they can't match), BYO-then-broker neutralizes the OAuth moat over time,
AGPL + self-host neutralizes the trust objection.

---

## 7. Build order — walking skeleton first

Integration is the long pole, not code volume. Build a thread through everything
before deepening any subsystem:

1. **Skeleton:** gateway binary serving one MCP endpoint, spawning one hardcoded echo
   server under bwrap, SQLite, one static bearer token. Claude Code connects end-to-end.
   (Runs inside a Linux container on the dev Mac — bwrap/netns/Landlock don't exist on
   macOS; the whole integration test suite is container-native.)
2. **Proxy:** netns-per-sandbox + veth identity + allowlist + Tier-1 swap against a
   real API (GitHub PAT is the easiest first target).
3. **Vault & manifests:** envelope encryption; manifest schema; runner consumes a local
   `index.json`.
4. **Registry pipeline:** `gigemcp-registry` CI — lint, image build, sign, publish index.
5. **Auth & multi-user:** OIDC, sessions, roles, REST API.
6. **Dashboard:** Next.js against the API.
7. **Hardening pass:** Tier-2, OAuth BYO flow, impersonation-B, audit UI, idle reaping,
   seccomp profile docs, threat-model doc.

Repo layout: monorepo `gigemcp/` → `cmd/gateway/`, `internal/{mcp,sandbox,proxy,vault,auth,store,registry}/`,
`web/` (Next.js), `deploy/` (compose, seccomp profile), `docs/`.
