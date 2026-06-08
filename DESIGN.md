# Gig'MCP — Design Decision Record

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
connectors, trust us." Gig'MCP's model is "run *anyone's* server; the sandbox and
proxy make trust unnecessary." Credentials can also stay entirely on user hardware
(self-host), which Composio cannot offer.

---

## 2. Decision Summary

| # | Decision | Choice |
|---|----------|--------|
| 1 | Product slice | Secure runtime/gateway. Marketplace UI deferred (registry repo is the interim marketplace). |
| 2 | Deployment target | Docker-native from the start; Linux-only runtime. Runs on homelab/VPS; on Mac dev machines it runs inside Docker. |
| 3 | Sandbox provisioning | **No Docker socket.** Gateway spawns MCP servers as bwrap sandboxed child processes inside its own container (user/pid/mount/net namespaces + seccomp + Landlock + cgroups). Requires `seccomp=unconfined`/`systempaths=unconfined` (until a custom seccomp profile allowing unprivileged userns ships — see the SECCOMP STATUS note in §3). **Egress networking validated NET_ADMIN-only (no SYS_ADMIN, no privileged):** bwrap creates the netns via userns (`--unshare-net`); the gateway uses `--userns-block-fd` to pause the child, writes a uid/gid map covering uids 0..65534 to `/proc/<child>/uid_map` + `gid_map` (enabling both uid 0 for bootstrap's CAP_NET_ADMIN and uid 65534 for the server), then unblocks the child; moves a veth into the bwrap child's netns by host PID via `LinkSetNsPid` (avoids the named-netns bind-mount that needs SYS_ADMIN); and a trusted in-sandbox bootstrap (`cmd/bootstrap`) configures the link + default route, drops **all** caps (`CapEff=0`), drops to uid/gid 65534 (nobody), and `execve`s the untrusted server. **The server process runs as uid 65534 with zero capabilities — verified.** |
| 4 | Hosted product shape | Hosted control plane is fine holding keys (users who object can self-host). Same codebase self-hosts. |
| 5 | Multi-tenancy granularity | Shared **code/image**, never shared **process**: one sandboxed instance per (server × user/profile), idle-reaped, spawned in milliseconds. |
| 6 | Credential model | **Tier 1 "Sealed"** (default): placeholder token in sandbox env; embedded MITM egress proxy swaps in the real key per tenant. Key never enters the sandbox. **Tier 2 "Entrusted"**: real secret in sandbox env (DB strings, cert-pinned clients), egress allowlist still applies. **Tier 3 / local-resource servers: out of scope** (catalog targets SaaS APIs: Ubiquiti, Google, Slack, GitHub...). |
| 7 | Entitlements manifests | Author-declared, PR-gated into a registry repo (owner approves), enforced as a hard cap by the proxy. Lint CI blocks wildcards/known exfil domains. Manifest changes on update ⇒ re-consent. |
| 8 | Registry topology | GitHub org, two repos: `gigmcp` (gateway monorepo) + `gigmcp-registry` (manifests). CI compiles manifests → **signed `index.json`** artifact; runners consume the index, never the raw repo. |
| 9 | Packaging | **OCI images**, built by registry CI from the author's tagged source, **pinned by digest** in the manifest. Runner pulls, verifies digest, extracts rootfs, runs entrypoint under bwrap. `npx`/`uvx` only as a clearly-marked untrusted self-host escape hatch (not currently implemented). |
| 10 | Credential acquisition | BYO keys + BYO OAuth apps (client id/secret via compose env / `*_FILE` Docker secrets), runner executes the OAuth flow, per-provider setup guides. Hosted managed OAuth broker later — manifest credential schema is source-agnostic so it bolts on. |
| 11 | Client surface | One streamable-HTTP MCP endpoint per **profile** (`/mcp/p/<profile>`), per-profile bearer tokens. Meta-tools mode (search/load tools) as per-profile opt-in flag. Manifests mark tools `default: true/false` so installs expose a curated subset (Composio-style). |
| 12 | Gateway language | **Go.** Single static binary, scratch image. |
| 13 | Egress proxy | **Embedded** in the gateway binary, **hand-rolled net/http CONNECT MITM** (spike found martian/goproxy unmaintained; stdlib is simpler and a cleaner hook for source-IP lookup + header rewrite). Runtime ECDSA P-256 CA, per-host leaf minting (mutex-cached), allowlist checked at CONNECT time *before* a leaf is minted, header rewrite via `bufio`+`http.ReadRequest`. Identity binding is network-level: each sandbox netns gets a unique veth/IP recorded at spawn; proxy resolves `source IP → (server, user, profile)` from the accepted conn's RemoteAddr — unforgeable because the netns can only source its own /30. Per-request audit log falls out of this lookup. CA injected via `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`; `HTTPS_PROXY` set in the sandbox as convenience only — **route isolation is the actual enforcement** (env-only proxying is bypassable and was proven insufficient). |
| 14 | Storage | Repository interface with **SQLite** (zero-config default) and **Postgres** drivers. Rule: no Postgres-only features in core. |
| 15 | Vault encryption | Envelope encryption: per-secret DEKs, XChaCha20-Poly1305 (libsodium primitives via `golang.org/x/crypto`), wrapped by master KEK from `GIG_MASTER_KEY` env / `_FILE` secret. Versioned key IDs in ciphertext header for rotation. KEK never in DB. |
| 16 | License & protection | **Unmodified AGPL-3.0** (gateway/control plane). Name/logo protected by **trademark policy** (TRADEMARK.md; register later), not license edits. **DCO** for contributions; copyright kept concentrated to preserve dual-licensing of the hosted product. Apache-2.0 for manifest schema/SDKs when they exist. |
| 17 | Frontend | **Next.js** dashboard as pure frontend (separate `web` container). Visual style: model after **Composio's dashboard UI**. Astro reserved for future marketing/docs/marketplace static site. |
| 18 | Auth | Go gateway is the **sole auth authority**: local email+password + generic **OIDC client** (`coreos/go-oidc`) covering social login (Google/GitHub) and enterprise SSO (Okta/Entra/Authentik/Authelia) with one config block. Go issues httpOnly session after OIDC callback; Next.js forwards it. No Auth.js session ownership. |
| 19 | Multi-user | Multi-user **from the start**: `user_id` on every table, roles `admin`/`user`, OIDC + local login, admin user management, invitations. |
| 20 | Impersonation | **Config-only (option B)**: admin sees the user's view (profiles, server status, logs) but cannot execute tools or touch secrets. Time-boxed, banner-visible, loud audit event visible to the impersonated user too. Full impersonation = deliberate org-level toggle, off by default; not currently implemented. |

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

 gigmcp-registry repo ──CI──▶ lint manifests ▶ build OCI images ▶ sign index.json ──▶ runner pulls by digest
```

**Request flow (Tier 1):** client calls tool → gateway routes to the user's sandbox
instance (spawning it if cold) → server code makes HTTPS call with placeholder token →
only route is the proxy → proxy resolves identity from source IP → checks domain against
manifest allowlist → swaps placeholder for the user's real key from the vault → forwards
→ logs (user, server, domain, method, ts) to audit log.

**Threat model in one line:** gateway is trusted infrastructure; MCP servers are
untrusted; the kernel (namespaces/seccomp/Landlock) is the boundary between them; keys
live only on the trusted side.

> **SECURITY NOTE — SECCOMP STATUS:**
>
> **Docker-level `--security-opt seccomp=unconfined`** is still required and
> set. bwrap needs it to create an unprivileged user namespace (`--unshare-user`).
> A custom Docker seccomp profile that permits only the specific syscalls bwrap
> needs is a follow-up hardening item; it has not shipped yet.
>
> **Application-level seccomp-BPF filter** (`internal/seccomp`, installed by
> `cmd/bootstrap` after the capability/uid drop and before execve, inherited
> across execve): **this filter CLOSES the nested-user-namespace escape.**
> Specifically it denies:
> - `unshare`, `setns` → KILL_PROCESS (blanket; no legitimate use)
> - `clone(CLONE_NEWUSER)` → KILL_PROCESS (arg-filtered via BitsSet on arg0)
> - `clone3` → **ENOSYS** (not KILL — glibc ≥2.34 uses clone3 for
>   `pthread_create` and falls back to `clone` only on ENOSYS; a KILL would
>   SIGSYS-kill Rust/C servers on thread creation; the escape stays closed
>   because the fallback `clone(CLONE_NEWUSER)` is still arg-filtered above)
> - mount family (`mount`/`umount2`/`pivot_root`/`chroot`/`open_tree`/
>   `move_mount`/`fsopen`/`mount_setattr`) → KILL_PROCESS
> - `ptrace`, `process_vm_readv`, `process_vm_writev` → KILL_PROCESS
> - `keyctl`, `add_key`, `request_key` → KILL_PROCESS
> - `bpf`, `perf_event_open` → KILL_PROCESS
> - `kexec_load`, `init_module`, `finit_module`, `delete_module` → KILL_PROCESS
>
> **Default action is ALLOW** (not a full allowlist): only the escape/escalation
> vectors are denied, not every syscall. A fuller allowlist-style profile
> (as Docker's default seccomp profile provides) is deferred; the current filter
> closes the specific userns-escape and privilege-escalation paths that uid 65534
> + cap-drop alone do not prevent.
>
> Verified by `TestSeccompBlocksUnshare` (SIGSYS on unshare → kill) and
> `TestSeccompAllowsNormalWork` (Go goroutines + TCP, exit 0). Remaining
> hardening: Landlock (filesystem), cgroups (resource limits), and optionally a
> full allowlist seccomp profile for maximally hostile workloads.

**Egress networking:** the gateway holds only `CAP_NET_ADMIN` (no `SYS_ADMIN`,
no privileged). Route isolation — not environment variables — is the actual
enforcement: each sandbox's only route is `default via <proxy-IP>`, so all egress
hits the embedded MITM proxy regardless of what the sandboxed process does with
`HTTPS_PROXY`. The proxy identifies the tenant by the connection's source IP
(unforgeable — the netns can only source its own /30). Belt-and-suspenders:
the gateway sets the `iptables FORWARD` policy to `DROP` at startup (requires
iptables in the image; best-effort — route isolation remains if this step fails).

**Known residual risks (accepted, documented):**
- Tier 2 servers can exfiltrate their own secret *through* an allowed domain (e.g. write it into a gist). Tier label surfaces this.
- Shared-kernel isolation: a kernel 0-day breaks tenant separation. Acceptable for self-host / curated catalog; revisit (gVisor/microVMs) if hosting truly hostile workloads.
- `seccomp=unconfined` (Docker-level): required for bwrap userns; application-level BPF filter closes the userns-escape vectors — see SECCOMP STATUS note above. A custom Docker seccomp profile is a follow-up item.
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
  ref: ghcr.io/gigmcp/slack-mcp
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

## 5. Scope (deliberately large, per owner's call)

1. Go gateway: streamable-HTTP MCP endpoint, profile routing, per-profile bearer tokens
2. Sandbox runtime: OCI pull → digest verify → rootfs extract → bwrap spawn; per (server×user×profile) instances; idle reaping
3. Embedded egress proxy: IP identity binding, allowlists, Tier-1 injection, Tier-2 env injection, audit log
4. Vault: envelope encryption; SQLite + Postgres backends
5. `gigmcp-registry`: schema, lint CI, image build CI, signed `index.json`, ~8–10 launch manifests (Ubiquiti, Slack, GitHub, Google, …)
6. Auth & multi-user: OIDC + local login, admin/user roles, user management, invitations, config-only impersonation
7. Next.js dashboard: servers, profiles, credentials (incl. BYO OAuth flow), users/admin, audit log — ruthlessly minimal
8. BYO OAuth: provider client id/secret via compose env / Docker secrets; per-provider setup guides
9. Compose file: `gateway` + `web` (+ optional `postgres`)

**Known follow-ups (from skeleton code review):** `gateway.New` needs tool-namespace
collision handling once multiple backends exist — reject/deduplicate duplicate backend
names and backend names containing `_` (ambiguous `backend_tool` parsing). Deferred to the
multi-backend/registry plan; harmless at skeleton stage (single hardcoded backend).

**Future work (explicitly out of scope):** hosted control plane & managed OAuth broker, marketplace
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
apps — bureaucracy, not code. Gig'MCP's answers: sandbox makes untrusted code safe
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
4. **Registry pipeline:** `gigmcp-registry` CI — lint, image build, sign, publish index.
5. **Auth & multi-user:** OIDC, sessions, roles, REST API.
6. **Dashboard:** Next.js against the API.
7. **Hardening pass:** Tier-2, OAuth BYO flow, impersonation-B, audit UI, idle reaping,
   seccomp profile docs, threat-model doc.

Repo layout: monorepo `gigmcp/` → `cmd/gateway/`, `internal/{mcp,sandbox,proxy,vault,auth,store,registry}/`,
`web/` (Next.js), `deploy/` (compose, seccomp profile).
