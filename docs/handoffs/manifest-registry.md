# Handoff — Manifest / Registry Workstream

> Audience: the engineer/agent building the **manifest + registry + OCI-installer**
> workstream of gigmcp, working **in parallel** with a second agent building the
> **frontend / control-plane** workstream (auth, users, profiles, sessions, REST
> API, Next.js dashboard).
>
> This document is self-contained: read it plus the files it points at and you can
> start. It defines what you own, what you must not touch, the exact contracts
> ("seams") you share with the frontend agent, the spikes to run first, and how to
> build/test. The orchestrator will reconcile this doc against the frontend doc and
> do all `git commit`s — **do not commit, do not write code as part of this
> handoff.**

---

> **Parallel workstream notice:** This doc covers the **manifest / registry**
> workstream. The companion workstream is documented in
> [docs/handoffs/frontend-control-plane.md](frontend-control-plane.md). The two
> workstreams run in parallel sharing three coordination seams: `store.Store` interface
> (additive, separate files), `cmd/gateway/main.go run()` wiring (additive helpers),
> and the proxy resolver allowlist(from manifest)+secret(from vault) split. ONE
> cross-boundary item needs joint agreement before either goes deep: the sandbox
> currently mounts a single binary at `/app/server`, but OCI images (Node/Python) are
> full rootfses, so real images require a coordinated extension to the otherwise-stable
> `internal/sandbox` — prove the pipeline with static-binary images first, then agree
> the rootfs-mount extension.

---

## 1. Mission + fit in the product

gigmcp is an AGPL, security-first MCP gateway: it runs *untrusted, community* MCP
servers inside kernel-enforced sandboxes (bwrap: user/pid/net/mount namespaces +
seccomp + cap-drop) and injects credentials at an egress MITM proxy so a
compromised tool never sees the raw key. It is the open, self-hostable answer to
Composio: "run anyone's server; the sandbox + proxy make trust unnecessary."

Today the gateway runs **one hardcoded server** (an `echo` binary already baked
into the image). That is the walking skeleton. **Your workstream is what turns
gigmcp into a real product**: a curated, signed *registry* of community servers,
packaged as digest-pinned OCI images, with author-declared *entitlement manifests*
(egress allowlist, credential schema, tool subset, security tier) that the gateway
*installs*, *verifies*, and *enforces*. You replace "hardcoded echo binary" with
"install `slack-mcp@1.4.2` from the signed index, pull its image by digest, verify,
extract, run sandboxed, enforce its manifest."

You span **two repos**:

1. **`gigmcp-registry`** (a *new, separate* GitHub repo — DESIGN #8): the manifest
   format, example/launch manifests, lint CI, OCI image-build CI, and a signing
   step that publishes a **signed `index.json`** artifact.
2. **`gigmcp`** (this repo): the gateway-side **runner/installer** that consumes
   the signed `index.json`, pulls + verifies images by digest, extracts them, and
   records the server + manifest in the store; plus the refactor that makes egress
   allowlist + credential-injection schema come from the **manifest** instead of
   the credential row.

The frontend agent builds the API/UI that *calls* your installer and *reads* the
manifest data you persist. You build the engine; they build the cockpit.

---

## 2. Current repo state (what exists, with file pointers)

Walking skeleton + egress proxy + encrypted vault + scoped seccomp are **done and
tested**. Servers are **hardcoded**. There is **no manifest, no registry, no OCI
pull, no digest verification** anywhere — servers run from binaries already present
in the image.

Verified current facts:

- **Servers are seeded by hand.** `cmd/gateway/main.go` `run()` (lines ~74-77)
  calls `st.EnsureServer(ctx, "echo", cfg.EchoBinary)` — the `echo` server's
  binary path comes from the `GIG_ECHO_BIN` env var (`internal/config/config.go`,
  `EchoBinary`, *required*). Tests additionally use a `fetch` server
  (`cmd/fetch-mcp`) the same way. **This seeding is exactly what registry-driven
  install replaces.**
- **`store.Server` is minimal.** `internal/store/store.go`:
  ```go
  type Server struct {
      ID     int64
      Name   string // unique; tool namespace prefix
      Binary string // absolute host path to the server's binary
  }
  ```
  The `Store` interface today: `EnsureServer(ctx, name, binary)`, `ListServers(ctx)`,
  `PutCredential`, `GetCredential`, `Close`. SQLite schema in
  `internal/store/sqlite.go` (`servers` table: `id, name, binary`). The opener is
  `OpenSQLite(path)` and it runs `schema` + `credSchema` at open time (additive
  `CREATE TABLE IF NOT EXISTS` — this is where you add manifest tables).
- **Allowlist + injection live on the credential row, NOT a manifest.**
  `internal/store/credentials.go`:
  ```go
  type Credential struct {
      Server, Tenant string
      EncryptedKey   []byte   // vault ciphertext
      InjectHeader   string   // "Authorization"
      InjectFormat   string   // "Bearer {token}"
      Placeholder    string   // sentinel the sandbox sends
      AllowedHosts   []string // egress allowlist for this (server,tenant)
  }
  ```
  The proxy resolver `internal/gateway/resolver.go` (`CredResolver.Resolve`) reads
  **all** of these from the credential row and hands them to the proxy as a
  `proxy.Credential`. **Decision #7 says the allowlist + injection schema are
  author-declared in the manifest and enforced as a hard cap — so this data must
  move to the manifest. That refactor is yours (see seam §6.C).**
- **How a server is run.** `internal/gateway/spawn.go` `SpawnEgressBackend(ctx,
  srv store.Server, alloc, reg, proxyPort, caFile, bootstrapPath)`:
  - allocates a `/30`, spawns bwrap via `internal/sandbox`,
  - **mounts the server binary as a single read-only bind: `{Src: srv.Binary,
    Dst: "/app/server"}`** and runs `Exec: "/app/server"`,
  - sets non-secret sandbox env (`HTTPS_PROXY`, `SSL_CERT_FILE`,
    `NODE_EXTRA_CA_CERTS`, `GIG_PLACEHOLDER`),
  - registers `sourceIP → proxy.Identity{Server: srv.Name, Tenant: "default"}` in
    the proxy registry, then connects the MCP stdio session.
  **It consumes a `store.Server` with a `Binary` path and builds the `Egress`
  config itself.** Key constraint: **the sandbox mounts ONE binary at
  `/app/server`** (`internal/sandbox/sandbox.go`, `commandEgress`). An OCI image is
  a whole rootfs, not one static binary — this mismatch is the central sandbox
  coordination question (see seam §6.E and spike §7.C).
- **The proxy** (`internal/proxy/proxy.go`) checks `allowed(targetHost,
  cred.AllowedHosts)` at CONNECT time *before* minting a leaf, then swaps the
  placeholder for the real secret using `InjectHeader`/`InjectFormat`. The
  `CredentialResolver` interface and `proxy.Credential` struct are the seam you
  refactor. `allowed()` already supports exact match + single-label `*.suffix`
  wildcards — your lint rules must match this semantics.
- **Aggregator** (`internal/gateway/gateway.go`, `New`) re-exposes every backend
  tool as `<backend>_<tool>` and **currently exposes ALL tools** with no notion of
  a default subset. Decision #11's `default: true/false` is *not* implemented —
  that's yours (seam/area §4.4). Note the known follow-up in DESIGN §5: tool-
  namespace collision handling + rejecting backend names containing `_` once
  multiple backends exist — relevant the moment registry installs >1 server.
- **Config** (`internal/config/config.go`) is env-only; `GIG_ECHO_BIN` is
  currently *required* — registry-driven install should remove that hard
  requirement (coordinate; it's a startup-path edit, see §6.D).
- **Stable, done, tested, do-not-touch:** `internal/{sandbox,netmgr,proxy,vault,
  seccomp}`, `cmd/bootstrap`. See `docs/superpowers/plans/2026-06-06-egress-proxy-
  vault.md` and `...-walking-skeleton.md` for how they were built (and the spike
  facts that de-risked them).

---

## 3. Relevant DESIGN decisions (quote # + gist)

Read `DESIGN.md` in full; these are the ones that govern your workstream.

- **#7 Entitlements manifests.** Author-declared, **PR-gated** into the registry
  repo (owner approves), **enforced as a hard cap by the proxy**. **Lint CI blocks
  wildcards / known exfil domains.** **Manifest changes on update ⇒ re-consent.**
- **#8 Registry topology.** GitHub org, **two repos**: `gigmcp` (gateway monorepo)
  + `gigmcp-registry` (manifests). CI **compiles manifests → a *signed*
  `index.json`** artifact; **runners consume the index, never the raw repo**.
- **#9 Packaging.** **OCI images**, built by registry CI from the author's tagged
  source, **pinned by digest** in the manifest. **Runner pulls, verifies digest,
  extracts rootfs, runs entrypoint under bwrap.** `npx`/`uvx` only as a clearly-
  marked untrusted self-host escape hatch (post-v1 — *out of scope for you*).
- **#11 Client surface / tool subset.** One streamable-HTTP endpoint per profile.
  **Manifests mark tools `default: true/false` so installs expose a curated
  subset** (Composio-style). Meta-tools (search/load) is a per-profile opt-in flag
  (frontend territory; you provide the default-subset data).
- **#6 Credential tiers.** **Tier 1 "Sealed"** (default): placeholder token in
  sandbox; proxy swaps the real key per tenant — key never enters the sandbox.
  **Tier 2 "Entrusted"**: real secret in sandbox env (DB strings, cert-pinned
  clients); **egress allowlist still applies**. Tier 3 / local-resource servers
  out of scope. The manifest's `tier:` field drives this.

### DESIGN §4 manifest schema sketch (your starting point — refine it)

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

Registry CI lints: no bare `*` egress, denylist (pastebin/webhook.site/raw
IPs/...), digest present, schema valid. Manifest diff on version bump ⇒ runner
forces re-consent.

**Refinements you should consider (call these out in your plan, get sign-off):**
- An **entrypoint / argv** field (the OCI image may declare an `ENTRYPOINT`, but you
  want it explicit and lintable; also which binary becomes `/app/server` or how the
  rootfs entrypoint is invoked under bwrap).
- A **`placeholder`** value per credential (today hardcoded to `"PLACEHOLDER"` in
  spawn.go — must be a high-entropy per-credential sentinel; `proxy.Credential`
  warns the placeholder is matched as a substring).
- **Tier-2 env injection**: for `tier: entrusted`, the manifest needs to name the
  **env var** the real secret is injected into (vs Tier-1 header rewrite). The
  schema should make tier-1-vs-tier-2 injection explicit.
- A **schema version** field on the manifest and on `index.json` for forward compat.
- Whether `entitlements.egress` entries are hostnames only (current `allowed()`
  semantics: exact host or `*.suffix`; no ports, no paths, no CIDRs). Keep lint and
  the proxy's `allowed()` in lockstep.

---

## 4. What you OWN (5 areas → concrete deliverables)

### 4.1 The `gigmcp-registry` repo (new, separate GitHub repo)

- **Manifest format**: a documented YAML schema (refine §4 above). Ship a
  machine-checkable schema (JSON Schema or a Go struct + validator in a shared,
  Apache-2.0 package per DESIGN #16 "Apache-2.0 for manifest schema/SDKs"). The
  *authoritative* parser/validator should be Go so the gateway and CI agree
  byte-for-byte — strongly prefer one shared module over a YAML-schema-in-CI +
  separate-Go-parser split that can drift.
- **Example / launch manifests**: ~8-10 (DESIGN §5: Ubiquiti, Slack, GitHub,
  Google, …). For the handoff, start with 1-2 real ones (echo/fetch re-expressed as
  manifests is a great first integration target — it lets you prove install-from-
  manifest against servers that already exist in this repo).
- **Lint CI** (the heart of #7): reject **bare wildcards** (`*`, `*.com`, anything
  broader than single-suffix per `proxy.allowed()`), **known-exfil domains**
  (pastebin.com, webhook.site, requestbin, ngrok, raw IP literals, …), **require an
  image digest**, and **require schema validity**. CI must **fail the PR** on any
  violation. Maintain the exfil denylist as a checked-in, reviewable file.
- **Image-build pipeline**: build an **OCI image from the author's tagged source**
  (DESIGN #9), push to a registry (likely `ghcr.io/gigmcp/<name>`), and **capture
  the resulting digest** — the digest the manifest pins is the digest CI produced
  ("what was approved is what runs").
- **Signing step → signed `index.json`**: compile all approved manifests into a
  single `index.json` (name → version → manifest + digest), **sign it**, and
  publish it as an artifact (release asset / GitHub Pages — open question §10). The
  runner downloads `index.json` + signature and **verifies the signature before
  trusting any entry**.
- **Deliverable: a `README`/`CONTRIBUTING` in that repo** describing the PR-gated
  author flow (author opens PR with manifest + source tag → CI lints + builds image
  + computes digest → owner approves → merge → index re-signed + published).

**Repo layout (proposed):**
```
gigmcp-registry/
├── manifests/<name>/<version>.yaml     # one file per server version
├── schema/                             # JSON Schema and/or vendored Go validator
├── denylist/exfil-domains.txt          # checked-in, reviewed
├── .github/workflows/
│   ├── lint.yml                        # schema + wildcard + denylist + digest-present
│   ├── build-images.yml                # OCI build from author tag → push → digest
│   └── publish-index.yml              # compile → sign → publish index.json (+ .sig)
└── README.md / CONTRIBUTING.md
```

### 4.2 Gateway-side runner / installer (new `internal/registry` + `internal/oci`)

- **`internal/registry`**: fetch + **verify the signed `index.json`**; resolve a
  manifest by `name@version` (or by digest); parse/validate manifests using the
  shared schema module.
- **`internal/oci`**: **pull an OCI image BY DIGEST** (no Docker daemon — spike
  §7.A), **verify the pulled digest matches the manifest**, and **extract the
  rootfs (or the entrypoint binary) to a local path**.
- **Install flow** (`Installer.Install`, see §6.B): resolve manifest → pull image
  by digest → verify digest → extract to a local path → **record the server + its
  manifest in the store** (tier, egress allowlist, injection schema, tool default-
  subset, digest, entrypoint). **This replaces `EnsureServer("echo", ...)` seeding
  in `cmd/gateway/main.go run()`.**

### 4.3 Manifest-driven enforcement (the resolver refactor)

The egress allowlist + injection config must come from the **manifest** (per
server), **not** the credential row (DESIGN #7: author-declared, hard cap). Only
the **real secret** comes from the vault (per server,tenant — frontend owns
credential CRUD). Refactor `CredResolver.Resolve` to **merge manifest (allowlist +
injection schema, keyed by server) + vault secret (keyed by server,tenant)**. See
seam §6.C for the exact contract — this is a coordination point.

### 4.4 Tool default-subset (#11)

Manifests mark tools `default: true/false`. The aggregator (`internal/gateway/
gateway.go`) currently exposes **all** backend tools. Make it expose only the
**default subset** for a server (the manifest's tool list), while keeping the
non-default tools available for the future meta-tools / per-profile opt-in path.
You own the manifest→tools data and the aggregator filter; the frontend owns any
per-profile UI toggling on top of it.

### 4.5 Digest pinning + re-consent (#7)

The manifest pins `image.digest` — the installer verifies the pulled image matches.
On **update** (new version / changed manifest), a manifest **diff requires
re-consent**. The **consent UI is the frontend's**; **you define the data/flag the
frontend reads** — e.g. a persisted record of "the manifest hash the user last
consented to" per (server,tenant/user) and a derived `NeedsReconsent` boolean
(current manifest hash != consented hash). Specify this field in the store so the
frontend can render the re-consent prompt and call back to record acceptance.

---

## 5. What you must NOT touch (and why)

- **`internal/{sandbox,netmgr,proxy,vault,seccomp}`, `cmd/bootstrap`** — STABLE,
  security-critical, fully tested. You **consume** them (spawn via the existing
  sandbox/spawn path) but **do not change their internals**. The one *coordinated*
  exception is feeding the manifest allowlist into the proxy resolver (seam §6.C) —
  that's the resolver in `internal/gateway`, not the proxy package itself. And the
  rootfs-vs-single-binary sandbox question (§6.E) is a *proposal to be agreed*, not
  a unilateral edit.
- **Auth, users, profiles, sessions, the Next.js dashboard, the REST API** —
  **frontend owns these entirely** (DESIGN #17-#20). You **provide the installer
  interface** their API calls; you do **not** build API or UI.

---

## 6. Shared seams & coordination protocol (the contract)

These are the exact touchpoints where your code and the frontend's code meet. State
them precisely; the orchestrator reconciles this doc against the frontend doc.

### 6.A `store.Store` interface + schema (additive, separate files)

- **You add** server/manifest persistence. Two clean options — **prefer a separate
  `manifests` table over widening `Server` inline**, to avoid editing the same
  struct lines the frontend may touch:
  - **Option A (recommended):** new file `internal/store/manifests.go` with a
    `Manifest` table (server name/version, digest, tier, allowlist (newline-joined,
    matching the `credentials.allowed_hosts` convention), injection schema as JSON,
    tools as JSON, entrypoint, raw manifest hash for re-consent) + `Store` methods
    `PutManifest` / `GetManifest(server)` / `ListManifests`. Add its
    `CREATE TABLE IF NOT EXISTS` to `OpenSQLite` next to `schema`/`credSchema`.
  - **Option B:** widen `store.Server` with manifest fields. If you do this, **you
    OWN the manifest-related fields of `Server`; the frontend reads `Server`
    read-only.** Riskier for merges.
- **Protocol:** additive `CREATE TABLE IF NOT EXISTS` in `OpenSQLite` (it already
  chains `schema` then `credSchema` — append yours the same way). Keep your DDL +
  methods in **separate files** (`manifests.go`) from the frontend's
  (`users.go`/`profiles.go`/`sessions.go`). Avoid editing the same struct lines.
  Don't drop/rename existing columns. SQLite + Postgres parity (DESIGN #14): no
  SQLite-only features.

### 6.B Installer interface (you implement + expose; frontend consumes)

**This is the exact interface you provide.** It must match the frontend doc's
expectation; the orchestrator will confirm.

```go
type Installer interface {
    Install(ctx context.Context, ref string) (store.Server, error)  // ref = name@version | name(latest) | sha256:<digest>; idempotent by (name,version)
    Uninstall(ctx context.Context, name string) error
    List(ctx context.Context) ([]store.Server, error)
}
```

- `ref` grammar: `name@version` | `name` (latest in index) | `sha256:<digest>`.
- `Install` is **idempotent** by (name,version): re-installing the same version is a
  no-op (or refreshes the record); installing a *new* version sets the re-consent
  flag (§4.5).
- Return type is `store.Server` so the frontend renders from the shared struct.
- **Open coordination point:** whether `Install` *also spawns* the backend or only
  records it (spawn happens separately at startup / on first use). Recommendation:
  `Install` = record only; spawning stays in the gateway run-loop / a separate
  supervisor call, so the API stays fast and idempotent. Flag this for the
  orchestrator to reconcile with the frontend's expectations (does "Install" in the
  UI mean "available" or "running"?).

### 6.C `proxy.CredentialResolver` / `proxy.Credential` (allowlist/secret split)

- **Today** (`internal/gateway/resolver.go`): `CredResolver.Resolve` reads
  `EncryptedKey`, `InjectHeader`, `InjectFormat`, `Placeholder`, `AllowedHosts`
  **all from the credential row** and returns a `proxy.Credential`.
- **Target:** `proxy.Credential{RealSecret, InjectHeader, InjectFormat,
  Placeholder, AllowedHosts}` is assembled from **two sources**:
  - **manifest (by server):** `AllowedHosts`, `InjectHeader`, `InjectFormat`,
    `Placeholder` — the author-declared hard cap.
  - **vault (by server,tenant):** `RealSecret` only (decrypt `EncryptedKey`).
- **Refactor:** `Resolve(id, host)` looks up the **manifest for `id.Server`** (your
  store method) for allowlist + injection schema, and the **vault secret for
  (`id.Server`,`id.Tenant`)** for the real key, then merges. **The
  `proxy.Credential` shape and the `CredentialResolver` interface do NOT change** —
  only where `CredResolver` (in `internal/gateway`, which you may edit) sources its
  fields. The proxy package itself stays untouched.
- **Coordination:** the frontend owns credential CRUD, so the credential row may
  shrink to just `{Server, Tenant, EncryptedKey}` (injection/allowlist columns
  become manifest-sourced). **Agree with the frontend agent** whether those columns
  are dropped, ignored, or kept as a per-tenant override. Recommended: manifest is
  the source of truth for allowlist + injection; credential row keeps only the
  secret. Don't break `PutCredential`/`GetCredential` signatures without
  reconciling — the frontend writes credentials through them.

### 6.D `cmd/gateway/main.go run()` (startup wiring — shared merge touchpoint)

- **You replace** the hardcoded `EnsureServer("echo", cfg.EchoBinary)` + demo
  credential seeding with **registry-driven install** (install-on-startup from a
  configured set, and/or install-on-demand via the `Installer` the API calls).
  Also relax the `GIG_ECHO_BIN`-required check in `internal/config` (coordinate).
- **Frontend also extends `run()`** (mounting the REST API server + auth).
- **Protocol:** keep your additions in **separate helper functions** (e.g.
  `installFromIndex(...)`, `spawnInstalled(...)`) called from `run()`, mirroring the
  existing `seedDemoCredential`/`writeTempCA`/`applyForwardDrop` style — minimise
  the lines in `run()` that both agents touch. Expect a small merge here; the
  orchestrator resolves it.

### 6.E sandbox/spawn — single binary vs OCI rootfs (FLAG: likely sandbox extension)

- `SpawnEgressBackend` already consumes a `store.Server` and builds the `Egress`
  config — **for a single static binary this works unchanged**: set
  `srv.Binary` to your extracted entrypoint binary and it mounts at `/app/server`.
- **BUT** the current sandbox mounts exactly **one** binary
  (`{Src: srv.Binary, Dst: "/app/server"}`, `Exec: "/app/server"`). A real OCI
  image is a **whole rootfs** (interpreter, shared libs, node/python runtime,
  resource files) — a single bind won't run a Node/Python MCP server.
- **This is a coordination/extension point with the (stable) sandbox**, not a
  unilateral edit. Two paths to put before the human + sandbox owner:
  1. **v1-simple:** registry images are **static, self-contained binaries** (Go-
     style scratch images). Extract just the entrypoint binary; **no sandbox change
     needed**. Constrains what authors can ship but is the lowest-risk first cut.
  2. **v1-full:** extract the full rootfs and have bwrap **bind the rootfs** (e.g.
     `--bind <rootfs> /` or per-top-dir ro-binds) instead of one `/app/server`.
     This needs a **new `sandbox.Spec` field** (e.g. `RootfsDir` / a richer mount
     set) — a real change to a "stable" package, so it must be **agreed and owned
     jointly**, with its own tests.
- **Recommendation:** prove the whole pipeline end-to-end with path (1) first
  (re-express the existing `echo`/`fetch` static binaries as manifests + a trivial
  "image"), then propose the rootfs extension (path 2) as a scoped follow-up with
  the sandbox owner. **Do not modify `internal/sandbox` before that agreement.**
  **Note:** this cross-boundary finding was independently surfaced by both workstreams
  (see frontend-control-plane handoff doc §5).

---

## 7. Suggested approach: brainstorm + spikes + TDD

This codebase has a **strong, proven discipline: spike the hard systems problem in
a throwaway first, capture the verified facts, then build test-first.** The egress-
proxy/vault plan (`docs/superpowers/plans/2026-06-06-egress-proxy-vault.md`) opens
with a "critical environment facts (from spikes — do not re-derive)" + "verified API
cheat sheet (trust over memory)" block — that de-risking is *why* the netns/bwrap
work landed cleanly. **Follow the same pattern.** Use:

- `superpowers:brainstorming` before designing the manifest schema + install flow.
- `superpowers:writing-plans` to turn the agreed design into a checkbox plan under
  `docs/superpowers/plans/`.
- `superpowers:subagent-driven-development` + `superpowers:test-driven-development`
  to execute task-by-task (red-green-refactor), same as prior plans.
- Spike each unknown **before** committing to a design.

### FIRST spikes to run (before writing the real implementation)

**Spike A — OCI pull-by-digest WITHOUT a Docker daemon (run this FIRST).**
DESIGN #3 mandates *no Docker socket*; the gateway is a single static
`CGO_ENABLED=0` binary in a scratch image. You must pull + verify + extract OCI
images purely as a library. Evaluate, in order of likely fit:
- **`github.com/google/go-containerregistry`** (`crane`/`v1` packages) — pure-Go,
  daemonless, first-class **pull by digest** and layer access; most likely answer.
- **`containerd`** client libs — heavier, often assumes a containerd daemon.
- **`umoci`** + an OCI-layout puller — strong at **rootfs extraction** specifically.
Decide: can we pull by digest, verify the digest, and extract a rootfs (or a single
binary) **with `CGO_ENABLED=0`, no daemon, in a scratch image**, and what's the
dependency/footprint cost? Output: a "verified facts + API cheat sheet" block like
the egress plan's. **This is the top spike — it gates the whole workstream.**

**Spike B — signed `index.json` format + signing/verify.** Decide the signing
scheme (e.g. **`cosign`/sigstore** vs a **plain ed25519 detached signature** over
the canonical `index.json` bytes — ed25519 is trivial to verify in-process with
`crypto/ed25519` and needs no external infra). Decide key management (open question
§10) and the on-disk/on-wire format (`index.json` + `index.json.sig`, or an
embedded signature). Output: the exact bytes the runner verifies and how.

**Spike C — rootfs extraction + does bwrap need to mount a rootfs vs one binary.**
Take a real Node or Python MCP server image, extract it with the Spike-A library,
and try to run it under the *existing* `internal/sandbox` egress path. Confirm
whether path (1) (single binary, no sandbox change) or path (2) (full rootfs bind,
sandbox extension) is required for the launch catalog. This directly answers seam
§6.E and tells the human/sandbox-owner what (if anything) must change in the stable
sandbox package.

**Then** write the plan and build: manifest schema module → registry lint/build/sign
CI → gateway `internal/oci` + `internal/registry` + `Installer` → store
`manifests.go` → resolver refactor → aggregator default-subset → main.go wiring.

---

## 8. How to build / test

- **Gateway (this repo):** Go module `github.com/gigmcp/gigmcp`, Go 1.26.
  - `make test` — full suite incl. sandbox/egress/vault tests, in a Linux container
    with `--cap-add NET_ADMIN` + relaxed seccomp/apparmor/systempaths (bwrap needs
    unprivileged userns; see Makefile + DESIGN §3). **Your OCI/registry/installer
    unit tests run here too.**
  - `make test-local` — host-side subset; Linux-only sandbox tests self-skip on
    macOS (`sandbox.Available()` gates them). Dev machine is macOS — pure-Go
    registry/manifest/index logic can be TDD'd locally with `make test-local`; the
    spawn/sandbox integration must run in the container via `make test`.
  - Keep `CGO_ENABLED=0` (modernc sqlite + scratch image). **Your OCI library choice
    must not break static builds** — verify in Spike A.
- **`gigmcp-registry` (separate repo):** its **CI is its own** (GitHub Actions:
  lint, image-build, sign+publish index). The **runner-side** consumption of the
  index is tested in *this* repo (`internal/registry` against a fixture
  `index.json` + signature). Use a **fixture signed index + tiny fixture OCI image**
  (or OCI layout dir) committed as testdata so installer tests are hermetic.

---

## 9. Key file pointers + libraries already in play

**Files you will read/extend (this repo):**
- `internal/store/store.go` — `Server`, `Store` interface (add `manifests.go` +
  methods).
- `internal/store/sqlite.go` — `OpenSQLite`, `schema`; chain your DDL here.
- `internal/store/credentials.go` — `Credential` (allowlist/injection move to
  manifest; coordinate shrink with frontend).
- `internal/gateway/resolver.go` — `CredResolver.Resolve` (the §6.C refactor).
- `internal/gateway/spawn.go` — `SpawnEgressBackend` (consumes `store.Server`;
  §6.E single-binary vs rootfs).
- `internal/gateway/gateway.go` — aggregator `New` (add default-subset filter).
- `cmd/gateway/main.go` — `run()` (replace seeding; §6.D).
- `internal/config/config.go` — relax `GIG_ECHO_BIN`; add registry/index config.
- `internal/sandbox/sandbox.go` — **read-only** unless the rootfs extension (§6.E)
  is agreed.
- New: `internal/oci/`, `internal/registry/`.

**Libraries already in `go.mod`:** Go 1.26; `modernc.org/sqlite` (pure-Go, no CGO);
`github.com/modelcontextprotocol/go-sdk v1.6.1` (MCP); `golang.org/x/crypto`
(vault); `github.com/vishvananda/netlink` + `netns` (netmgr);
`github.com/elastic/go-seccomp-bpf`. **No OCI/registry/signing libs yet** — you add
them (Spike A/B).

**Candidate libs to evaluate (not yet vendored):**
- OCI pull/extract: `github.com/google/go-containerregistry` (primary candidate),
  `containerd` client, `umoci`.
- Signing: `crypto/ed25519` (stdlib, simplest), or `sigstore/cosign` libs.
- YAML: `sigs.k8s.io/yaml` or `gopkg.in/yaml.v3` for manifest parsing; pair with a
  Go struct validator (and optionally `santhosh-tekuri/jsonschema` for the CI side
  if you keep a JSON Schema).

---

## 10. Open questions for the human

1. **`index.json` signing key management.** Where does the signing private key live
   (GitHub Actions secret? sigstore/keyless OIDC? offline owner key?) and how does
   the runner obtain/trust the public key (baked into the gateway binary? config?)?
   This gates Spike B.
2. **v1 packaging granularity:** do v1 registry images ship as **static self-
   contained binaries** (no sandbox change — §6.E path 1) or **full rootfs** (needs
   the stable sandbox extended — path 2)? Strong lean: path 1 for v1, path 2 as a
   scoped follow-up. Needs the owner + sandbox-owner's call.
3. **Registry hosting / index distribution:** GitHub **release artifact**, **GitHub
   Pages**, or the registry (OCI artifact) itself? Affects how the runner fetches
   `index.json` + signature.
4. **Install-on-startup vs install-on-demand-via-API:** does the gateway install a
   configured default set at boot, or only what the frontend's API installs? And
   does `Installer.Install` *spawn* the backend or only *record* it (see §6.B)?
   Needs reconciliation with the frontend's "Install" UX semantics.
5. **Credential row shrink:** with allowlist + injection moving to the manifest, do
   we **drop** the `inject_*`/`allowed_hosts`/`placeholder` columns from
   `credentials`, keep them as optional per-tenant **overrides**, or ignore them?
   Coordinate with the frontend (credential CRUD owner).
6. **OCI library + static build:** confirm the chosen OCI lib keeps `CGO_ENABLED=0`
   / scratch-image builds working (Spike A output).
```
