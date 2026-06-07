# Manifest / Registry Workstream — Design

> Spec for the manifest + registry + OCI-installer workstream defined in
> [docs/handoffs/manifest-registry.md](../../handoffs/manifest-registry.md).
> Brainstormed and approved 2026-06-06. Companion workstream:
> [frontend-control-plane](../../handoffs/frontend-control-plane.md).

## Goal

Replace the hardcoded `EnsureServer("echo", cfg.EchoBinary)` seeding with a real
supply chain: a curated, signed registry of community MCP servers, packaged as
digest-pinned OCI images with author-declared entitlement manifests that the
gateway installs, verifies, and enforces.

Spans two repos:

1. **`gigmcp-registry`** (new repo): manifest schema + validator, example
   manifests, lint CI, image-build CI, signed `index.json` publishing.
2. **`gigmcp`** (this repo): `internal/registry` (index fetch/verify/resolve),
   `internal/oci` (pull-by-digest/verify/extract), `Installer`, store
   `manifests` table, resolver refactor, aggregator default-subset filter,
   `main.go` wiring.

## Resolved open questions (handoff §10)

| # | Question | Decision |
|---|----------|----------|
| 1 | Index signing + key management | Plain **ed25519 detached signature**: `index.json` + `index.json.sig`. Private key in a GitHub Actions secret. Public key **baked into the gateway binary**, overridable via config (`GIG_REGISTRY_PUBKEY`). Verified in-process with `crypto/ed25519`; no external infra. Sigstore/cosign can be adopted later without breaking consumers (new sig file alongside). |
| 2 | v1 packaging granularity | **Static self-contained binaries first** (handoff §6.E path 1). No change to `internal/sandbox`. Full-rootfs support (Node/Python) is a follow-up plan, informed by Spike C and agreed with the sandbox owner. |
| 3 | Index distribution | **GitHub release asset** on `gigmcp-registry` at a stable `latest` URL. Gateway index URL is config (`GIG_REGISTRY_INDEX_URL`); `file://` supported for tests/dev. |
| 4 | Install semantics | **`Install` = record only** (resolve → pull → verify → extract → persist). Spawning stays in the gateway run-loop. Boot-time install of a configured set via `GIG_INSTALL` (comma-separated refs) so the gateway works standalone before the dashboard exists. |
| 5 | Credential row shrink | Manifest is the **only** source of allowlist + injection config. Credential row contributes only the encrypted secret. Existing `inject_*`/`allowed_hosts`/`placeholder` columns are **kept** (no destructive migration) and used only by the legacy `GIG_ECHO_BIN` fallback path; manifest-backed servers never read them. Dropping them is reconciled with the frontend agent later. `PutCredential`/`GetCredential` signatures unchanged. |
| 6 | OCI library | `github.com/google/go-containerregistry` — **pending Spike A** confirmation of daemonless pull-by-digest + extraction with `CGO_ENABLED=0` scratch builds. |

## 1. Manifest schema

DESIGN.md §4 sketch, refined with the four gaps the handoff flags
(schema version, explicit entrypoint, tier-explicit injection, placeholder):

```yaml
schemaVersion: 1                 # forward compat (also on index.json)
name: slack-mcp                  # unique; lint rejects "_" (tool-namespace separator)
version: 1.4.2
source:
  repo: github.com/author/slack-mcp
  tag: v1.4.2
image:
  ref: ghcr.io/gigmcp/slack-mcp
  digest: sha256:…               # what was approved is what runs
  entrypoint: /server            # explicit path of the static binary inside the image
tier: sealed                     # sealed | entrusted
entitlements:
  egress:                        # hostnames only: exact or single-label "*.suffix";
    - slack.com                  # no ports/paths/CIDRs/bare wildcards — exactly
    - "*.slack.com"              # proxy.allowed() semantics; lint enforces lockstep
credentials:
  - id: slack_bot_token
    type: api_key                # oauth2 | api_key | basic | custom_env
    provider: slack
    scopes: [chat:write]
    inject:                      # tier-explicit injection:
      header: Authorization      #   sealed: proxy rewrites this header
      format: "Bearer {token}"
      # env: SLACK_TOKEN         #   entrusted: real secret in this env var instead
tools:
  - name: send_message
    default: true
  - name: admin_set_workspace_settings
    default: false
```

Validation rules (enforced identically in CI and gateway via the shared module):

- `schemaVersion` known; `name` matches `[a-z0-9-]+` (no `_`); semver `version`.
- `image.digest` present and well-formed (`sha256:` + 64 hex).
- `image.entrypoint` absolute path, present.
- Egress entries: exact hostname or `*.suffix` with at least two remaining
  labels; reject bare `*`, `*.com`-style single-label suffixes, IP literals,
  ports, paths. Reject entries on the exfil denylist.
- `tier: sealed` credentials require `inject.header`+`inject.format`;
  `tier: entrusted` credentials require `inject.env`. Exactly one mode per
  credential.
- Tool names non-empty, unique.

**Placeholder** is NOT in the manifest: it is generated at install time as a
high-entropy random sentinel per (server, credential) and stored with the
manifest record. Replaces the hardcoded `"PLACEHOLDER"` (substring-match
footgun noted in `proxy.Credential`).

**Shared schema module**: `github.com/gigmcp/gigmcp-registry/schema`, its own
Go module, Apache-2.0 (DESIGN #16). The single authoritative
parser/validator/linter used byte-for-byte by registry CI and the gateway —
no JSON-Schema/Go-parser drift possible. YAML via `sigs.k8s.io/yaml`
(YAML→JSON→struct keeps JSON canonical for hashing).

**Manifest hash**: SHA-256 over the canonical JSON encoding of the parsed
manifest (not raw YAML bytes) — basis for re-consent.

## 2. `gigmcp-registry` repo + CI

```
gigmcp-registry/
├── manifests/<name>/<version>.yaml    # one file per server version
├── schema/                            # Go module: types, Parse, Validate, Lint, Hash
├── denylist/exfil-domains.txt         # checked-in, reviewed (pastebin.com, webhook.site,
│                                      #   requestbin, ngrok, …; IP literals rejected by rule)
├── cmd/registryctl/                   # CLI used by CI and locally:
│                                      #   lint | build-index | sign | verify
├── .github/workflows/
│   ├── lint.yml                       # PRs: schema + egress rules + denylist + digest present
│   ├── build-images.yml               # build OCI image from author tag → push ghcr.io → emit digest
│   └── publish-index.yml              # main: compile → sign (ed25519) → release assets
└── README.md / CONTRIBUTING.md        # PR-gated author flow
```

Author flow (DESIGN #7): author PRs `manifests/<name>/<version>.yaml` pointing
at a tagged source → `lint.yml` must pass → `build-images.yml` builds from that
tag, pushes `ghcr.io/gigmcp/<name>`, reports the digest the manifest must pin →
owner approves, merges → `publish-index.yml` recompiles `index.json`, signs,
publishes `index.json` + `index.json.sig` as the rolling `latest` release.

`index.json` (canonical JSON; the exact bytes are what is signed):

```json
{
  "schemaVersion": 1,
  "generated": "<RFC3339>",
  "servers": {
    "echo": {
      "latest": "0.1.0",
      "versions": { "0.1.0": { /* full manifest object, embedded */ } }
    }
  }
}
```

Launch manifests: start with **echo** and **fetch** (re-expressing
`cmd/echo-mcp` / `cmd/fetch-mcp` as static-binary images) to prove
install-from-manifest against servers that already exist; grow toward the
8–10 catalog (DESIGN §5) after the pipeline works.

## 3. Gateway-side installer

### `internal/registry`

- `Client.FetchIndex(ctx)`: GET `index.json` + `index.json.sig` from
  `GIG_REGISTRY_INDEX_URL` (`https://` or `file://`), verify ed25519 signature
  over the raw index bytes against the trusted public key **before parsing**,
  then parse + validate via the schema module.
- `Index.Resolve(ref)`: ref grammar `name@version` | `name` (→ `latest`) |
  `sha256:<digest>` (exact image-digest lookup).
- `Installer` (implements the seam-§6.B contract the frontend consumes):

```go
type Installer interface {
    Install(ctx context.Context, ref string) (store.Server, error) // idempotent by (name,version)
    Uninstall(ctx context.Context, name string) error
    List(ctx context.Context) ([]store.Server, error)
}
```

`Install`: resolve manifest → pull image by digest (`internal/oci`) → verify →
extract entrypoint to `<GIG_DATA_DIR>/servers/<name>@<version>/server` →
generate placeholder(s) → `EnsureServer(name, extractedPath)` +
`PutManifest(...)`. Same (name,version) already installed → refresh record,
no re-download. New version → record new manifest hash; consent flag goes
stale (§5). `Uninstall`: remove store rows + extracted files (spawned
instances are the run-loop's concern). Record-only: **never spawns**.

### `internal/oci`

- `Pull(ctx, ref, digest)` with go-containerregistry: fetch by digest (no
  daemon, no Docker socket), verify the received manifest/layer digests match
  the pinned digest, flatten layers, extract `image.entrypoint` to a target
  path (0555). Reject images whose entrypoint is missing or non-regular.
- Hermetic tests against a tiny fixture image in OCI-layout format committed
  under testdata (no network).

### `internal/store/manifests.go` (seam §6.A, Option A)

New file + table, additive `CREATE TABLE IF NOT EXISTS` chained in
`OpenSQLite` after `schema`/`credSchema`; no SQLite-only features (DESIGN #14):

```sql
CREATE TABLE IF NOT EXISTS manifests (
  server          TEXT PRIMARY KEY,       -- FK by convention to servers.name
  version         TEXT NOT NULL,
  digest          TEXT NOT NULL,
  tier            TEXT NOT NULL,          -- sealed | entrusted
  entrypoint      TEXT NOT NULL,          -- path inside image
  allowed_hosts   TEXT NOT NULL,          -- newline-joined (credentials.go convention)
  injections      TEXT NOT NULL,          -- JSON: [{id, header, format, env, placeholder}]
  tools           TEXT NOT NULL,          -- JSON: [{name, default}]
  manifest_hash   TEXT NOT NULL,          -- canonical-JSON SHA-256
  consented_hash  TEXT NOT NULL DEFAULT ''-- last hash the user accepted
);
```

Store methods (separate file from frontend's users/profiles/sessions work):
`PutManifest`, `GetManifest(server)`, `ListManifests`, `RecordConsent(server,
hash)`, plus derived `Manifest.NeedsReconsent() bool`
(`manifest_hash != consented_hash`).

### `cmd/gateway/main.go` + config (seam §6.D)

- New helpers (additive, mirroring `seedDemoCredential` style):
  `installFromIndex(ctx, st, inst, cfg)` — installs each ref in `GIG_INSTALL`;
  `spawnInstalled(...)` — current spawn loop, skipping servers with
  `NeedsReconsent` (fail-closed) with a clear log line.
- Config: add `GIG_REGISTRY_INDEX_URL`, `GIG_REGISTRY_PUBKEY` (override),
  `GIG_INSTALL`, `GIG_DATA_DIR`. `GIG_ECHO_BIN` becomes **optional** (legacy
  dev fallback: if set, seed echo exactly as today).

## 4. Enforcement, tool subset, re-consent

### Resolver refactor (seam §6.C)

`CredResolver.Resolve(id, host)` assembles `proxy.Credential` from two sources:

- **manifest** (by `id.Server`): `AllowedHosts`, `InjectHeader`,
  `InjectFormat`, `Placeholder` — the author-declared hard cap;
- **vault** (by `id.Server`, `id.Tenant`): `RealSecret` only.

`proxy.Credential`, `proxy.CredentialResolver`, and the proxy package are
unchanged. Servers without a manifest (legacy `GIG_ECHO_BIN` path) fall back
to the credential row's fields so the demo flow keeps working until removal
is reconciled. v1 enforces the **first** credential's injection at the proxy
(multi-credential proxy rewrite is a follow-up; schema supports it).

### Tool default-subset (#11)

`gateway.New` gains per-backend tool filters (from the manifest's
`default: true` set; nil filter = expose all, preserving legacy behavior).
Non-default tools stay connected but unexposed (future meta-tools path).
Also fix the known multi-backend follow-up (DESIGN §5): reject duplicate
backend names and backend names containing `_`.

### Re-consent (#7)

Install of a changed manifest leaves `consented_hash` stale →
`NeedsReconsent` true → run-loop refuses to spawn (fail-closed) and the
frontend renders the consent prompt from the same flag, calling
`RecordConsent` on acceptance. First install: boot-time installs via
`GIG_INSTALL` are self-consenting (operator-initiated; consent recorded at
install); API installs leave consent to the frontend flow.

## 5. Spikes (before implementation; throwaway code; output = verified-facts blocks)

- **Spike A — OCI pull-by-digest, daemonless, CGO=0** (gates everything):
  prove go-containerregistry can pull by digest, verify, and extract a layer's
  file with `CGO_ENABLED=0`, building a static binary; record dependency
  footprint. Fallbacks: containerd client libs, umoci.
- **Spike B — signed index**: canonical-JSON bytes, `crypto/ed25519` keygen/
  sign/verify round-trip, key encoding (hex/PEM) for Actions secret + baked-in
  pubkey.
- **Spike C — rootfs under existing sandbox** (informs the *follow-up* plan,
  not v1): extract a real Node/Python server image; confirm single-binary
  mount cannot run it; sketch the minimal `sandbox.Spec` extension (e.g.
  `RootfsDir`) to propose to the sandbox owner.

## 6. Testing strategy

- TDD throughout (red-green-refactor), per repo discipline.
- Pure-Go logic (schema, lint, index sign/verify, resolve, store, installer
  against fixtures) runs on macOS via `make test-local`.
- Fixtures committed under testdata: a signed fixture index (+ a second,
  tampered copy), a tiny OCI-layout image containing one static binary.
- Spawn/aggregator integration (installed server actually runs sandboxed;
  default-subset visible over MCP; manifest allowlist enforced at the proxy)
  runs in the Linux container via `make test`.
- `CGO_ENABLED=0` static build asserted in CI after adding the OCI dep.
- Registry-repo CI exercises itself (lint fixtures with deliberate
  violations).

## 7. Out of scope (this plan)

- Full-rootfs / Node / Python servers (follow-up plan after Spike C +
  sandbox-owner agreement; **no `internal/sandbox` edits here**).
- `npx`/`uvx` escape hatch (post-v1, DESIGN #9).
- Auth/users/profiles/REST API/dashboard (frontend workstream).
- Dropping legacy credential-row columns (reconcile with frontend agent).
- Meta-tools mode; per-profile tool toggles (frontend, on top of the
  default-subset data).
- Multi-credential proxy rewrite (schema supports; enforcement v1 = first
  credential).

## 8. Build order

Spike A → Spike B → schema module (registry repo) → store `manifests.go` →
`internal/oci` → `internal/registry` + Installer → resolver refactor →
aggregator filter + name validation → main.go/config wiring → registry repo
CI + echo/fetch manifests + README/CONTRIBUTING → container E2E → Spike C
(feeds the follow-up rootfs plan).
