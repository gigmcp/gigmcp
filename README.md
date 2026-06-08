# Gig'MCP

Gig'MCP is an open-source, security-first MCP gateway: run community MCP
servers **sandboxed**, with credentials injected at the
network boundary so one compromised tool never exposes your keys.
See [DESIGN.md](DESIGN.md)
for the full architecture and decision record.

> **Status: profile-scoped endpoints + OIDC control plane.** Per-profile MCP
> endpoints (`/mcp/p/<profile>`) with per-profile tokens, OIDC-backed REST API
> and dashboard, signed registry installs, bubblewrap sandboxing, SQLite,
> embedded MITM egress proxy with XChaCha20-Poly1305 envelope-encrypted vault.
> Each sandbox runs in its own network namespace; the only route is the proxy;
> credentials never enter the sandbox (placeholder-in-env → real key injected
> at the proxy boundary).

## Quickstart

All MCP endpoints are profile-scoped and authenticated by per-profile bearer
tokens, which can only be minted through the OIDC-gated dashboard/REST API —
so a fresh install needs an OIDC identity provider configured:

```bash
GIG_MASTER_KEY=$(openssl rand -hex 32) \
GIG_OIDC_ISSUER=https://<your-idp> \
GIG_OIDC_CLIENT_ID=<client-id> \
GIG_OIDC_REDIRECT_URL=http://localhost:8080/api/auth/callback \
docker compose up --build -d
```

No IdP handy? `docker-compose.dev.yml` provides a Zitadel fixture at
`http://localhost:8082` (console: `/ui/console`, admin / Password1!) — bring it
up first with `docker compose -f docker-compose.dev.yml up -d`, create an OIDC
client there, and point `GIG_OIDC_ISSUER` at `http://localhost:8082`.

**Required environment variables:**

| Variable | Description |
|---|---|
| `GIG_MASTER_KEY` | 32-byte hex master key for the credential vault (`openssl rand -hex 32`) |

**OIDC control plane** (all-or-none; required to create profiles and mint
profile tokens — only an already-provisioned gateway can leave these unset, in
which case `/api` and the dashboard are disabled while existing profile MCP
endpoints keep working):

| Variable | Description |
|---|---|
| `GIG_OIDC_ISSUER` | OIDC issuer URL (e.g. your Zitadel/Okta/Authentik instance) |
| `GIG_OIDC_CLIENT_ID` | OIDC client id |
| `GIG_OIDC_REDIRECT_URL` | Callback URL, e.g. `http://localhost:8080/api/auth/callback` |
| `GIG_OIDC_CLIENT_SECRET` | Optional (omit for PKCE public clients); `_FILE` variant supported |

**Runtime requirements:** the gateway container needs `cap_add: NET_ADMIN` (already
in `docker-compose.yml`). No `SYS_ADMIN` or privileged mode is needed — `NET_ADMIN`
is sufficient for creating veth pairs and moving them into sandbox network namespaces.

**Credential injection model:** each sandbox receives only a placeholder token
(`PLACEHOLDER`) in its environment. When the server makes an outbound HTTPS call,
the embedded proxy identifies the tenant by the connection's source IP (unforgeable
— each sandbox sits in its own `/30`), checks the domain allowlist, and swaps the
placeholder for the vault-decrypted real key. The real key never enters the sandbox.

**Connecting an MCP client:** every MCP endpoint is profile-scoped. Create a
profile in the dashboard (`http://localhost:3000`, OIDC login) or via the REST
API, assign servers to it, and mint a profile token (shown exactly once). Then:

```bash
claude mcp add --transport http gigmcp http://localhost:8080/mcp/p/<profile-slug> \
  --header "Authorization: Bearer <profile token>"
```

Each server in the profile runs in an egress-isolated bubblewrap sandbox:
private network namespace, no host filesystem, cleared environment, credential
injected only at the proxy.

## Building

A plain clone is all you need: the registry schema is consumed as a published
Go module ([github.com/gigmcp/registry/schema](https://github.com/gigmcp/registry),
pinned in `go.mod`) and fetched from the Go module proxy during the build, so
`git clone` followed by the `docker compose up` invocation from the
[Quickstart](#quickstart) (which sets the required environment variables)
builds and runs everything from this repository alone.

## Development

```bash
make test        # full suite incl. sandbox + egress + vault tests, in a Linux container
make test-local  # host-side subset (Linux-only tests skip on macOS)
```

## License

[AGPL-3.0](LICENSE).
