# gigemcp

Open-source, security-first MCP gateway: run community MCP servers
**sandboxed**, with credentials injected at the
network boundary so one compromised tool never exposes your keys.
See [DESIGN.md](DESIGN.md)
for the full architecture and decision record. AGPL-3.0.

> **Status: egress proxy + credential vault complete.** One bundled echo server,
> bearer auth, bubblewrap sandboxing, SQLite, embedded MITM egress proxy with
> XChaCha20-Poly1305 envelope-encrypted vault. Each sandbox runs in its own
> network namespace; the only route is the proxy; credentials never enter the
> sandbox (placeholder-in-env → real key injected at the proxy boundary).
> Registry, multi-user auth, and dashboard are landing per DESIGN.md §5.

## Quickstart

```bash
GIGE_BEARER_TOKEN=$(openssl rand -hex 24) \
GIGE_MASTER_KEY=$(openssl rand -hex 32) \
docker compose up --build -d
```

**Required environment variables:**

| Variable | Description |
|---|---|
| `GIGE_BEARER_TOKEN` | Bearer token for authenticating MCP clients |
| `GIGE_MASTER_KEY` | 32-byte hex master key for the credential vault (`openssl rand -hex 32`) |

**Optional:**

| Variable | Description |
|---|---|
| `GIGE_DEMO_TOKEN` | Seeds a demo credential for the echo server on startup |
| `GIGE_DEMO_ALLOW` | Comma-separated allowed hosts for the demo credential (default: `api.example.com`) |

**Runtime requirements:** the gateway container needs `cap_add: NET_ADMIN` (already
in `docker-compose.yml`). No `SYS_ADMIN` or privileged mode is needed — `NET_ADMIN`
is sufficient for creating veth pairs and moving them into sandbox network namespaces.

**Credential injection model:** each sandbox receives only a placeholder token
(`PLACEHOLDER`) in its environment. When the server makes an outbound HTTPS call,
the embedded proxy identifies the tenant by the connection's source IP (unforgeable
— each sandbox sits in its own `/30`), checks the domain allowlist, and swaps the
placeholder for the vault-decrypted real key. The real key never enters the sandbox.

Connect Claude Code:

```bash
claude mcp add --transport http gigemcp http://localhost:8080 \
  --header "Authorization: Bearer <your token>"
```

You should see one tool, `echo_echo`, served by an MCP server running in an
egress-isolated bubblewrap sandbox: private network namespace, no host filesystem,
cleared environment, credential injected only at the proxy.

## Development

```bash
make test        # full suite incl. sandbox + egress + vault tests, in a Linux container
make test-local  # host-side subset (Linux-only tests skip on macOS)
```
