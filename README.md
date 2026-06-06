# gigemcp

Open-source, security-first MCP gateway: run community MCP servers
**sandboxed**, with credentials injected at the
network boundary so one compromised tool can never expose your keys
*(credential injection is on the roadmap; see below)*. See [DESIGN.md](DESIGN.md)
for the full architecture and decision record. AGPL-3.0.

> **Status: walking skeleton.** One bundled echo server, bearer auth,
> bubblewrap sandboxing, SQLite. Egress proxy, credential vault, registry,
> multi-user auth, and dashboard are landing per DESIGN.md §5.

## Quickstart

```bash
GIGE_BEARER_TOKEN=$(openssl rand -hex 24) docker compose up --build -d
```

Connect Claude Code:

```bash
claude mcp add --transport http gigemcp http://localhost:8080 \
  --header "Authorization: Bearer <your token>"
```

You should see one tool, `echo_echo`, served by an MCP server running in a
bubblewrap sandbox: no network, no host filesystem, cleared environment.

## Development

```bash
make test        # full suite incl. sandbox tests, in a Linux container
make test-local  # host-side subset (sandbox tests skip on macOS)
```
