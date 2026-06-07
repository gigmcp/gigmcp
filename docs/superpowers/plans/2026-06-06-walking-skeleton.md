# Walking Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An end-to-end thread through gigmcp: a Go gateway serving a bearer-authed streamable-HTTP MCP endpoint that spawns one echo MCP server inside a bubblewrap sandbox and proxies namespaced tool calls to it, backed by SQLite.

**Architecture:** The gateway is an MCP *server* to clients (streamable HTTP) and an MCP *client* to each sandboxed backend (stdio over `CommandTransport` wrapping a `bwrap` command). Tools are re-exposed as `<backend>_<tool>`. This is DESIGN.md §7 step 1 — it deliberately proves the riskiest seams (bwrap-in-Docker, MCP session ↔ sandbox lifecycle) before any subsystem gets deep. Subsequent plans (egress proxy, vault/manifests, registry CI, auth/multi-user, dashboard) build on these seams.

**Tech Stack:** Go (module `github.com/gigmcp/gigmcp`), `github.com/modelcontextprotocol/go-sdk` **v1.6.1** (API signatures below were verified against this version), `modernc.org/sqlite` (pure Go — keeps CGO_ENABLED=0 static builds), bubblewrap, Docker.

**Critical environment fact:** bwrap, namespaces, and Landlock do not exist on macOS. The dev machine is a Mac, so **all sandbox-touching tests run inside a Linux container** (`make test`). Sandbox tests skip themselves on macOS via `sandbox.Available()`. Pure-logic tests run anywhere (`make test-local`).

**SDK API cheat sheet (verified v1.6.1 — do not "fix" these from memory):**
- `mcp.NewServer(&mcp.Implementation{Name, Version}, *mcp.ServerOptions) *mcp.Server`
- `(*mcp.Server).AddTool(t *mcp.Tool, h mcp.ToolHandler)` — raw handler `func(ctx, *mcp.CallToolRequest) (*mcp.CallToolResult, error)`; `req.Params.Arguments` is `json.RawMessage`
- `mcp.AddTool[In, Out](s, t, h mcp.ToolHandlerFor[In, Out])` — typed handler `func(ctx, *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error)`
- `(*mcp.Client).Connect(ctx, transport, *mcp.ClientSessionOptions) (*mcp.ClientSession, error)`
- `(*mcp.Server).Connect(ctx, transport, *mcp.ServerSessionOptions) (*mcp.ServerSession, error)`
- `mcp.NewInMemoryTransports() (*mcp.InMemoryTransport, *mcp.InMemoryTransport)` — **connect the server before the client**
- `&mcp.CommandTransport{Command: *exec.Cmd}`, `&mcp.StdioTransport{}`
- `mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server, *mcp.StreamableHTTPOptions) http.Handler`
- `&mcp.StreamableClientTransport{Endpoint: url, HTTPClient: *http.Client}`
- `(*mcp.ClientSession).ListTools(ctx, *mcp.ListToolsParams) (*mcp.ListToolsResult, error)`
- `(*mcp.ClientSession).CallTool(ctx, &mcp.CallToolParams{Name string, Arguments any}) (*mcp.CallToolResult, error)`
- Text content: `&mcp.TextContent{Text: string}` (implements `mcp.Content`)

---

## File Structure

```
gigmcp/
├── DESIGN.md                      # exists — commit as-is
├── LICENSE                        # AGPL-3.0 (Task 1)
├── README.md                      # quickstart (Task 10)
├── .gitignore                     # (Task 1)
├── go.mod / go.sum                # (Task 1)
├── Makefile                       # test = in Docker, test-local = host (Task 2)
├── Dockerfile.dev                 # golang + bubblewrap, for tests (Task 2)
├── Dockerfile                     # production multi-stage build (Task 10)
├── docker-compose.yml             # gateway service (Task 10)
├── cmd/
│   ├── gateway/main.go            # wiring: config→store→sandbox→sessions→HTTP (Task 8)
│   └── echo-mcp/main.go           # stdio entrypoint for the echo server (Task 3)
├── internal/
│   ├── echo/echo.go               # echo MCP server as a library (Task 3)
│   ├── echo/echo_test.go
│   ├── sandbox/sandbox.go         # Spec → bwrap *exec.Cmd; Available() (Task 4)
│   ├── sandbox/sandbox_test.go    # Linux-only isolation tests
│   ├── store/store.go             # Store interface + Server record (Task 5)
│   ├── store/sqlite.go            # modernc.org/sqlite impl + schema
│   ├── store/sqlite_test.go
│   ├── config/config.go           # env-var config (Task 7)
│   ├── config/config_test.go
│   └── gateway/
│       ├── auth.go                # bearer middleware (Task 6)
│       ├── auth_test.go
│       ├── gateway.go             # tool aggregator/proxy (Task 7)
│       ├── gateway_test.go        # in-memory aggregation test
│       └── e2e_test.go            # HTTP client → gateway → bwrap echo (Task 9)
└── docs/superpowers/plans/        # this file
```

Responsibilities: `echo` knows nothing about sandboxing; `sandbox` knows nothing about MCP; `gateway` knows nothing about bwrap or SQLite (it receives ready `*mcp.ClientSession`s); only `cmd/gateway/main.go` composes them. These seams are where the egress proxy, supervisor, and vault plans will later attach.

---

### Task 1: Repository scaffolding

**Files:**
- Create: `.gitignore`, `LICENSE`, `go.mod`, `go.sum`

- [ ] **Step 1: Init repo and Go module**

```bash
cd /Users/julianbeaulieu/Code/gigmcp
git init -b main
go mod init github.com/gigmcp/gigmcp
```

- [ ] **Step 2: Create `.gitignore`**

```gitignore
/bin/
*.db
.env
```

- [ ] **Step 3: Fetch the AGPL-3.0 license text**

```bash
curl -fsSL https://www.gnu.org/licenses/agpl-3.0.txt -o LICENSE
head -3 LICENSE   # expect: "GNU AFFERO GENERAL PUBLIC LICENSE / Version 3, 19 November 2007"
```

- [ ] **Step 4: Add dependencies**

```bash
go get github.com/modelcontextprotocol/go-sdk@v1.6.1
go get modernc.org/sqlite@latest
```

Expected: `go.mod` lists both; `go.sum` created.

- [ ] **Step 5: Commit**

```bash
git add .gitignore LICENSE go.mod go.sum DESIGN.md docs/
git commit -m "chore: scaffold repo — AGPL-3.0, Go module, design doc"
```

---

### Task 2: Dev container + Makefile (test infrastructure first)

**Files:**
- Create: `Dockerfile.dev`, `Makefile`

- [ ] **Step 1: Create `Dockerfile.dev`**

```dockerfile
FROM golang:1.25-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends bubblewrap \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
```

- [ ] **Step 2: Create `Makefile`**

```makefile
DEV_IMAGE := gigmcp-dev

.PHONY: dev-image test test-local

dev-image:
	docker build -f Dockerfile.dev -t $(DEV_IMAGE) .

# Full suite, including sandbox tests — runs on Linux inside Docker.
# seccomp/apparmor are relaxed because bwrap needs unprivileged user
# namespaces, which Docker's default profiles block (see DESIGN.md §3).
test: dev-image
	docker run --rm \
		--security-opt seccomp=unconfined \
		--security-opt apparmor=unconfined \
		-v $(PWD):/src -w /src \
		-v gigmcp-gomod:/go/pkg/mod \
		-v gigmcp-gocache:/root/.cache/go-build \
		$(DEV_IMAGE) go test ./...

# Host-side subset — sandbox tests self-skip on macOS.
test-local:
	go test ./...
```

- [ ] **Step 3: Verify the harness runs (no packages yet — expect "no Go files" style success/no-op)**

```bash
make test
```

Expected: image builds; `go test ./...` reports `no packages to test` or similar, exit 0. (If `go test` exits non-zero on an empty module, that's fine — the harness itself ran; it goes green in Task 3.)

- [ ] **Step 4: Commit**

```bash
git add Dockerfile.dev Makefile
git commit -m "chore: dev container with bubblewrap + make test harness"
```

---

### Task 3: Echo MCP server

**Files:**
- Create: `internal/echo/echo.go`, `cmd/echo-mcp/main.go`
- Test: `internal/echo/echo_test.go`

- [ ] **Step 1: Write the failing test** — `internal/echo/echo_test.go`

```go
package echo_test

import (
	"context"
	"testing"

	"github.com/gigmcp/gigmcp/internal/echo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestEchoTool(t *testing.T) {
	ctx := context.Background()
	clientTr, serverTr := mcp.NewInMemoryTransports()

	srv := echo.NewServer()
	serverSess, err := srv.Connect(ctx, serverTr, nil) // server first, then client
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer serverSess.Close()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	sess, err := client.Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer sess.Close()

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo",
		Arguments: map[string]any{"message": "hi"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("want 1 content item, got %d", len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("want TextContent, got %T", res.Content[0])
	}
	if text.Text != "echo: hi" {
		t.Errorf("got %q, want %q", text.Text, "echo: hi")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/echo/
```

Expected: FAIL — `no required module provides package github.com/gigmcp/gigmcp/internal/echo` / undefined `echo.NewServer`.

- [ ] **Step 3: Write the implementation** — `internal/echo/echo.go`

```go
// Package echo provides a trivial MCP server used by the walking skeleton
// to prove the gateway→sandbox→backend path end to end.
package echo

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Args are the input arguments of the echo tool.
type Args struct {
	Message string `json:"message" jsonschema:"the text to echo back"`
}

// NewServer returns an MCP server exposing a single "echo" tool.
func NewServer() *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "echo-mcp", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "echo", Description: "Echoes a message back"},
		func(ctx context.Context, req *mcp.CallToolRequest, in Args) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{Text: "echo: " + in.Message}},
			}, nil, nil
		})
	return s
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/echo/
```

Expected: PASS.

- [ ] **Step 5: Write the stdio entrypoint** — `cmd/echo-mcp/main.go`

```go
// Command echo-mcp runs the echo MCP server over stdio. The gateway executes
// this binary inside a bubblewrap sandbox.
package main

import (
	"context"
	"log"

	"github.com/gigmcp/gigmcp/internal/echo"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	if err := echo.NewServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
```

- [ ] **Step 6: Verify it builds**

```bash
go build ./... && go vet ./...
```

Expected: exit 0.

- [ ] **Step 7: Commit**

```bash
git add internal/echo/ cmd/echo-mcp/
git commit -m "feat: echo MCP server (skeleton backend)"
```

---

### Task 4: Sandbox package (bwrap wrapper)

**Files:**
- Create: `internal/sandbox/sandbox.go`
- Test: `internal/sandbox/sandbox_test.go`

- [ ] **Step 1: Write the failing tests** — `internal/sandbox/sandbox_test.go`

```go
package sandbox_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/sandbox"
)

func requireSandbox(t *testing.T) {
	t.Helper()
	if !sandbox.Available() {
		t.Skip("sandbox requires Linux with bwrap installed — run `make test`")
	}
}

func runShell(t *testing.T, script string) (string, error) {
	t.Helper()
	cmd := sandbox.Command(sandbox.Spec{
		Exec:   "/bin/sh",
		Args:   []string{"-c", script},
		Mounts: sandbox.ShellMounts(),
	})
	out, err := cmd.Output()
	return string(out), err
}

func TestRunsCommand(t *testing.T) {
	requireSandbox(t)
	out, err := runShell(t, "echo hi")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(out); got != "hi" {
		t.Errorf("got %q, want %q", got, "hi")
	}
}

func TestNoNetworkInterfaces(t *testing.T) {
	requireSandbox(t)
	out, err := runShell(t, "cat /proc/net/dev")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "lo:") {
		t.Errorf("expected loopback to exist, got:\n%s", out)
	}
	if strings.Contains(out, "eth0") {
		t.Errorf("sandbox sees host network interface eth0:\n%s", out)
	}
}

func TestHostFilesHidden(t *testing.T) {
	requireSandbox(t)
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("key-material"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The host path is not bind-mounted, so reading it must fail.
	if _, err := runShell(t, "cat "+secret); err == nil {
		t.Fatal("sandbox could read an unmounted host file")
	}
}

func TestEnvCleared(t *testing.T) {
	requireSandbox(t)
	t.Setenv("GIG_SECRET_CANARY", "leak")
	out, err := runShell(t, "env")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "GIG_SECRET_CANARY") {
		t.Errorf("host environment leaked into sandbox:\n%s", out)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/sandbox/
```

Expected: FAIL — undefined `sandbox.Available`, `sandbox.Command`, etc. (compile error).

- [ ] **Step 3: Write the implementation** — `internal/sandbox/sandbox.go`

```go
// Package sandbox builds bubblewrap commands that run untrusted MCP servers
// in fresh user/pid/net/mount/ipc/uts namespaces with a read-only view of
// exactly the files they were granted (DESIGN.md decisions #3, #5).
package sandbox

import (
	"os/exec"
	"runtime"
)

// Mount is a read-only bind mount from host Src to sandbox Dst.
type Mount struct {
	Src      string
	Dst      string
	Optional bool // tolerate a missing Src (--ro-bind-try)
}

// Spec describes a process to run inside the sandbox.
type Spec struct {
	Exec   string  // path of the executable *inside* the sandbox
	Args   []string
	Mounts []Mount // the executable itself must be covered by one of these
}

// Available reports whether bwrap sandboxing can run on this host.
func Available() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("bwrap")
	return err == nil
}

// Command builds an *exec.Cmd running spec under bwrap with no network,
// fresh namespaces, a private /tmp, and a cleared environment. Stdio is
// inherited/wired by the caller (the MCP CommandTransport uses it).
func Command(spec Spec) *exec.Cmd {
	args := []string{
		"--die-with-parent", // no orphaned servers if the gateway dies
		"--unshare-all",     // user, pid, net, mount, ipc, uts, cgroup
		"--clearenv",
		"--setenv", "PATH", "/usr/bin:/bin",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--chdir", "/",
	}
	for _, m := range spec.Mounts {
		flag := "--ro-bind"
		if m.Optional {
			flag = "--ro-bind-try"
		}
		args = append(args, flag, m.Src, m.Dst)
	}
	args = append(args, spec.Exec)
	args = append(args, spec.Args...)
	return exec.Command("bwrap", args...)
}

// ShellMounts returns the binds needed to run /bin/sh (tests only).
func ShellMounts() []Mount {
	return []Mount{
		{Src: "/bin", Dst: "/bin"},
		{Src: "/usr", Dst: "/usr"},
		{Src: "/lib", Dst: "/lib", Optional: true},
		{Src: "/lib64", Dst: "/lib64", Optional: true},
	}
}
```

- [ ] **Step 4: Run the full suite in the Linux container to verify it passes**

```bash
make test
```

Expected: `internal/sandbox` PASS (4 tests run, none skipped); `internal/echo` PASS. If sandbox tests fail with `bwrap: ... Operation not permitted`, the Docker flags from Task 2's Makefile are missing — do not weaken the sandbox args to compensate.

- [ ] **Step 5: Verify the macOS skip path**

```bash
make test-local
```

Expected: sandbox tests report SKIP, everything else PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/sandbox/
git commit -m "feat: bubblewrap sandbox wrapper with isolation tests"
```

---

### Task 5: SQLite store

**Files:**
- Create: `internal/store/store.go`, `internal/store/sqlite.go`
- Test: `internal/store/sqlite_test.go`

- [ ] **Step 1: Write the failing test** — `internal/store/sqlite_test.go`

```go
package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestEnsureAndListServers(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	first, err := st.EnsureServer(ctx, "echo", "/usr/local/bin/echo-mcp")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if first.ID == 0 || first.Name != "echo" || first.Binary != "/usr/local/bin/echo-mcp" {
		t.Errorf("unexpected record: %+v", first)
	}

	// Idempotent upsert by name: same ID, updated binary.
	second, err := st.EnsureServer(ctx, "echo", "/new/path/echo-mcp")
	if err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("upsert created a new row: %d != %d", second.ID, first.ID)
	}
	if second.Binary != "/new/path/echo-mcp" {
		t.Errorf("binary not updated: %q", second.Binary)
	}

	servers, err := st.ListServers(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("want 1 server, got %d", len(servers))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/store/
```

Expected: FAIL — undefined `store.OpenSQLite` (compile error).

- [ ] **Step 3: Write the interface** — `internal/store/store.go`

```go
// Package store persists gateway state. The interface is deliberately
// driver-agnostic: DESIGN.md decision #14 requires SQLite and Postgres
// backends with no driver-specific features in core.
package store

import "context"

// Server is a registered MCP server the gateway should run.
type Server struct {
	ID     int64
	Name   string // unique; used as the tool namespace prefix
	Binary string // absolute host path to the server's binary
}

// Store persists gateway state.
type Store interface {
	// EnsureServer upserts a server by name and returns the stored record.
	EnsureServer(ctx context.Context, name, binary string) (Server, error)
	// ListServers returns all registered servers ordered by name.
	ListServers(ctx context.Context) ([]Server, error)
	Close() error
}
```

- [ ] **Step 4: Write the SQLite implementation** — `internal/store/sqlite.go`

```go
package store

import (
	"context"
	"database/sql"

	_ "modernc.org/sqlite" // pure-Go driver; keeps CGO_ENABLED=0 builds
)

type sqliteStore struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS servers (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	name   TEXT NOT NULL UNIQUE,
	binary TEXT NOT NULL
);`

// OpenSQLite opens (creating if necessary) a SQLite-backed Store at path.
func OpenSQLite(path string) (Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &sqliteStore{db: db}, nil
}

func (s *sqliteStore) EnsureServer(ctx context.Context, name, binary string) (Server, error) {
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO servers (name, binary) VALUES (?, ?)
		 ON CONFLICT(name) DO UPDATE SET binary = excluded.binary`,
		name, binary); err != nil {
		return Server{}, err
	}
	var srv Server
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, binary FROM servers WHERE name = ?`, name).
		Scan(&srv.ID, &srv.Name, &srv.Binary)
	return srv, err
}

func (s *sqliteStore) ListServers(ctx context.Context) ([]Server, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, binary FROM servers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var servers []Server
	for rows.Next() {
		var srv Server
		if err := rows.Scan(&srv.ID, &srv.Name, &srv.Binary); err != nil {
			return nil, err
		}
		servers = append(servers, srv)
	}
	return servers, rows.Err()
}

func (s *sqliteStore) Close() error { return s.db.Close() }
```

- [ ] **Step 5: Run test to verify it passes**

```bash
go test ./internal/store/
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/
git commit -m "feat: server store with SQLite backend"
```

---

### Task 6: Bearer auth middleware

**Files:**
- Create: `internal/gateway/auth.go`
- Test: `internal/gateway/auth_test.go`

- [ ] **Step 1: Write the failing test** — `internal/gateway/auth_test.go`

```go
package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
)

func TestRequireBearer(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := gateway.RequireBearer("sekrit", next)

	cases := []struct {
		name   string
		header string
		want   int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic sekrit", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"token as prefix", "Bearer sekrit2", http.StatusUnauthorized},
		{"correct", "Bearer sekrit", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Errorf("got %d, want %d", rec.Code, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/gateway/
```

Expected: FAIL — undefined `gateway.RequireBearer` (compile error).

- [ ] **Step 3: Write the implementation** — `internal/gateway/auth.go`

```go
package gateway

import (
	"crypto/subtle"
	"net/http"
)

// RequireBearer rejects requests whose Authorization header is not exactly
// "Bearer <token>", using a constant-time comparison.
func RequireBearer(token string, next http.Handler) http.Handler {
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		// ConstantTimeCompare returns 0 for length mismatches.
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/gateway/
```

Expected: PASS (5 subtests).

- [ ] **Step 5: Commit**

```bash
git add internal/gateway/auth.go internal/gateway/auth_test.go
git commit -m "feat: constant-time bearer auth middleware"
```

---

### Task 7: Tool aggregator + config

**Files:**
- Create: `internal/gateway/gateway.go`, `internal/config/config.go`
- Test: `internal/gateway/gateway_test.go`, `internal/config/config_test.go`

- [ ] **Step 1: Write the failing aggregator test** — `internal/gateway/gateway_test.go`

```go
package gateway_test

import (
	"context"
	"testing"

	"github.com/gigmcp/gigmcp/internal/echo"
	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectEchoBackend wires an in-memory echo server and returns a client
// session to it, as the gateway would hold for a sandboxed backend.
func connectEchoBackend(t *testing.T, ctx context.Context) *mcp.ClientSession {
	t.Helper()
	clientTr, serverTr := mcp.NewInMemoryTransports()
	srv := echo.NewServer()
	serverSess, err := srv.Connect(ctx, serverTr, nil)
	if err != nil {
		t.Fatalf("backend server connect: %v", err)
	}
	t.Cleanup(func() { serverSess.Close() })

	c := mcp.NewClient(&mcp.Implementation{Name: "gigmcp-gw", Version: "test"}, nil)
	sess, err := c.Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatalf("backend client connect: %v", err)
	}
	t.Cleanup(func() { sess.Close() })
	return sess
}

func TestAggregatorNamespacesAndProxies(t *testing.T) {
	ctx := context.Background()
	backend := connectEchoBackend(t, ctx)

	gw, err := gateway.New(ctx, "test", []gateway.Backend{{Name: "echo", Session: backend}})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}

	// Connect a client to the aggregating gateway itself.
	clientTr, serverTr := mcp.NewInMemoryTransports()
	gwSess, err := gw.Connect(ctx, serverTr, nil)
	if err != nil {
		t.Fatalf("gateway connect: %v", err)
	}
	defer gwSess.Close()
	c := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.0"}, nil)
	sess, err := c.Connect(ctx, clientTr, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer sess.Close()

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo_echo" {
		t.Fatalf("want exactly [echo_echo], got %+v", tools.Tools)
	}

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo_echo",
		Arguments: map[string]any{"message": "hi"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "echo: hi" {
		t.Fatalf("got %+v, want text %q", res.Content[0], "echo: hi")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/gateway/
```

Expected: FAIL — undefined `gateway.New`, `gateway.Backend` (compile error).

- [ ] **Step 3: Write the aggregator** — `internal/gateway/gateway.go`

```go
// Package gateway aggregates backend MCP servers behind one MCP server,
// re-exposing every backend tool as <backend>_<tool> (DESIGN.md decision #11;
// profiles arrive in a later plan — the skeleton has one implicit profile).
package gateway

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Backend is a connected upstream MCP server.
type Backend struct {
	Name    string // namespace prefix for its tools
	Session *mcp.ClientSession
}

// New builds the aggregating MCP server over the given backends.
func New(ctx context.Context, version string, backends []Backend) (*mcp.Server, error) {
	gw := mcp.NewServer(&mcp.Implementation{Name: "gigmcp", Version: version}, nil)
	for _, b := range backends {
		sess := b.Session
		tools, err := sess.ListTools(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("list tools for backend %q: %w", b.Name, err)
		}
		for _, tool := range tools.Tools {
			upstream := tool.Name
			proxied := *tool
			proxied.Name = b.Name + "_" + upstream
			gw.AddTool(&proxied, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				// Raw pass-through: arguments forwarded verbatim; the
				// backend performs its own validation.
				return sess.CallTool(ctx, &mcp.CallToolParams{
					Name:      upstream,
					Arguments: req.Params.Arguments,
				})
			})
		}
	}
	return gw, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/gateway/
```

Expected: PASS (auth + aggregator tests).

- [ ] **Step 5: Write the failing config test** — `internal/config/config_test.go`

```go
package config_test

import (
	"testing"

	"github.com/gigmcp/gigmcp/internal/config"
)

func TestFromEnv(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_ECHO_BIN", "/usr/local/bin/echo-mcp")
	t.Setenv("GIG_LISTEN", "")
	t.Setenv("GIG_DB_PATH", "")

	cfg, err := config.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("Listen default: got %q", cfg.Listen)
	}
	if cfg.DBPath != "gigmcp.db" {
		t.Errorf("DBPath default: got %q", cfg.DBPath)
	}
	if cfg.BearerToken != "tok" || cfg.EchoBinary != "/usr/local/bin/echo-mcp" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
}

func TestFromEnvRequiresToken(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "")
	t.Setenv("GIG_ECHO_BIN", "/x")
	if _, err := config.FromEnv(); err == nil {
		t.Fatal("expected error when GIG_BEARER_TOKEN is empty")
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

```bash
go test ./internal/config/
```

Expected: FAIL — package does not exist.

- [ ] **Step 7: Write the config** — `internal/config/config.go`

```go
// Package config reads gateway configuration from the environment
// (compose-env-first per DESIGN.md decision; secrets gain *_FILE support
// in the vault plan).
package config

import (
	"errors"
	"os"
)

// Config is the gateway's runtime configuration.
type Config struct {
	Listen      string // GIG_LISTEN, default ":8080"
	BearerToken string // GIG_BEARER_TOKEN, required
	DBPath      string // GIG_DB_PATH, default "gigmcp.db"
	EchoBinary  string // GIG_ECHO_BIN, required (skeleton's seeded backend)
}

// FromEnv loads Config from environment variables.
func FromEnv() (Config, error) {
	cfg := Config{
		Listen:      envOr("GIG_LISTEN", ":8080"),
		BearerToken: os.Getenv("GIG_BEARER_TOKEN"),
		DBPath:      envOr("GIG_DB_PATH", "gigmcp.db"),
		EchoBinary:  os.Getenv("GIG_ECHO_BIN"),
	}
	if cfg.BearerToken == "" {
		return Config{}, errors.New("GIG_BEARER_TOKEN must be set")
	}
	if cfg.EchoBinary == "" {
		return Config{}, errors.New("GIG_ECHO_BIN must be set")
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
```

- [ ] **Step 8: Run tests to verify they pass**

```bash
go test ./internal/config/ ./internal/gateway/
```

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/gateway/gateway.go internal/gateway/gateway_test.go internal/config/
git commit -m "feat: tool aggregator with namespacing + env config"
```

---

### Task 8: Gateway main wiring

**Files:**
- Create: `cmd/gateway/main.go`

- [ ] **Step 1: Write main** — `cmd/gateway/main.go`

```go
// Command gateway is the gigmcp walking skeleton: it seeds the echo server
// in the store, spawns each stored server in a bubblewrap sandbox, and
// serves an aggregated, bearer-authed streamable-HTTP MCP endpoint.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/gigmcp/gigmcp/internal/config"
	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/sandbox"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const version = "0.1.0-skeleton"

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if !sandbox.Available() {
		return fmt.Errorf("bwrap sandboxing unavailable: gigmcp requires Linux with bubblewrap installed")
	}

	st, err := store.OpenSQLite(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Skeleton: seed the single echo backend. Registry-driven installs
	// replace this in the manifests plan.
	if _, err := st.EnsureServer(ctx, "echo", cfg.EchoBinary); err != nil {
		return fmt.Errorf("seed echo server: %w", err)
	}

	servers, err := st.ListServers(ctx)
	if err != nil {
		return fmt.Errorf("list servers: %w", err)
	}

	var backends []gateway.Backend
	for _, srv := range servers {
		cmd := sandbox.Command(sandbox.Spec{
			Exec:   "/app/server",
			Mounts: []sandbox.Mount{{Src: srv.Binary, Dst: "/app/server"}},
		})
		client := mcp.NewClient(&mcp.Implementation{Name: "gigmcp-gw", Version: version}, nil)
		sess, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
		if err != nil {
			return fmt.Errorf("connect backend %q: %w", srv.Name, err)
		}
		defer sess.Close()
		backends = append(backends, gateway.Backend{Name: srv.Name, Session: sess})
		log.Printf("backend %q running sandboxed (%s)", srv.Name, srv.Binary)
	}

	gw, err := gateway.New(ctx, version, backends)
	if err != nil {
		return err
	}
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return gw }, nil)
	log.Printf("gigmcp %s listening on %s (%d backend(s))", version, cfg.Listen, len(backends))
	return http.ListenAndServe(cfg.Listen, gateway.RequireBearer(cfg.BearerToken, handler))
}
```

- [ ] **Step 2: Verify it builds and vets**

```bash
go build ./... && go vet ./...
```

Expected: exit 0.

- [ ] **Step 3: Commit**

```bash
git add cmd/gateway/
git commit -m "feat: gateway main — store, sandboxed backends, authed MCP endpoint"
```

---

### Task 9: End-to-end test

**Files:**
- Test: `internal/gateway/e2e_test.go`

- [ ] **Step 1: Write the failing E2E test** — `internal/gateway/e2e_test.go`

```go
package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/gateway"
	"github.com/gigmcp/gigmcp/internal/sandbox"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildEchoBinary compiles cmd/echo-mcp as a static binary for the sandbox.
func buildEchoBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "echo-mcp")
	cmd := exec.Command("go", "build", "-o", out, "github.com/gigmcp/gigmcp/cmd/echo-mcp")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build echo-mcp: %v\n%s", err, b)
	}
	return out
}

type bearerTransport struct{ token string }

func (b *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestEndToEnd(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("sandbox requires Linux with bwrap installed — run `make test`")
	}
	ctx := context.Background()
	bin := buildEchoBinary(t)

	// Gateway side: sandboxed echo backend over stdio.
	cmd := sandbox.Command(sandbox.Spec{
		Exec:   "/app/server",
		Mounts: []sandbox.Mount{{Src: bin, Dst: "/app/server"}},
	})
	backendClient := mcp.NewClient(&mcp.Implementation{Name: "gigmcp-gw", Version: "e2e"}, nil)
	backendSess, err := backendClient.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect sandboxed backend: %v", err)
	}
	defer backendSess.Close()

	gw, err := gateway.New(ctx, "e2e", []gateway.Backend{{Name: "echo", Session: backendSess}})
	if err != nil {
		t.Fatalf("gateway.New: %v", err)
	}
	handler := gateway.RequireBearer("sekrit",
		mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return gw }, nil))
	ts := httptest.NewServer(handler)
	defer ts.Close()

	// Unauthenticated requests are rejected before reaching MCP.
	resp, err := http.Post(ts.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("unauthed post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthed request: got %d, want 401", resp.StatusCode)
	}

	// Real MCP client over streamable HTTP with the bearer token.
	c := mcp.NewClient(&mcp.Implementation{Name: "e2e-client", Version: "0.0.0"}, nil)
	sess, err := c.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   ts.URL,
		HTTPClient: &http.Client{Transport: &bearerTransport{token: "sekrit"}},
	}, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer sess.Close()

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo_echo" {
		t.Fatalf("want exactly [echo_echo], got %+v", tools.Tools)
	}

	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      "echo_echo",
		Arguments: map[string]any{"message": "through the sandbox"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok || text.Text != "echo: through the sandbox" {
		t.Fatalf("got %+v, want %q", res.Content[0], "echo: through the sandbox")
	}
}
```

- [ ] **Step 2: Run the full suite in the Linux container**

```bash
make test
```

Expected: ALL packages PASS, `TestEndToEnd` runs (not skipped). This is the walking skeleton's proof: HTTP client → bearer auth → streamable MCP → aggregator → stdio → bwrap sandbox → echo server → back.

- [ ] **Step 3: Verify macOS subset still green**

```bash
make test-local
```

Expected: PASS with sandbox/E2E tests SKIPPED.

- [ ] **Step 4: Commit**

```bash
git add internal/gateway/e2e_test.go
git commit -m "test: end-to-end — authed HTTP MCP client through sandboxed backend"
```

---

### Task 10: Production image, compose, README

**Files:**
- Create: `Dockerfile`, `docker-compose.yml`, `README.md`

- [ ] **Step 1: Create `Dockerfile`**

```dockerfile
FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/gateway ./cmd/gateway \
 && CGO_ENABLED=0 go build -o /out/echo-mcp ./cmd/echo-mcp

# Not FROM scratch: the runtime needs the bwrap binary (DESIGN.md §3).
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends bubblewrap ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/gateway /usr/local/bin/gateway
COPY --from=build /out/echo-mcp /usr/local/bin/echo-mcp
ENV GIG_ECHO_BIN=/usr/local/bin/echo-mcp \
    GIG_DB_PATH=/data/gigmcp.db
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["gateway"]
```

- [ ] **Step 2: Create `docker-compose.yml`**

```yaml
services:
  gateway:
    build: .
    ports:
      - "8080:8080"
    environment:
      GIG_BEARER_TOKEN: ${GIG_BEARER_TOKEN:?set GIG_BEARER_TOKEN in .env or the environment}
    volumes:
      - gigmcp-data:/data
    # bwrap needs unprivileged user namespaces, which Docker's default
    # seccomp/apparmor profiles block. A scoped allow-userns seccomp profile
    # replaces 'unconfined' in the hardening plan (DESIGN.md §5 item 7).
    security_opt:
      - seccomp=unconfined
      - apparmor=unconfined

volumes:
  gigmcp-data:
```

- [ ] **Step 3: Create `README.md`**

```markdown
# gigmcp

Open-source, security-first MCP gateway: run community MCP servers
**sandboxed**, with credentials injected at the network boundary — one
compromised tool can never expose your keys. See [DESIGN.md](DESIGN.md)
for the full architecture and decision record. AGPL-3.0.

> **Status: walking skeleton.** One bundled echo server, bearer auth,
> bubblewrap sandboxing, SQLite. Egress proxy, credential vault, registry,
> multi-user auth, and dashboard are landing per DESIGN.md §5.

## Quickstart

```bash
GIG_BEARER_TOKEN=$(openssl rand -hex 24) docker compose up --build -d
```

Connect Claude Code:

```bash
claude mcp add --transport http gigmcp http://localhost:8080 \
  --header "Authorization: Bearer <your token>"
```

You should see one tool, `echo_echo`, served by an MCP server running in a
bubblewrap sandbox: no network, no host filesystem, cleared environment.

## Development

```bash
make test        # full suite incl. sandbox tests, in a Linux container
make test-local  # host-side subset (sandbox tests skip on macOS)
```
```

- [ ] **Step 4: Build and boot the real stack**

```bash
GIG_BEARER_TOKEN=test-token-123 docker compose up --build -d
sleep 2 && docker compose logs gateway
```

Expected log lines: `backend "echo" running sandboxed (/usr/local/bin/echo-mcp)` and `gigmcp 0.1.0-skeleton listening on :8080 (1 backend(s))`.

- [ ] **Step 5: Smoke-test auth from the host**

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080 -H "Authorization: Bearer test-token-123" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
```

Expected: `401` then a non-401 status (the MCP handler may answer 400/202 for a bare ping outside a session — anything but 401/5xx is fine; the protocol-level proof was Task 9's E2E test).

- [ ] **Step 6: Manual verification with Claude Code** (requires user)

```bash
claude mcp add --transport http gigmcp http://localhost:8080 --header "Authorization: Bearer test-token-123"
```

In a Claude Code session: ask it to call `echo_echo` with message "hello from the sandbox". Expected reply contains `echo: hello from the sandbox`. Then clean up:

```bash
docker compose down
```

- [ ] **Step 7: Commit**

```bash
git add Dockerfile docker-compose.yml README.md
git commit -m "feat: production image, compose stack, README quickstart"
```

---

## Done criteria

- `make test` green on the dev Mac (suite runs in Linux container, sandbox + E2E tests executed, not skipped)
- `docker compose up` serves an authed MCP endpoint; Claude Code lists and calls `echo_echo`
- The three risk assumptions from DESIGN.md validated or characterized: bwrap-under-Docker works with documented security_opt; MCP session ↔ sandbox lifecycle works via CommandTransport; (CA-injection risk is deferred to the egress-proxy plan)

## Explicitly out of scope (later plans)

Egress proxy & credential injection · vault/encryption · manifests & OCI pulling · per-user instances & idle reaping · profiles · OIDC/multi-user · Next.js dashboard · Postgres driver · scoped seccomp profile to replace `unconfined`.
