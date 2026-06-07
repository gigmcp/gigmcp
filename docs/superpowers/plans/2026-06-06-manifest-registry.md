# Manifest / Registry / OCI-Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hardcoded server seeding with a signed registry pipeline: manifests → signed `index.json` → gateway installs digest-pinned OCI images, verifies, extracts, and enforces author-declared entitlements.

**Architecture:** Two repos. `gigmcp-registry` (new) holds the authoritative Go schema module (parse/validate/lint/hash/index/sign), launch manifests, denylist, `registryctl` CLI, and CI workflows. `gigmcp` gains `internal/oci` (daemonless pull-by-digest + extract), `internal/registry` (index fetch/verify + record-only Installer), a `manifests` store table, a manifest+vault split in the proxy resolver, an aggregator default-subset filter, and `main.go` wiring. v1 packaging = static self-contained binaries; **no `internal/sandbox` changes**.

**Tech Stack:** Go 1.26, `sigs.k8s.io/yaml`, `github.com/google/go-containerregistry` v0.21.6, stdlib `crypto/ed25519`, modernc sqlite (existing). Everything stays `CGO_ENABLED=0`.

**Spec:** `docs/superpowers/specs/2026-06-06-manifest-registry-design.md`

---

## Verified facts (from spikes — do not re-derive)

- **go-containerregistry v0.21.6** pulls by digest with **no Docker daemon**, builds with `CGO_ENABLED=0` (binary cost ~9.5 MB, 30 go.sum lines, 23 packages). `remote.Image(name.NewDigest(...))` + compare `img.Digest()` against the pin.
- **Multi-arch nuance:** a tag resolves (`remote.Get`) to the **index** digest; `remote.Image` returns a **platform image** whose `img.Digest()` is the *platform manifest* digest. **Rule: manifests pin the platform (linux/amd64) image-manifest digest**, so gateway-side `img.Digest() == pinned` verification is exact.
- A wrong digest fails at the registry (content-addressed); tamper-rejection is inherent to pull-by-digest.
- **`pkg/v1/layout`** round-trip (write image → read back by digest → `mutate.Extract` rootfs tar) works **fully offline** — hermetic testdata fixtures confirmed viable.
- **stdlib ed25519:** pubkey 32 bytes (hex → bake into gateway), privkey 64 bytes (hex → GH Actions secret), signature 64 bytes; sign/verify/tamper-reject round-trip verified with zero external deps.
- **`proxy.allowed()` semantics** (`internal/proxy/proxy.go:179`): case-insensitive exact match, OR entry `*.suffix` matches any host ending in `.suffix` (any depth). Lint must mirror exactly: hostnames only, no ports/paths/IPs/bare `*`.
- **Placeholder is matched as a substring** of the header value (`proxy.go:148`) — must be high-entropy.
- **`make test`** mounts only `$(PWD)` into the container → the cross-repo `replace` needs a second mount (Task 9).
- **Existing E2E gating pattern**: `if !sandbox.Available() { t.Skip(...) }` (see `internal/gateway/egress_e2e_test.go:34`).
- Store conventions: newline-joined host lists, `ON CONFLICT ... DO UPDATE` upserts, additive `CREATE TABLE IF NOT EXISTS` chained in `OpenSQLite`, errors like `errors.New("store: credential not found")`.

## Commit policy

- **`gigmcp-registry`**: this workstream owns it — commit normally after each task.
- **`gigmcp`**: per the handoff, the orchestrator reconciles parallel workstreams. Work on branch `manifest-registry` and commit there; do NOT touch `main`. If an orchestrator is active and reserves commits, `git add` and stop at the commit step.

## File map

**gigmcp-registry (new repo at `~/Code/gigmcp-registry`):**
- `schema/go.mod`, `schema/manifest.go`, `schema/validate.go`, `schema/lint.go`, `schema/hash.go`, `schema/index.go`, `schema/sign.go` + `*_test.go`
- `cmd/registryctl/main.go` (+ `go.mod` at repo root for the CLI)
- `manifests/echo/0.1.0.yaml`, `manifests/fetch/0.1.0.yaml`
- `denylist/exfil-domains.txt`
- `.github/workflows/{lint,build-images,publish-index}.yml`
- `README.md`, `CONTRIBUTING.md`, `LICENSE` (Apache-2.0)

**gigmcp (branch `manifest-registry`):**
- Create: `internal/store/manifests.go` + `manifests_test.go`
- Create: `internal/oci/oci.go`, `internal/oci/oci_test.go`, `internal/oci/ocitest/ocitest.go`
- Create: `internal/registry/api.go`, `client.go`, `installer.go` + tests
- Create: `internal/gateway/registry_e2e_test.go`
- Modify: `internal/store/store.go` (additive interface methods), `internal/gateway/resolver.go`, `internal/gateway/gateway.go`, `internal/gateway/spawn.go` (placeholder param), `internal/config/config.go`, `cmd/gateway/main.go`, `Makefile`, `go.mod`

---

### Task 1: Bootstrap the `gigmcp-registry` repo + schema module skeleton

**Files:**
- Create: `~/Code/gigmcp-registry/{LICENSE,schema/go.mod}`

- [ ] **Step 1: Init repo and module**

```bash
cd ~/Code/gigmcp-registry
git init -b main
curl -fsSL https://www.apache.org/licenses/LICENSE-2.0.txt -o LICENSE
mkdir -p schema cmd/registryctl manifests denylist .github/workflows
cd schema && go mod init github.com/gigmcp/gigmcp-registry/schema && go get sigs.k8s.io/yaml@latest
```

- [ ] **Step 2: Commit**

```bash
cd ~/Code/gigmcp-registry && git add -A && git commit -m "chore: repo scaffold + Apache-2.0 schema module init"
```

---

### Task 2: Manifest types + strict Parse

**Files:**
- Create: `schema/manifest.go`, `schema/manifest_test.go`

- [ ] **Step 1: Write the failing test**

`schema/manifest_test.go`:

```go
package schema

import (
	"strings"
	"testing"
)

const goodYAML = `
schemaVersion: 1
name: slack-mcp
version: 1.4.2
source:
  repo: github.com/author/slack-mcp
  tag: v1.4.2
image:
  ref: ghcr.io/gigmcp/slack-mcp
  digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  entrypoint: /server
tier: sealed
entitlements:
  egress:
    - slack.com
    - "*.slack.com"
credentials:
  - id: slack_bot_token
    type: api_key
    provider: slack
    scopes: [chat:write]
    inject:
      header: Authorization
      format: "Bearer {token}"
tools:
  - name: send_message
    default: true
  - name: admin_set_workspace_settings
    default: false
`

func TestParseGoodManifest(t *testing.T) {
	m, err := Parse([]byte(goodYAML))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Name != "slack-mcp" || m.Version != "1.4.2" || m.Tier != "sealed" {
		t.Fatalf("bad fields: %+v", m)
	}
	if m.Image.Entrypoint != "/server" || len(m.Entitlements.Egress) != 2 {
		t.Fatalf("bad image/egress: %+v", m)
	}
	if len(m.Credentials) != 1 || m.Credentials[0].Inject.Header != "Authorization" {
		t.Fatalf("bad credentials: %+v", m.Credentials)
	}
	if len(m.Tools) != 2 || !m.Tools[0].Default || m.Tools[1].Default {
		t.Fatalf("bad tools: %+v", m.Tools)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	bad := goodYAML + "\nsurprise: field\n"
	if _, err := Parse([]byte(bad)); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte("{[not yaml")); err == nil || !strings.Contains(err.Error(), "parse manifest") {
		t.Fatalf("expected parse error, got %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Code/gigmcp-registry/schema && go test ./... -run TestParse -v`
Expected: FAIL (compile error: `Parse` undefined)

- [ ] **Step 3: Write minimal implementation**

`schema/manifest.go`:

```go
// Package schema is the authoritative parser/validator/linter for gigmcp
// registry manifests and the signed index. The SAME code runs in registry CI
// and in the gateway, so the two can never drift (handoff §4.1). Apache-2.0
// (DESIGN #16).
package schema

import (
	"fmt"

	sigsyaml "sigs.k8s.io/yaml"
)

// Manifest is an author-declared entitlements manifest (DESIGN #7, §4).
type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	Name          string       `json:"name"` // unique; tool-namespace prefix; no "_"
	Version       string       `json:"version"`
	Source        Source       `json:"source"`
	Image         Image        `json:"image"`
	Tier          string       `json:"tier"` // sealed | entrusted (DESIGN #6)
	Entitlements  Entitlements `json:"entitlements"`
	Credentials   []Credential `json:"credentials,omitempty"`
	Tools         []Tool       `json:"tools,omitempty"`
}

type Source struct {
	Repo string `json:"repo"`
	Tag  string `json:"tag"`
}

type Image struct {
	Ref string `json:"ref"`
	// Digest is the PLATFORM (linux/amd64) image-manifest digest, NOT a
	// multi-arch index digest — the gateway compares img.Digest() against it.
	Digest     string `json:"digest"`
	Entrypoint string `json:"entrypoint"` // absolute path of the static binary inside the image
}

type Entitlements struct {
	Egress []string `json:"egress,omitempty"` // exact host or "*.suffix" — proxy.allowed() semantics
}

type Credential struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"` // oauth2 | api_key | basic | custom_env
	Provider string   `json:"provider"`
	Scopes   []string `json:"scopes,omitempty"`
	Inject   Inject   `json:"inject"`
}

// Inject is tier-explicit: sealed sets Header+Format (proxy header rewrite);
// entrusted sets Env (real secret into sandbox env). Exactly one mode.
type Inject struct {
	Header string `json:"header,omitempty"`
	Format string `json:"format,omitempty"` // must contain "{token}"
	Env    string `json:"env,omitempty"`
}

type Tool struct {
	Name    string `json:"name"`
	Default bool   `json:"default"` // exposed by default (DESIGN #11)
}

// Parse decodes manifest YAML. Strict: unknown fields are errors, so typos in
// security-relevant fields (e.g. "egres:") cannot silently grant nothing.
func Parse(data []byte) (*Manifest, error) {
	var m Manifest
	if err := sigsyaml.UnmarshalStrict(data, &m); err != nil {
		return nil, fmt.Errorf("schema: parse manifest: %w", err)
	}
	return &m, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ~/Code/gigmcp-registry/schema && go test ./... -run TestParse -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
cd ~/Code/gigmcp-registry && git add -A && git commit -m "feat(schema): manifest types + strict YAML parse"
```

---

### Task 3: Validate + egress lint rules

**Files:**
- Create: `schema/validate.go`, `schema/lint.go`, `schema/validate_test.go`

- [ ] **Step 1: Write the failing tests**

`schema/validate_test.go`:

```go
package schema

import (
	"strings"
	"testing"
)

func good(t *testing.T) *Manifest {
	t.Helper()
	m, err := Parse([]byte(goodYAML))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestValidateGood(t *testing.T) {
	if err := good(t).Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Manifest)
		want string
	}{
		{"bad schemaVersion", func(m *Manifest) { m.SchemaVersion = 2 }, "schemaVersion"},
		{"underscore name", func(m *Manifest) { m.Name = "slack_mcp" }, "name"},
		{"uppercase name", func(m *Manifest) { m.Name = "Slack" }, "name"},
		{"bad version", func(m *Manifest) { m.Version = "1.4" }, "version"},
		{"missing source", func(m *Manifest) { m.Source.Repo = "" }, "source"},
		{"bad digest", func(m *Manifest) { m.Image.Digest = "sha256:short" }, "digest"},
		{"missing ref", func(m *Manifest) { m.Image.Ref = "" }, "image.ref"},
		{"relative entrypoint", func(m *Manifest) { m.Image.Entrypoint = "server" }, "entrypoint"},
		{"bad tier", func(m *Manifest) { m.Tier = "yolo" }, "tier"},
		{"sealed without header", func(m *Manifest) { m.Credentials[0].Inject = Inject{Env: "TOKEN"} }, "sealed"},
		{"format without token", func(m *Manifest) { m.Credentials[0].Inject.Format = "Bearer xyz" }, "{token}"},
		{"dup credential id", func(m *Manifest) { m.Credentials = append(m.Credentials, m.Credentials[0]) }, "credential"},
		{"dup tool", func(m *Manifest) { m.Tools = append(m.Tools, m.Tools[0]) }, "tool"},
		{"empty tool name", func(m *Manifest) { m.Tools[0].Name = "" }, "tool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := good(t)
			tc.mut(m)
			err := m.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateEntrustedInjection(t *testing.T) {
	m := good(t)
	m.Tier = TierEntrusted
	m.Credentials[0].Inject = Inject{Env: "SLACK_TOKEN"}
	if err := m.Validate(); err != nil {
		t.Fatalf("entrusted env injection should validate: %v", err)
	}
	m.Credentials[0].Inject.Header = "Authorization"
	if err := m.Validate(); err == nil {
		t.Fatal("entrusted with header should fail (exactly one mode)")
	}
}

func TestCheckEgressEntry(t *testing.T) {
	ok := []string{"slack.com", "*.slack.com", "api.github.com", "*.s3.us-east-1.amazonaws.com"}
	for _, e := range ok {
		if err := CheckEgressEntry(e); err != nil {
			t.Errorf("CheckEgressEntry(%q) = %v, want nil", e, err)
		}
	}
	bad := map[string]string{
		"*":               "wildcard",
		"*.com":           "two labels",
		"foo.*.com":       "wildcard",
		"slack.com:443":   "ports",
		"slack.com/path":  "ports",
		"10.0.0.1":        "IP",
		"*.10.0.0.1":      "IP",
		"":                "label",
		"UPPER.com":       "label",
		"-bad.com":        "label",
	}
	for e, want := range bad {
		err := CheckEgressEntry(e)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckEgressEntry(%q) = %v, want error containing %q", e, err, want)
		}
	}
}

func TestLintDenylist(t *testing.T) {
	deny := []string{"# exfil domains", "pastebin.com", "webhook.site", "ngrok.io"}
	m := good(t)
	if err := m.Lint(deny); err != nil {
		t.Fatalf("clean manifest should lint: %v", err)
	}
	for _, evil := range []string{"pastebin.com", "api.pastebin.com", "*.ngrok.io"} {
		m := good(t)
		m.Entitlements.Egress = []string{evil}
		if err := m.Lint(deny); err == nil || !strings.Contains(err.Error(), "denylist") {
			t.Errorf("Lint with egress %q = %v, want denylist error", evil, err)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ~/Code/gigmcp-registry/schema && go test ./... -v 2>&1 | head -20`
Expected: FAIL (compile errors: `Validate`, `CheckEgressEntry`, `Lint`, `TierEntrusted` undefined)

- [ ] **Step 3: Write the implementation**

`schema/validate.go`:

```go
package schema

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

const (
	TierSealed    = "sealed"
	TierEntrusted = "entrusted"
)

var (
	nameRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	versionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	digestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Validate checks structural rules. Registry-policy rules that need external
// data (the exfil denylist) live in Lint.
func (m *Manifest) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if m.SchemaVersion != 1 {
		add("schemaVersion must be 1, got %d", m.SchemaVersion)
	}
	if !nameRE.MatchString(m.Name) {
		add("name %q invalid: lowercase [a-z0-9-], no underscores (name is the tool-namespace prefix)", m.Name)
	}
	if !versionRE.MatchString(m.Version) {
		add("version %q invalid: must be MAJOR.MINOR.PATCH", m.Version)
	}
	if m.Source.Repo == "" || m.Source.Tag == "" {
		add("source.repo and source.tag are required")
	}
	if m.Image.Ref == "" {
		add("image.ref is required")
	}
	if !digestRE.MatchString(m.Image.Digest) {
		add("image.digest %q invalid: must be sha256:<64 hex> (the approved digest is what runs)", m.Image.Digest)
	}
	if !strings.HasPrefix(m.Image.Entrypoint, "/") {
		add("image.entrypoint %q must be an absolute path inside the image", m.Image.Entrypoint)
	}
	if m.Tier != TierSealed && m.Tier != TierEntrusted {
		add("tier %q invalid: must be %q or %q", m.Tier, TierSealed, TierEntrusted)
	}
	for _, e := range m.Entitlements.Egress {
		if err := CheckEgressEntry(e); err != nil {
			errs = append(errs, err)
		}
	}
	seenCred := map[string]bool{}
	for _, c := range m.Credentials {
		if c.ID == "" || seenCred[c.ID] {
			add("credential id %q empty or duplicate", c.ID)
		}
		seenCred[c.ID] = true
		switch m.Tier {
		case TierSealed:
			if c.Inject.Header == "" || !strings.Contains(c.Inject.Format, "{token}") || c.Inject.Env != "" {
				add("credential %q: sealed tier requires inject.header + inject.format containing {token}, and no inject.env", c.ID)
			}
		case TierEntrusted:
			if c.Inject.Env == "" || c.Inject.Header != "" || c.Inject.Format != "" {
				add("credential %q: entrusted tier requires inject.env only", c.ID)
			}
		}
	}
	seenTool := map[string]bool{}
	for _, tl := range m.Tools {
		if tl.Name == "" || seenTool[tl.Name] {
			add("tool name %q empty or duplicate", tl.Name)
		}
		seenTool[tl.Name] = true
	}
	return errors.Join(errs...)
}
```

`schema/lint.go`:

```go
package schema

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// CheckEgressEntry enforces EXACTLY the proxy's allowed() semantics
// (internal/proxy in gigmcp: case-insensitive exact host, or "*.suffix"
// suffix match): lowercase hostnames only; wildcards only as a leading "*."
// whose suffix keeps >= 2 labels; no ports, paths, or IP literals.
func CheckEgressEntry(e string) error {
	host := e
	if strings.HasPrefix(e, "*.") {
		host = strings.TrimPrefix(e, "*.")
		if strings.Count(host, ".") < 1 {
			return fmt.Errorf("egress %q: wildcard suffix must keep at least two labels (*.%s is too broad)", e, host)
		}
	}
	if strings.Contains(host, "*") {
		return fmt.Errorf("egress %q: bare or embedded wildcard not allowed", e)
	}
	if strings.ContainsAny(e, ":/") {
		return fmt.Errorf("egress %q: ports and paths not allowed (hostnames only)", e)
	}
	if net.ParseIP(host) != nil {
		return fmt.Errorf("egress %q: raw IP literals not allowed", e)
	}
	for _, label := range strings.Split(host, ".") {
		if !nameRE.MatchString(label) { // same charset as names: ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$
			return fmt.Errorf("egress %q: invalid label %q (lowercase a-z0-9, hyphens inside)", e, label)
		}
	}
	return nil
}

// Lint = Validate + registry policy: no egress entry may equal or be a
// subdomain of a denylisted exfil domain. Denylist lines starting with "#"
// or blank are ignored (the checked-in denylist file is passed line-split).
func (m *Manifest) Lint(denylist []string) error {
	if err := m.Validate(); err != nil {
		return err
	}
	var errs []error
	for _, e := range m.Entitlements.Egress {
		host := strings.TrimPrefix(e, "*.")
		for _, bad := range denylist {
			bad = strings.ToLower(strings.TrimSpace(bad))
			if bad == "" || strings.HasPrefix(bad, "#") {
				continue
			}
			if host == bad || strings.HasSuffix(host, "."+bad) {
				errs = append(errs, fmt.Errorf("egress %q matches denylist entry %q", e, bad))
			}
		}
	}
	return errors.Join(errs...)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ~/Code/gigmcp-registry/schema && go test ./... -v 2>&1 | tail -5`
Expected: PASS (all)

- [ ] **Step 5: Commit**

```bash
cd ~/Code/gigmcp-registry && git add -A && git commit -m "feat(schema): Validate + egress lint in proxy-allowed() lockstep + denylist"
```

---

### Task 4: Canonical hash, index build/resolve, ed25519 sign/verify

**Files:**
- Create: `schema/hash.go`, `schema/index.go`, `schema/sign.go`, `schema/index_test.go`

- [ ] **Step 1: Write the failing tests**

`schema/index_test.go`:

```go
package schema

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestHashStableAndSensitive(t *testing.T) {
	m1, m2 := good(t), good(t)
	h1, err := m1.Hash()
	if err != nil || len(h1) != 64 {
		t.Fatalf("Hash: %v %q", err, h1)
	}
	h2, _ := m2.Hash()
	if h1 != h2 {
		t.Fatal("same manifest must hash identically")
	}
	m2.Entitlements.Egress = append(m2.Entitlements.Egress, "evil.example")
	if h3, _ := m2.Hash(); h3 == h1 {
		t.Fatal("changed manifest must change hash")
	}
}

func TestBuildIndexAndResolve(t *testing.T) {
	a, b := good(t), good(t)
	b.Version = "1.5.0"
	b.Image.Digest = "sha256:" + strings.Repeat("b", 64)
	ix, err := BuildIndex([]*Manifest{a, b}, "2026-06-06T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if ix.Servers["slack-mcp"].Latest != "1.5.0" {
		t.Fatalf("latest = %q, want 1.5.0", ix.Servers["slack-mcp"].Latest)
	}
	for ref, wantVer := range map[string]string{
		"slack-mcp":              "1.5.0",
		"slack-mcp@1.4.2":        "1.4.2",
		b.Image.Digest:           "1.5.0",
	} {
		m, err := ix.Resolve(ref)
		if err != nil || m.Version != wantVer {
			t.Errorf("Resolve(%q) = %v, %v; want version %s", ref, m, err, wantVer)
		}
	}
	for _, ref := range []string{"nope", "slack-mcp@9.9.9", "sha256:" + strings.Repeat("c", 64)} {
		if _, err := ix.Resolve(ref); err == nil {
			t.Errorf("Resolve(%q) should fail", ref)
		}
	}
	if _, err := BuildIndex([]*Manifest{a, a}, "x"); err == nil {
		t.Fatal("duplicate name@version must fail")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ix, _ := BuildIndex([]*Manifest{good(t)}, "2026-06-06T00:00:00Z")
	raw, err := json.Marshal(ix)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(hex.EncodeToString(priv), raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(hex.EncodeToString(pub), raw, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	tampered := append([]byte(nil), raw...)
	tampered[20] ^= 1
	if err := Verify(hex.EncodeToString(pub), tampered, sig); err == nil {
		t.Fatal("tampered bytes must fail verification")
	}
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := Verify(hex.EncodeToString(pub2), raw, sig); err == nil {
		t.Fatal("wrong key must fail verification")
	}
	if _, err := Sign("zz", raw); err == nil {
		t.Fatal("bad key hex must fail")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ~/Code/gigmcp-registry/schema && go test ./... 2>&1 | head -5`
Expected: FAIL (compile: `Hash`, `BuildIndex`, `Sign`, `Verify` undefined)

- [ ] **Step 3: Write the implementation**

`schema/hash.go`:

```go
package schema

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Hash is the canonical manifest hash: SHA-256 over the canonical JSON
// encoding of the PARSED manifest (struct field order is deterministic;
// no maps), hex-encoded. Basis for re-consent (DESIGN #7): a changed
// manifest changes the hash; YAML formatting changes do not.
func (m *Manifest) Hash() (string, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
```

`schema/index.go`:

```go
package schema

import (
	"fmt"
	"strconv"
	"strings"
)

// Index is the compiled, signed registry artifact. Runners consume ONLY this
// (never the raw repo, DESIGN #8). The signature covers the exact published
// index.json bytes — verify raw bytes, never re-serialized JSON.
type Index struct {
	SchemaVersion int                    `json:"schemaVersion"`
	Generated     string                 `json:"generated"` // RFC3339, set by CI
	Servers       map[string]IndexServer `json:"servers"`
}

type IndexServer struct {
	Latest   string               `json:"latest"`
	Versions map[string]*Manifest `json:"versions"`
}

// BuildIndex validates every manifest and compiles the index. Latest is the
// highest semver per server.
func BuildIndex(manifests []*Manifest, generated string) (*Index, error) {
	ix := &Index{SchemaVersion: 1, Generated: generated, Servers: map[string]IndexServer{}}
	for _, m := range manifests {
		if err := m.Validate(); err != nil {
			return nil, fmt.Errorf("manifest %s@%s: %w", m.Name, m.Version, err)
		}
		s := ix.Servers[m.Name]
		if s.Versions == nil {
			s.Versions = map[string]*Manifest{}
		}
		if _, dup := s.Versions[m.Version]; dup {
			return nil, fmt.Errorf("duplicate manifest %s@%s", m.Name, m.Version)
		}
		s.Versions[m.Version] = m
		if s.Latest == "" || semverLess(s.Latest, m.Version) {
			s.Latest = m.Version
		}
		ix.Servers[m.Name] = s
	}
	return ix, nil
}

// Resolve resolves "name" (latest), "name@version", or "sha256:<digest>"
// (exact image-digest lookup) — the installer ref grammar (handoff §6.B).
func (ix *Index) Resolve(ref string) (*Manifest, error) {
	if strings.HasPrefix(ref, "sha256:") {
		for _, s := range ix.Servers {
			for _, m := range s.Versions {
				if m.Image.Digest == ref {
					return m, nil
				}
			}
		}
		return nil, fmt.Errorf("schema: no manifest pins image digest %s", ref)
	}
	name, version, _ := strings.Cut(ref, "@")
	s, ok := ix.Servers[name]
	if !ok {
		return nil, fmt.Errorf("schema: unknown server %q", name)
	}
	if version == "" {
		version = s.Latest
	}
	m, ok := s.Versions[version]
	if !ok {
		return nil, fmt.Errorf("schema: unknown version %s@%s", name, version)
	}
	return m, nil
}

// semverLess reports a < b for versionRE-validated MAJOR.MINOR.PATCH strings.
func semverLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		na, _ := strconv.Atoi(pa[i])
		nb, _ := strconv.Atoi(pb[i])
		if na != nb {
			return na < nb
		}
	}
	return false
}
```

`schema/sign.go`:

```go
package schema

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
)

// Sign returns the hex-encoded ed25519 detached signature over data (the
// exact index.json bytes to publish). privHex: 64-byte private key, hex
// (lives in a GitHub Actions secret).
func Sign(privHex string, data []byte) (string, error) {
	key, err := hex.DecodeString(strings.TrimSpace(privHex))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("schema: signing key must be %d hex-encoded bytes", ed25519.PrivateKeySize)
	}
	return hex.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), data)), nil
}

// Verify checks sigHex over data with a 32-byte hex public key (baked into
// the gateway / GIG_REGISTRY_PUBKEY). MUST pass before the index is parsed.
func Verify(pubHex string, data []byte, sigHex string) error {
	pub, err := hex.DecodeString(strings.TrimSpace(pubHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("schema: public key must be %d hex-encoded bytes", ed25519.PublicKeySize)
	}
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("schema: signature must be %d hex-encoded bytes", ed25519.SignatureSize)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return fmt.Errorf("schema: index signature verification FAILED")
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ~/Code/gigmcp-registry/schema && go test ./... -v 2>&1 | tail -3`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd ~/Code/gigmcp-registry && git add -A && git commit -m "feat(schema): canonical hash, index build/resolve, ed25519 sign/verify"
```

---

### Task 5: `registryctl` CLI

**Files:**
- Create: `~/Code/gigmcp-registry/go.mod` (repo-root module for the CLI), `cmd/registryctl/main.go`, `cmd/registryctl/main_test.go`

- [ ] **Step 1: Init root module wired to the local schema module**

```bash
cd ~/Code/gigmcp-registry
go mod init github.com/gigmcp/gigmcp-registry
go mod edit -require=github.com/gigmcp/gigmcp-registry/schema@v0.0.0 \
            -replace=github.com/gigmcp/gigmcp-registry/schema=./schema
```

- [ ] **Step 2: Write the failing test**

`cmd/registryctl/main_test.go`:

```go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

const testManifest = `
schemaVersion: 1
name: echo
version: 0.1.0
source: {repo: github.com/gigmcp/gigmcp, tag: v0.1.0}
image:
  ref: ghcr.io/gigmcp/echo-mcp
  digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  entrypoint: /app/echo
tier: sealed
entitlements: {egress: [api.example.com]}
credentials:
  - id: token
    type: api_key
    provider: example
    inject: {header: Authorization, format: "Bearer {token}"}
tools:
  - {name: echo, default: true}
`

func writeTree(t *testing.T, manifestYAML string) (manifestDir, denyFile string) {
	t.Helper()
	dir := t.TempDir()
	manifestDir = filepath.Join(dir, "manifests")
	if err := os.MkdirAll(filepath.Join(manifestDir, "echo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(manifestDir, "echo", "0.1.0.yaml"), []byte(manifestYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	denyFile = filepath.Join(dir, "deny.txt")
	if err := os.WriteFile(denyFile, []byte("# exfil\npastebin.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return manifestDir, denyFile
}

func TestLintBuildSignVerify(t *testing.T) {
	manifestDir, denyFile := writeTree(t, testManifest)
	if err := run([]string{"lint", manifestDir, "-denylist", denyFile}); err != nil {
		t.Fatalf("lint: %v", err)
	}

	out := filepath.Join(t.TempDir(), "index.json")
	if err := run([]string{"build-index", manifestDir, "-out", out}); err != nil {
		t.Fatalf("build-index: %v", err)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Setenv("GIG_SIGNING_KEY", hex.EncodeToString(priv))
	sig := out + ".sig"
	if err := run([]string{"sign", "-in", out, "-out", sig}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := run([]string{"verify", "-in", out, "-sig", sig, "-pub", hex.EncodeToString(pub)}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestLintFailsOnViolation(t *testing.T) {
	bad := testManifest[:len(testManifest)-len("tools:\n  - {name: echo, default: true}\n")]
	// inject a denylisted egress host
	manifestDir, denyFile := writeTree(t, bad+`tools: [{name: echo, default: true}]`)
	evil := testManifest + "" // separate tree with a bad manifest
	_ = evil
	dir2, deny2 := writeTree(t, `
schemaVersion: 1
name: echo
version: 0.1.0
source: {repo: github.com/gigmcp/gigmcp, tag: v0.1.0}
image:
  ref: ghcr.io/gigmcp/echo-mcp
  digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  entrypoint: /app/echo
tier: sealed
entitlements: {egress: [pastebin.com]}
tools: [{name: echo, default: true}]
`)
	if err := run([]string{"lint", dir2, "-denylist", deny2}); err == nil {
		t.Fatal("lint must fail on denylisted egress")
	}
	if err := run([]string{"lint", manifestDir, "-denylist", denyFile}); err != nil {
		t.Fatalf("control lint should pass: %v", err)
	}
}

func TestLintFailsOnPathMismatch(t *testing.T) {
	manifestDir, denyFile := writeTree(t, testManifest)
	// file claims to be wrong-name/9.9.9.yaml
	if err := os.MkdirAll(filepath.Join(manifestDir, "wrong-name"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(
		filepath.Join(manifestDir, "echo", "0.1.0.yaml"),
		filepath.Join(manifestDir, "wrong-name", "9.9.9.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"lint", manifestDir, "-denylist", denyFile}); err == nil {
		t.Fatal("lint must fail when path does not match name/version")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd ~/Code/gigmcp-registry && go test ./cmd/registryctl 2>&1 | head -5`
Expected: FAIL (compile: `run` undefined)

- [ ] **Step 4: Write the implementation**

`cmd/registryctl/main.go`:

```go
// Command registryctl is the registry CI tool: lint manifests, compile the
// signed index, sign and verify it. Thin shell over the schema package so CI
// and the gateway share one validator (handoff §4.1).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gigmcp/gigmcp-registry/schema"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "registryctl:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: registryctl lint|build-index|sign|verify|keygen ...")
	}
	switch args[0] {
	case "lint":
		fs := flag.NewFlagSet("lint", flag.ContinueOnError)
		denyPath := fs.String("denylist", "", "path to exfil denylist file")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		var deny []string
		if *denyPath != "" {
			raw, err := os.ReadFile(*denyPath)
			if err != nil {
				return err
			}
			deny = strings.Split(string(raw), "\n")
		}
		manifests, err := loadAll(args[1], deny)
		if err != nil {
			return err
		}
		fmt.Printf("lint OK: %d manifest(s)\n", len(manifests))
		return nil

	case "build-index":
		fs := flag.NewFlagSet("build-index", flag.ContinueOnError)
		out := fs.String("out", "index.json", "output path")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		manifests, err := loadAll(args[1], nil)
		if err != nil {
			return err
		}
		ix, err := schema.BuildIndex(manifests, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			return err
		}
		raw, err := json.Marshal(ix)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, raw, 0o644)

	case "sign":
		fs := flag.NewFlagSet("sign", flag.ContinueOnError)
		in := fs.String("in", "index.json", "index file")
		out := fs.String("out", "index.json.sig", "signature output")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		key := os.Getenv("GIG_SIGNING_KEY")
		if key == "" {
			return fmt.Errorf("GIG_SIGNING_KEY must be set (64-byte ed25519 private key, hex)")
		}
		raw, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		sig, err := schema.Sign(key, raw)
		if err != nil {
			return err
		}
		return os.WriteFile(*out, []byte(sig+"\n"), 0o644)

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ContinueOnError)
		in := fs.String("in", "index.json", "index file")
		sigPath := fs.String("sig", "index.json.sig", "signature file")
		pub := fs.String("pub", "", "32-byte ed25519 public key, hex")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		raw, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		sig, err := os.ReadFile(*sigPath)
		if err != nil {
			return err
		}
		if err := schema.Verify(*pub, raw, string(sig)); err != nil {
			return err
		}
		fmt.Println("signature OK")
		return nil

	case "keygen":
		return keygen()

	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

// loadAll parses every manifests/<name>/<version>.yaml, enforces that the
// path matches the manifest's name/version (prevents PR sleight-of-hand),
// and lints when a denylist is given.
func loadAll(dir string, deny []string) ([]*schema.Manifest, error) {
	var manifests []*schema.Manifest
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		m, err := schema.Parse(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if deny != nil {
			if err := m.Lint(deny); err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
		} else if err := m.Validate(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		wantDir, wantFile := m.Name, m.Version+".yaml"
		if filepath.Base(filepath.Dir(path)) != wantDir || filepath.Base(path) != wantFile {
			return fmt.Errorf("%s: path must be manifests/%s/%s", path, wantDir, wantFile)
		}
		manifests = append(manifests, m)
		return nil
	})
	return manifests, err
}
```

Append the `keygen` helper to the same file:

```go
// keygen prints a fresh ed25519 keypair (hex). Run once; put the private key
// in the GIG_INDEX_SIGNING_KEY GitHub Actions secret, bake the public key
// into the gateway (internal/registry.DefaultPublicKeyHex / GIG_REGISTRY_PUBKEY).
func keygen() error {
	pub, priv, err := ed25519GenerateKey()
	if err != nil {
		return err
	}
	fmt.Printf("public:  %s\nprivate: %s\n", pub, priv)
	return nil
}
```

and at the top of the file add the real implementation (imports `crypto/ed25519`, `crypto/rand`, `encoding/hex`):

```go
func ed25519GenerateKey() (pubHex, privHex string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return hex.EncodeToString(pub), hex.EncodeToString(priv), nil
}
```

(Adjust imports: `crypto/ed25519`, `crypto/rand`, `encoding/hex` join the list.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ~/Code/gigmcp-registry && go mod tidy && go test ./... 2>&1 | tail -3`
Expected: PASS (both modules)

- [ ] **Step 6: Commit**

```bash
cd ~/Code/gigmcp-registry && git add -A && git commit -m "feat(registryctl): lint | build-index | sign | verify | keygen CLI"
```

---

### Task 6: Launch manifests, denylist, README/CONTRIBUTING, CI workflows

**Files:**
- Create: `manifests/echo/0.1.0.yaml`, `manifests/fetch/0.1.0.yaml`, `denylist/exfil-domains.txt`, `.github/workflows/{lint,build-images,publish-index}.yml`, `README.md`, `CONTRIBUTING.md`, `images/echo/Dockerfile`, `images/fetch/Dockerfile`

- [ ] **Step 1: Denylist**

`denylist/exfil-domains.txt`:

```
# Known data-exfiltration / request-capture services. PRs adding egress to
# any of these (or their subdomains) are rejected by lint CI (DESIGN #7).
pastebin.com
webhook.site
requestbin.com
pipedream.net
ngrok.io
ngrok-free.app
interactsh.com
oastify.com
burpcollaborator.net
transfer.sh
file.io
0x0.st
termbin.com
```

- [ ] **Step 2: Launch manifests (echo + fetch)**

`manifests/echo/0.1.0.yaml` — **note:** digest is a placeholder until `build-images.yml` produces the real one (README documents this bootstrap step; the gateway E2E uses its own fixture index, not these files):

```yaml
schemaVersion: 1
name: echo
version: 0.1.0
source:
  repo: github.com/gigmcp/gigmcp
  tag: v0.1.0
image:
  ref: ghcr.io/gigmcp/echo-mcp
  # PLACEHOLDER until build-images CI emits the real digest — see README.
  digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  entrypoint: /app/echo
tier: sealed
entitlements:
  egress:
    - api.example.com
credentials:
  - id: demo_token
    type: api_key
    provider: example
    inject:
      header: Authorization
      format: "Bearer {token}"
tools:
  - name: echo
    default: true
```

`manifests/fetch/0.1.0.yaml`:

```yaml
schemaVersion: 1
name: fetch
version: 0.1.0
source:
  repo: github.com/gigmcp/gigmcp
  tag: v0.1.0
image:
  ref: ghcr.io/gigmcp/fetch-mcp
  # PLACEHOLDER until build-images CI emits the real digest — see README.
  digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  entrypoint: /app/fetch
tier: sealed
entitlements:
  egress:
    - example.com
    - "*.example.com"
credentials:
  - id: demo_token
    type: api_key
    provider: example
    inject:
      header: Authorization
      format: "Bearer {token}"
tools:
  - name: fetch
    default: true
```

- [ ] **Step 3: Image Dockerfiles** (static binaries from the gigmcp tag — v1 packaging decision)

`images/echo/Dockerfile`:

```dockerfile
# Build the echo MCP server as a static binary from the pinned gigmcp tag.
FROM golang:1.26-bookworm AS build
ARG GIGMCP_TAG=v0.1.0
RUN git clone --depth 1 --branch ${GIGMCP_TAG} https://github.com/gigmcp/gigmcp /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -o /out/echo ./cmd/echo-mcp

FROM scratch
COPY --from=build /out/echo /app/echo
ENTRYPOINT ["/app/echo"]
```

`images/fetch/Dockerfile` — same with `fetch` substituted:

```dockerfile
FROM golang:1.26-bookworm AS build
ARG GIGMCP_TAG=v0.1.0
RUN git clone --depth 1 --branch ${GIGMCP_TAG} https://github.com/gigmcp/gigmcp /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -o /out/fetch ./cmd/fetch-mcp

FROM scratch
COPY --from=build /out/fetch /app/fetch
ENTRYPOINT ["/app/fetch"]
```

- [ ] **Step 4: Workflows**

`.github/workflows/lint.yml`:

```yaml
name: lint
on:
  pull_request:
  push: {branches: [main]}
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version: '1.26'}
      - run: go test ./...
      - run: go run ./cmd/registryctl lint ./manifests -denylist denylist/exfil-domains.txt
```

`.github/workflows/build-images.yml`:

```yaml
name: build-images
on:
  workflow_dispatch:
    inputs:
      name: {description: 'server name (manifests/<name>)', required: true}
      tag: {description: 'gigmcp/source tag to build', required: true}
permissions:
  packages: write
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Build and push by tag
        id: push
        run: |
          docker build --build-arg GIGMCP_TAG=${{ inputs.tag }} \
            -t ghcr.io/gigmcp/${{ inputs.name }}-mcp:${{ inputs.tag }} \
            images/${{ inputs.name }}
          docker push ghcr.io/gigmcp/${{ inputs.name }}-mcp:${{ inputs.tag }}
          # The digest the manifest must pin (platform image-manifest digest):
          docker buildx imagetools inspect ghcr.io/gigmcp/${{ inputs.name }}-mcp:${{ inputs.tag }} --format '{{json .}}' | head -50
      - name: Report digest
        run: echo "Pin the linux/amd64 image-manifest digest shown above in manifests/${{ inputs.name }}/<version>.yaml"
```

`.github/workflows/publish-index.yml`:

```yaml
name: publish-index
on:
  push: {branches: [main]}
permissions:
  contents: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version: '1.26'}
      - run: go run ./cmd/registryctl lint ./manifests -denylist denylist/exfil-domains.txt
      - run: go run ./cmd/registryctl build-index ./manifests -out index.json
      - run: go run ./cmd/registryctl sign -in index.json -out index.json.sig
        env:
          GIG_SIGNING_KEY: ${{ secrets.GIG_INDEX_SIGNING_KEY }}
      - name: Publish as rolling release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release delete latest --yes || true
          gh release create latest index.json index.json.sig \
            --title "registry index" --notes "Signed registry index (auto-published)"
```

- [ ] **Step 5: README + CONTRIBUTING**

`README.md`:

```markdown
# gigmcp-registry

Curated, signed registry of community MCP servers for [gigmcp](https://github.com/gigmcp/gigmcp).
Servers are packaged as digest-pinned OCI images with author-declared
entitlement manifests (egress allowlist, credential schema, tool subset,
security tier). The gateway installs from the **signed `index.json`** release
artifact — never from this repo directly.

## Layout
- `manifests/<name>/<version>.yaml` — one manifest per server version (schema: `schema/`)
- `schema/` — Go module (Apache-2.0): the authoritative parser/validator used
  byte-for-byte by CI here and by the gigmcp gateway
- `denylist/exfil-domains.txt` — egress domains lint CI rejects
- `cmd/registryctl` — lint | build-index | sign | verify | keygen

## Trust chain
1. Manifests are PR-gated; lint CI blocks invalid schemas, broad wildcards,
   and denylisted exfil domains. The path `manifests/<name>/<version>.yaml`
   must match the manifest contents.
2. Images are built by CI from the author's tagged source; the manifest pins
   the resulting **linux/amd64 image-manifest digest** — what was approved is
   what runs.
3. On merge to main, CI compiles all manifests into `index.json`, signs it
   (ed25519), and publishes both as the rolling `latest` release. The gateway
   verifies the signature before trusting any entry.

## Bootstrapping a manifest's digest
`build-images.yml` (manual dispatch) builds and pushes the image and prints
the digest; the PR then pins that digest. Manifests with placeholder digests
are not installable.
```

`CONTRIBUTING.md`:

```markdown
# Contributing a server

1. Tag a release of your MCP server's source repo.
2. Add `images/<name>/Dockerfile` producing a **static, self-contained
   binary** in a `FROM scratch` image (v1 constraint), with an explicit
   entrypoint path.
3. Open a PR adding `manifests/<name>/<version>.yaml`:
   - egress allowlist: exact hostnames or `*.suffix` (≥2 labels) only
   - credentials: `inject.header`+`format` (sealed) or `inject.env` (entrusted)
   - tools: mark the curated subset `default: true`
4. CI lints the manifest. A maintainer dispatches `build-images`; update your
   PR to pin the printed digest.
5. Owner review + merge ⇒ the signed index is republished automatically.

Manifest changes on version bump force re-consent in every gateway that has
the server installed.
```

- [ ] **Step 6: Lint the committed manifests with the real CLI, then commit**

Run: `cd ~/Code/gigmcp-registry && go run ./cmd/registryctl lint ./manifests -denylist denylist/exfil-domains.txt`
Expected: `lint OK: 2 manifest(s)`

```bash
cd ~/Code/gigmcp-registry && git add -A && git commit -m "feat: launch manifests (echo, fetch), denylist, CI workflows, docs"
```

---

### Task 7: gigmcp branch + cross-repo module wiring

**Files:**
- Modify: `~/Code/gigmcp/go.mod`, `~/Code/gigmcp/Makefile`

- [ ] **Step 1: Branch**

```bash
cd ~/Code/gigmcp && git checkout -b manifest-registry
```

- [ ] **Step 2: Wire the schema module (require + local replace)**

```bash
cd ~/Code/gigmcp
go mod edit -require=github.com/gigmcp/gigmcp-registry/schema@v0.0.0 \
            -replace=github.com/gigmcp/gigmcp-registry/schema=../gigmcp-registry/schema
go get github.com/google/go-containerregistry@v0.21.6
go mod tidy
```

- [ ] **Step 3: Make the container test mount the registry repo**

In `Makefile`, the `test` target's `docker run` gains one volume so the
relative `replace` path resolves inside the container (`/src/../gigmcp-registry`):

```make
test: dev-image
	docker run --rm \
		--security-opt seccomp=unconfined \
		--security-opt apparmor=unconfined \
		--security-opt systempaths=unconfined \
		--cap-add NET_ADMIN \
		-v $(PWD):/src -w /src \
		-v $(abspath $(PWD)/../gigmcp-registry):/gigmcp-registry \
		-v gigmcp-gomod:/go/pkg/mod \
		-v gigmcp-gocache:/root/.cache/go-build \
		$(DEV_IMAGE) go test ./...
```

**Wait** — `/src/../gigmcp-registry` is `/gigmcp-registry` only if `/src` is at root, which it is. The mount target must therefore be `/gigmcp-registry` (as written above).

- [ ] **Step 4: Verify both build paths**

Run: `cd ~/Code/gigmcp && go build ./... && make test-local 2>&1 | tail -3`
Expected: build OK; tests PASS (sandbox tests skip on macOS)

- [ ] **Step 5: Commit**

```bash
cd ~/Code/gigmcp && git add go.mod go.sum Makefile && git commit -m "build: depend on gigmcp-registry/schema (local replace) + go-containerregistry"
```

---

### Task 8: Store `manifests` table + methods

**Files:**
- Create: `internal/store/manifests.go`, `internal/store/manifests_test.go`
- Modify: `internal/store/store.go` (additive interface methods), `internal/store/sqlite.go` (chain DDL)

- [ ] **Step 1: Write the failing test**

`internal/store/manifests_test.go`:

```go
package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) Store {
	t.Helper()
	st, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func sampleRecord() ManifestRecord {
	return ManifestRecord{
		Server:       "slack-mcp",
		Version:      "1.4.2",
		Digest:       "sha256:abc",
		Tier:         "sealed",
		Entrypoint:   "/server",
		AllowedHosts: []string{"slack.com", "*.slack.com"},
		Injections: []Injection{{
			ID: "slack_bot_token", Header: "Authorization",
			Format: "Bearer {token}", Placeholder: "gigph-aabbcc",
		}},
		Tools:        []ToolEntry{{Name: "send_message", Default: true}, {Name: "admin", Default: false}},
		ManifestHash: "hash-v1",
	}
}

func TestManifestRoundTrip(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if err := st.PutManifest(ctx, sampleRecord()); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetManifest(ctx, "slack-mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != "1.4.2" || got.Tier != "sealed" || got.Entrypoint != "/server" {
		t.Fatalf("bad scalar fields: %+v", got)
	}
	if len(got.AllowedHosts) != 2 || got.AllowedHosts[1] != "*.slack.com" {
		t.Fatalf("bad hosts: %v", got.AllowedHosts)
	}
	if len(got.Injections) != 1 || got.Injections[0].Placeholder != "gigph-aabbcc" {
		t.Fatalf("bad injections: %+v", got.Injections)
	}
	if len(got.Tools) != 2 || !got.Tools[0].Default || got.Tools[1].Default {
		t.Fatalf("bad tools: %+v", got.Tools)
	}
	if !got.NeedsReconsent() {
		t.Fatal("fresh install (consented_hash empty) must need consent")
	}
}

func TestConsentLifecycle(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	rec := sampleRecord()
	if err := st.PutManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordConsent(ctx, "slack-mcp", "hash-v1"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetManifest(ctx, "slack-mcp")
	if got.NeedsReconsent() {
		t.Fatal("consented manifest must not need re-consent")
	}
	// Version bump with new hash: consent must be PRESERVED (and now stale).
	rec.Version = "1.5.0"
	rec.ManifestHash = "hash-v2"
	if err := st.PutManifest(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetManifest(ctx, "slack-mcp")
	if got.ConsentedHash != "hash-v1" || !got.NeedsReconsent() {
		t.Fatalf("upgrade must preserve consented hash and flip NeedsReconsent: %+v", got)
	}
	if err := st.RecordConsent(ctx, "missing", "x"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("consent on missing server: %v, want ErrManifestNotFound", err)
	}
}

func TestGetManifestNotFoundAndDelete(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()
	if _, err := st.GetManifest(ctx, "nope"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatalf("want ErrManifestNotFound, got %v", err)
	}
	if err := st.PutManifest(ctx, sampleRecord()); err != nil {
		t.Fatal(err)
	}
	if list, err := st.ListManifests(ctx); err != nil || len(list) != 1 {
		t.Fatalf("ListManifests: %v %v", list, err)
	}
	if err := st.DeleteManifest(ctx, "slack-mcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetManifest(ctx, "slack-mcp"); !errors.Is(err, ErrManifestNotFound) {
		t.Fatal("manifest should be gone")
	}
	// DeleteServer removes the servers row.
	if _, err := st.EnsureServer(ctx, "slack-mcp", "/tmp/x"); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteServer(ctx, "slack-mcp"); err != nil {
		t.Fatal(err)
	}
	servers, _ := st.ListServers(ctx)
	if len(servers) != 0 {
		t.Fatalf("server should be gone: %v", servers)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Code/gigmcp && go test ./internal/store/ 2>&1 | head -5`
Expected: FAIL (compile: `ManifestRecord` etc. undefined)

- [ ] **Step 3: Write the implementation**

`internal/store/manifests.go`:

```go
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

// ErrManifestNotFound is returned by GetManifest/RecordConsent for servers
// with no installed manifest (e.g. legacy GIG_ECHO_BIN-seeded servers).
var ErrManifestNotFound = errors.New("store: manifest not found")

// Injection is one credential's proxy-injection config from the manifest plus
// the install-time-generated high-entropy placeholder sentinel (the proxy
// matches it as a substring — see proxy.Credential).
type Injection struct {
	ID          string `json:"id"`
	Header      string `json:"header,omitempty"` // sealed: header the proxy rewrites
	Format      string `json:"format,omitempty"` // sealed: "{token}" → real secret
	Env         string `json:"env,omitempty"`    // entrusted: env var for the real secret
	Placeholder string `json:"placeholder,omitempty"`
}

// ToolEntry mirrors the manifest's tool list (DESIGN #11 default subset).
type ToolEntry struct {
	Name    string `json:"name"`
	Default bool   `json:"default"`
}

// ManifestRecord is the persisted, enforcement-relevant projection of a
// registry manifest (handoff seam §6.A, option A: separate table, separate
// file — the frontend workstream never touches this).
type ManifestRecord struct {
	Server        string
	Version       string
	Digest        string
	Tier          string
	Entrypoint    string
	AllowedHosts  []string
	Injections    []Injection
	Tools         []ToolEntry
	ManifestHash  string // canonical-JSON SHA-256 of the manifest
	ConsentedHash string // last hash the user accepted ("" = never)
}

// NeedsReconsent reports whether the installed manifest differs from what the
// user last consented to (DESIGN #7: manifest changes on update ⇒ re-consent).
// The gateway refuses to spawn such servers; the frontend renders the prompt.
func (m ManifestRecord) NeedsReconsent() bool { return m.ManifestHash != m.ConsentedHash }

const manifestSchema = `
CREATE TABLE IF NOT EXISTS manifests (
	server         TEXT PRIMARY KEY,
	version        TEXT NOT NULL,
	digest         TEXT NOT NULL,
	tier           TEXT NOT NULL,
	entrypoint     TEXT NOT NULL,
	allowed_hosts  TEXT NOT NULL,
	injections     TEXT NOT NULL,
	tools          TEXT NOT NULL,
	manifest_hash  TEXT NOT NULL,
	consented_hash TEXT NOT NULL DEFAULT ''
);`

// PutManifest upserts by server. consented_hash is PRESERVED on update —
// consent moves only via RecordConsent, so a version bump leaves the old
// consent in place and NeedsReconsent flips true.
func (s *sqliteStore) PutManifest(ctx context.Context, m ManifestRecord) error {
	inj, err := json.Marshal(m.Injections)
	if err != nil {
		return err
	}
	tools, err := json.Marshal(m.Tools)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO manifests (server,version,digest,tier,entrypoint,allowed_hosts,injections,tools,manifest_hash,consented_hash)
		 VALUES (?,?,?,?,?,?,?,?,?,'')
		 ON CONFLICT(server) DO UPDATE SET
		   version=excluded.version, digest=excluded.digest, tier=excluded.tier,
		   entrypoint=excluded.entrypoint, allowed_hosts=excluded.allowed_hosts,
		   injections=excluded.injections, tools=excluded.tools,
		   manifest_hash=excluded.manifest_hash`,
		m.Server, m.Version, m.Digest, m.Tier, m.Entrypoint,
		strings.Join(m.AllowedHosts, "\n"), string(inj), string(tools), m.ManifestHash)
	return err
}

func (s *sqliteStore) GetManifest(ctx context.Context, server string) (ManifestRecord, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT server,version,digest,tier,entrypoint,allowed_hosts,injections,tools,manifest_hash,consented_hash
		 FROM manifests WHERE server=?`, server)
	m, err := scanManifest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ManifestRecord{}, ErrManifestNotFound
	}
	return m, err
}

func (s *sqliteStore) ListManifests(ctx context.Context) ([]ManifestRecord, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT server,version,digest,tier,entrypoint,allowed_hosts,injections,tools,manifest_hash,consented_hash
		 FROM manifests ORDER BY server`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ManifestRecord
	for rows.Next() {
		m, err := scanManifest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// RecordConsent marks hash as the user-accepted manifest hash for server.
// The frontend calls this from its consent flow (seam §4.5).
func (s *sqliteStore) RecordConsent(ctx context.Context, server, hash string) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE manifests SET consented_hash=? WHERE server=?`, hash, server)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrManifestNotFound
	}
	return nil
}

func (s *sqliteStore) DeleteManifest(ctx context.Context, server string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM manifests WHERE server=?`, server)
	return err
}

// DeleteServer removes a servers row (Uninstall path; installer-owned).
func (s *sqliteStore) DeleteServer(ctx context.Context, name string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM servers WHERE name=?`, name)
	return err
}

type scanner interface{ Scan(dest ...any) error }

func scanManifest(row scanner) (ManifestRecord, error) {
	var m ManifestRecord
	var hosts, inj, tools string
	if err := row.Scan(&m.Server, &m.Version, &m.Digest, &m.Tier, &m.Entrypoint,
		&hosts, &inj, &tools, &m.ManifestHash, &m.ConsentedHash); err != nil {
		return ManifestRecord{}, err
	}
	if hosts != "" {
		m.AllowedHosts = strings.Split(hosts, "\n")
	}
	if err := json.Unmarshal([]byte(inj), &m.Injections); err != nil {
		return ManifestRecord{}, err
	}
	if err := json.Unmarshal([]byte(tools), &m.Tools); err != nil {
		return ManifestRecord{}, err
	}
	return m, nil
}
```

Modify `internal/store/store.go` — append to the `Store` interface (additive, at the end, per seam §6.A protocol):

```go
	// PutManifest upserts a manifest record by server (consent preserved).
	PutManifest(ctx context.Context, m ManifestRecord) error
	// GetManifest fetches the manifest for a server; ErrManifestNotFound if none.
	GetManifest(ctx context.Context, server string) (ManifestRecord, error)
	// ListManifests returns all manifest records ordered by server.
	ListManifests(ctx context.Context) ([]ManifestRecord, error)
	// RecordConsent stores the manifest hash the user accepted for server.
	RecordConsent(ctx context.Context, server, hash string) error
	// DeleteManifest removes a server's manifest record.
	DeleteManifest(ctx context.Context, server string) error
	// DeleteServer removes a server row (registry uninstall).
	DeleteServer(ctx context.Context, name string) error
```

Modify `internal/store/sqlite.go` `OpenSQLite` — chain the DDL after `credSchema`:

```go
	if _, err := db.ExecContext(ctx, manifestSchema); err != nil {
		db.Close()
		return nil, err
	}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ~/Code/gigmcp && go test ./internal/store/ -v 2>&1 | tail -5`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
cd ~/Code/gigmcp && git add internal/store && git commit -m "feat(store): manifests table + consent lifecycle (seam 6.A option A)"
```

---

### Task 9: `internal/oci` — pull by digest, verify, extract (+ `ocitest` fixture builder)

**Files:**
- Create: `internal/oci/ocitest/ocitest.go`, `internal/oci/oci.go`, `internal/oci/oci_test.go`

- [ ] **Step 1: Write the fixture builder** (test infrastructure; verified by the package tests)

`internal/oci/ocitest/ocitest.go`:

```go
// Package ocitest builds tiny OCI-layout image fixtures for hermetic tests
// (Spike A verified layout write→read-by-digest→extract works offline).
package ocitest

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// WriteLayoutImage writes an OCI layout at dir containing one single-layer
// image whose rootfs holds files (path inside image, WITHOUT leading slash →
// contents, mode 0755). Returns the image-manifest digest ("sha256:...") —
// the digest a manifest would pin.
func WriteLayoutImage(dir string, files map[string][]byte) (string, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, contents := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o755, Size: int64(len(contents)), Typeflag: tar.TypeReg,
		}); err != nil {
			return "", err
		}
		if _, err := tw.Write(contents); err != nil {
			return "", err
		}
	}
	if err := tw.Close(); err != nil {
		return "", err
	}
	layerBytes := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(layerBytes)), nil
	})
	if err != nil {
		return "", err
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return "", err
	}
	digest, err := img.Digest()
	if err != nil {
		return "", err
	}
	lp, err := layout.Write(dir, empty.Index)
	if err != nil {
		return "", fmt.Errorf("ocitest: write layout: %w", err)
	}
	if err := lp.AppendImage(img); err != nil {
		return "", err
	}
	return digest.String(), nil
}
```

- [ ] **Step 2: Write the failing test**

`internal/oci/oci_test.go`:

```go
package oci

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
)

func TestExtractFromLayout(t *testing.T) {
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{
		"app/server": []byte("fake-static-binary"),
		"etc/noise":  []byte("ignore me"),
	})
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "servers", "echo@0.1.0", "server")
	p := &Puller{LayoutDir: layoutDir}
	if err := p.Extract(context.Background(), "ghcr.io/ignored/by-layout", digest, "/app/server", dest); err != nil {
		t.Fatalf("Extract: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != "fake-static-binary" {
		t.Fatalf("dest contents: %q, %v", got, err)
	}
	info, _ := os.Stat(dest)
	if info.Mode().Perm() != 0o555 {
		t.Fatalf("dest mode = %v, want 0555", info.Mode().Perm())
	}
}

func TestExtractRejectsWrongDigest(t *testing.T) {
	layoutDir := t.TempDir()
	if _, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{"app/server": []byte("x")}); err != nil {
		t.Fatal(err)
	}
	wrong := "sha256:" + strings.Repeat("0", 64)
	p := &Puller{LayoutDir: layoutDir}
	err := p.Extract(context.Background(), "ref", wrong, "/app/server", filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Fatal("wrong digest must fail (content-addressed lookup)")
	}
}

func TestExtractRejectsMissingEntrypoint(t *testing.T) {
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{"app/server": []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	p := &Puller{LayoutDir: layoutDir}
	err = p.Extract(context.Background(), "ref", digest, "/does/not/exist", filepath.Join(t.TempDir(), "out"))
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("want entrypoint-not-found error, got %v", err)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd ~/Code/gigmcp && go test ./internal/oci/ 2>&1 | head -5`
Expected: FAIL (compile: `Puller` undefined)

- [ ] **Step 4: Write the implementation**

`internal/oci/oci.go`:

```go
// Package oci pulls digest-pinned images and extracts the entrypoint binary.
// Daemonless: pure go-containerregistry (Spike A: pull-by-digest verified,
// CGO_ENABLED=0 static builds preserved, OCI-layout reads work offline).
//
// v1 packaging is static self-contained binaries (spec decision #2): exactly
// one file is extracted and later bind-mounted at /app/server by the existing
// sandbox — NO internal/sandbox changes.
package oci

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Puller fetches images by digest. If LayoutDir is set, images are read from
// an OCI layout directory (hermetic tests, air-gapped installs) instead of a
// remote registry.
type Puller struct {
	LayoutDir string
}

// Extract pulls imageRef pinned to digest (a PLATFORM image-manifest digest,
// not a multi-arch index digest — Spike A), verifies the content digest
// matches, and writes the regular file at entrypoint (absolute path inside
// the image) to dest with mode 0555.
func (p *Puller) Extract(ctx context.Context, imageRef, digest, entrypoint, dest string) error {
	want, err := v1.NewHash(digest)
	if err != nil {
		return fmt.Errorf("oci: bad digest %q: %w", digest, err)
	}
	var img v1.Image
	if p.LayoutDir != "" {
		lp, err := layout.FromPath(p.LayoutDir)
		if err != nil {
			return fmt.Errorf("oci: open layout %s: %w", p.LayoutDir, err)
		}
		img, err = lp.Image(want)
		if err != nil {
			return fmt.Errorf("oci: image %s not in layout: %w", digest, err)
		}
	} else {
		ref, err := name.NewDigest(imageRef + "@" + digest)
		if err != nil {
			return fmt.Errorf("oci: bad ref %s@%s: %w", imageRef, digest, err)
		}
		img, err = remote.Image(ref, remote.WithContext(ctx))
		if err != nil {
			return fmt.Errorf("oci: pull %s: %w", ref, err)
		}
	}
	// Belt-and-suspenders: re-derive the digest of what actually arrived.
	got, err := img.Digest()
	if err != nil {
		return fmt.Errorf("oci: digest of pulled image: %w", err)
	}
	if got != want {
		return fmt.Errorf("oci: digest mismatch: pulled %s, manifest pins %s", got, want)
	}
	return extractFile(img, entrypoint, dest)
}

// extractFile streams the flattened rootfs (whiteouts applied) and writes the
// entrypoint file to dest.
func extractFile(img v1.Image, entrypoint, dest string) error {
	wantName := strings.TrimPrefix(entrypoint, "/")
	rc := mutate.Extract(img)
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("oci: read rootfs: %w", err)
		}
		if filepath.Clean(hdr.Name) != wantName {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return fmt.Errorf("oci: entrypoint %s is not a regular file", entrypoint)
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o555)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			os.Remove(dest)
			return fmt.Errorf("oci: write %s: %w", dest, err)
		}
		return f.Close()
	}
	return fmt.Errorf("oci: entrypoint %s not found in image rootfs", entrypoint)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ~/Code/gigmcp && go test ./internal/oci/ -v 2>&1 | tail -5`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
cd ~/Code/gigmcp && git add internal/oci && git commit -m "feat(oci): daemonless pull-by-digest + verify + entrypoint extract; layout fixtures"
```

---

### Task 10: `internal/registry` — client (fetch + verify index)

**Files:**
- Create: `internal/registry/client.go`, `internal/registry/client_test.go`, `internal/registry/fixture_test.go`

- [ ] **Step 1: Write the shared test fixture helper**

`internal/registry/fixture_test.go`:

```go
package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp-registry/schema"
)

// fixtureManifest returns a valid manifest for a server packaged at
// entrypoint /app/server with the given image digest.
func fixtureManifest(name, version, digest string) *schema.Manifest {
	return &schema.Manifest{
		SchemaVersion: 1,
		Name:          name,
		Version:       version,
		Source:        schema.Source{Repo: "github.com/gigmcp/gigmcp", Tag: "v" + version},
		Image:         schema.Image{Ref: "ghcr.io/gigmcp/" + name, Digest: digest, Entrypoint: "/app/server"},
		Tier:          schema.TierSealed,
		Entitlements:  schema.Entitlements{Egress: []string{"api.example.com"}},
		Credentials: []schema.Credential{{
			ID: "token", Type: "api_key", Provider: "example",
			Inject: schema.Inject{Header: "Authorization", Format: "Bearer {token}"},
		}},
		Tools: []schema.Tool{{Name: "echo", Default: true}, {Name: "loud_echo", Default: false}},
	}
}

// writeSignedIndex compiles manifests into a signed index on disk and returns
// the file:// URL and the hex public key.
func writeSignedIndex(t *testing.T, manifests ...*schema.Manifest) (indexURL, pubHex string) {
	t.Helper()
	ix, err := schema.BuildIndex(manifests, "2026-06-06T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(ix)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := schema.Sign(hex.EncodeToString(priv), raw)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.json")
	if err := os.WriteFile(indexPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath+".sig", []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	return "file://" + indexPath, hex.EncodeToString(pub)
}

// validDigest is a well-formed (but content-less) digest for client tests.
var validDigest = "sha256:" + strings.Repeat("a", 64)
```

- [ ] **Step 2: Write the failing client test**

`internal/registry/client_test.go`:

```go
package registry

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestFetchIndexVerifiesSignature(t *testing.T) {
	url, pub := writeSignedIndex(t, fixtureManifest("echo", "0.1.0", validDigest))
	c := &Client{IndexURL: url, PublicKeyHex: pub}
	ix, err := c.FetchIndex(context.Background())
	if err != nil {
		t.Fatalf("FetchIndex: %v", err)
	}
	if _, err := ix.Resolve("echo@0.1.0"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
}

func TestFetchIndexRejectsTamperedIndex(t *testing.T) {
	url, pub := writeSignedIndex(t, fixtureManifest("echo", "0.1.0", validDigest))
	path := strings.TrimPrefix(url, "file://")
	raw, _ := os.ReadFile(path)
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	c := &Client{IndexURL: url, PublicKeyHex: pub}
	if _, err := c.FetchIndex(context.Background()); err == nil || !strings.Contains(err.Error(), "UNTRUSTED") {
		t.Fatalf("tampered index must be rejected before parsing, got %v", err)
	}
}

func TestFetchIndexRejectsWrongKey(t *testing.T) {
	url, _ := writeSignedIndex(t, fixtureManifest("echo", "0.1.0", validDigest))
	_, otherPub := writeSignedIndex(t, fixtureManifest("other", "0.1.0", validDigest))
	c := &Client{IndexURL: url, PublicKeyHex: otherPub}
	if _, err := c.FetchIndex(context.Background()); err == nil {
		t.Fatal("index signed with a different key must be rejected")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd ~/Code/gigmcp && go test ./internal/registry/ 2>&1 | head -5`
Expected: FAIL (compile: `Client` undefined)

- [ ] **Step 4: Write the implementation**

`internal/registry/client.go`:

```go
// Package registry fetches and verifies the signed registry index and
// installs servers from it: resolve → pull by digest → verify → extract →
// record (handoff §4.2). Record-only: spawning stays in the gateway run-loop.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gigmcp/gigmcp-registry/schema"
)

// Client fetches index.json + index.json.sig and verifies the ed25519
// signature over the RAW index bytes BEFORE parsing anything (DESIGN #8:
// runners consume the signed index, never the raw repo).
type Client struct {
	IndexURL     string       // https://... or file:///...; signature at IndexURL + ".sig"
	PublicKeyHex string       // 32-byte ed25519 public key, hex
	HTTP         *http.Client // nil → http.DefaultClient
}

// FetchIndex downloads, verifies, and parses the registry index.
func (c *Client) FetchIndex(ctx context.Context) (*schema.Index, error) {
	raw, err := c.fetch(ctx, c.IndexURL)
	if err != nil {
		return nil, fmt.Errorf("registry: fetch index: %w", err)
	}
	sig, err := c.fetch(ctx, c.IndexURL+".sig")
	if err != nil {
		return nil, fmt.Errorf("registry: fetch index signature: %w", err)
	}
	if err := schema.Verify(c.PublicKeyHex, raw, string(sig)); err != nil {
		return nil, fmt.Errorf("registry: UNTRUSTED index: %w", err)
	}
	var ix schema.Index
	if err := json.Unmarshal(raw, &ix); err != nil {
		return nil, fmt.Errorf("registry: parse index: %w", err)
	}
	if ix.SchemaVersion != 1 {
		return nil, fmt.Errorf("registry: unsupported index schemaVersion %d", ix.SchemaVersion)
	}
	return &ix, nil
}

func (c *Client) fetch(ctx context.Context, url string) ([]byte, error) {
	if path, ok := strings.CutPrefix(url, "file://"); ok {
		return os.ReadFile(path)
	}
	httpc := c.HTTP
	if httpc == nil {
		httpc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ~/Code/gigmcp && go test ./internal/registry/ -v 2>&1 | tail -5`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd ~/Code/gigmcp && git add internal/registry && git commit -m "feat(registry): index client — signature verified before parse"
```

---

### Task 11: `internal/registry` — Installer (seam §6.B)

**Files:**
- Create: `internal/registry/api.go`, `internal/registry/installer.go`, `internal/registry/installer_test.go`

- [ ] **Step 1: Write the failing test**

`internal/registry/installer_test.go`:

```go
package registry

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
	"github.com/gigmcp/gigmcp/internal/store"
)

func newTestInstaller(t *testing.T, autoConsent bool) (*IndexInstaller, store.Store) {
	t.Helper()
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{
		"app/server": []byte("fake-echo-binary"),
	})
	if err != nil {
		t.Fatal(err)
	}
	url, pub := writeSignedIndex(t,
		fixtureManifest("echo", "0.1.0", digest),
		fixtureManifest("echo", "0.2.0", digest),
	)
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return &IndexInstaller{
		Store:       st,
		Client:      &Client{IndexURL: url, PublicKeyHex: pub},
		Puller:      &oci.Puller{LayoutDir: layoutDir},
		DataDir:     t.TempDir(),
		AutoConsent: autoConsent,
	}, st
}

func TestInstallRecordsServerAndManifest(t *testing.T) {
	inst, st := newTestInstaller(t, true)
	ctx := context.Background()
	srv, err := inst.Install(ctx, "echo@0.1.0")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if srv.Name != "echo" || !strings.Contains(srv.Binary, "echo@0.1.0") {
		t.Fatalf("bad server: %+v", srv)
	}
	if data, err := os.ReadFile(srv.Binary); err != nil || string(data) != "fake-echo-binary" {
		t.Fatalf("extracted binary: %q %v", data, err)
	}
	rec, err := st.GetManifest(ctx, "echo")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Version != "0.1.0" || rec.AllowedHosts[0] != "api.example.com" {
		t.Fatalf("bad record: %+v", rec)
	}
	if len(rec.Injections) != 1 || !strings.HasPrefix(rec.Injections[0].Placeholder, "gigph-") ||
		len(rec.Injections[0].Placeholder) < 20 {
		t.Fatalf("placeholder must be generated high-entropy: %+v", rec.Injections)
	}
	if rec.NeedsReconsent() {
		t.Fatal("AutoConsent install must be consented")
	}
}

func TestInstallIdempotentAndUpgradeFlipsConsent(t *testing.T) {
	inst, st := newTestInstaller(t, true)
	ctx := context.Background()
	if _, err := inst.Install(ctx, "echo@0.1.0"); err != nil {
		t.Fatal(err)
	}
	rec1, _ := st.GetManifest(ctx, "echo")
	if _, err := inst.Install(ctx, "echo@0.1.0"); err != nil { // re-install: no-op
		t.Fatal(err)
	}
	rec2, _ := st.GetManifest(ctx, "echo")
	if rec2.Injections[0].Placeholder != rec1.Injections[0].Placeholder {
		t.Fatal("idempotent re-install must not regenerate placeholders")
	}

	// Upgrade WITHOUT AutoConsent: consent goes stale.
	inst.AutoConsent = false
	if _, err := inst.Install(ctx, "echo"); err != nil { // latest = 0.2.0
		t.Fatal(err)
	}
	rec3, _ := st.GetManifest(ctx, "echo")
	if rec3.Version != "0.2.0" || !rec3.NeedsReconsent() {
		t.Fatalf("upgrade must record 0.2.0 and need re-consent: %+v", rec3)
	}
}

func TestInstallByDigestRef(t *testing.T) {
	inst, _ := newTestInstaller(t, true)
	ix, err := inst.Client.FetchIndex(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m, _ := ix.Resolve("echo@0.1.0")
	if _, err := inst.Install(context.Background(), m.Image.Digest); err != nil {
		t.Fatalf("install by sha256 ref: %v", err)
	}
}

func TestUninstallRemovesEverything(t *testing.T) {
	inst, st := newTestInstaller(t, true)
	ctx := context.Background()
	srv, err := inst.Install(ctx, "echo@0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := inst.Uninstall(ctx, "echo"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetManifest(ctx, "echo"); err == nil {
		t.Fatal("manifest must be deleted")
	}
	if servers, _ := st.ListServers(ctx); len(servers) != 0 {
		t.Fatal("server row must be deleted")
	}
	if _, err := os.Stat(srv.Binary); !os.IsNotExist(err) {
		t.Fatal("extracted files must be removed")
	}
}

func TestInstallUnknownRefFails(t *testing.T) {
	inst, _ := newTestInstaller(t, true)
	if _, err := inst.Install(context.Background(), "nope@1.0.0"); err == nil {
		t.Fatal("unknown ref must fail")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Code/gigmcp && go test ./internal/registry/ 2>&1 | head -5`
Expected: FAIL (compile: `IndexInstaller` undefined)

- [ ] **Step 3: Write the implementation**

`internal/registry/api.go`:

```go
package registry

import (
	"context"

	"github.com/gigmcp/gigmcp/internal/store"
)

// Installer is the install seam shared with the frontend workstream
// (handoff §6.B) — its REST API calls exactly this. Record-only: Install
// never spawns; the gateway run-loop owns spawning.
type Installer interface {
	// Install resolves ref (name@version | name = latest | sha256:<digest>),
	// pulls + verifies + extracts the pinned image, and records the server +
	// manifest. Idempotent by (name, version, manifest hash).
	Install(ctx context.Context, ref string) (store.Server, error)
	// Uninstall removes the server's store rows and extracted files.
	Uninstall(ctx context.Context, name string) error
	// List returns all registered servers.
	List(ctx context.Context) ([]store.Server, error)
}
```

`internal/registry/installer.go`:

```go
package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/store"
)

// IndexInstaller implements Installer against the signed registry index.
type IndexInstaller struct {
	Store   store.Store
	Client  *Client
	Puller  *oci.Puller
	DataDir string // extracted binaries land in <DataDir>/servers/<name>@<version>/server
	// AutoConsent records consent at install time. Set for operator-initiated
	// boot installs (GIG_INSTALL); leave false for API installs so the
	// frontend's consent flow gates the spawn (DESIGN #7).
	AutoConsent bool
}

var _ Installer = (*IndexInstaller)(nil)

func (i *IndexInstaller) Install(ctx context.Context, ref string) (store.Server, error) {
	ix, err := i.Client.FetchIndex(ctx)
	if err != nil {
		return store.Server{}, err
	}
	m, err := ix.Resolve(ref)
	if err != nil {
		return store.Server{}, err
	}
	// Defense in depth: a signed-but-malformed manifest must still not install.
	if err := m.Validate(); err != nil {
		return store.Server{}, fmt.Errorf("registry: manifest %s@%s invalid: %w", m.Name, m.Version, err)
	}
	hash, err := m.Hash()
	if err != nil {
		return store.Server{}, err
	}

	dest := filepath.Join(i.DataDir, "servers", m.Name+"@"+m.Version, "server")

	// Idempotent by (name, version, hash): same install → refresh, keep
	// placeholders and consent untouched.
	if existing, err := i.Store.GetManifest(ctx, m.Name); err == nil &&
		existing.Version == m.Version && existing.ManifestHash == hash {
		if _, statErr := os.Stat(dest); statErr == nil {
			return i.Store.EnsureServer(ctx, m.Name, dest)
		}
	}

	if err := i.Puller.Extract(ctx, m.Image.Ref, m.Image.Digest, m.Image.Entrypoint, dest); err != nil {
		return store.Server{}, err
	}

	injections := make([]store.Injection, 0, len(m.Credentials))
	for _, c := range m.Credentials {
		ph, err := newPlaceholder()
		if err != nil {
			return store.Server{}, err
		}
		injections = append(injections, store.Injection{
			ID: c.ID, Header: c.Inject.Header, Format: c.Inject.Format,
			Env: c.Inject.Env, Placeholder: ph,
		})
	}
	tools := make([]store.ToolEntry, 0, len(m.Tools))
	for _, tl := range m.Tools {
		tools = append(tools, store.ToolEntry{Name: tl.Name, Default: tl.Default})
	}

	srv, err := i.Store.EnsureServer(ctx, m.Name, dest)
	if err != nil {
		return store.Server{}, err
	}
	if err := i.Store.PutManifest(ctx, store.ManifestRecord{
		Server: m.Name, Version: m.Version, Digest: m.Image.Digest,
		Tier: m.Tier, Entrypoint: m.Image.Entrypoint,
		AllowedHosts: m.Entitlements.Egress,
		Injections:   injections, Tools: tools, ManifestHash: hash,
	}); err != nil {
		return store.Server{}, err
	}
	if i.AutoConsent {
		if err := i.Store.RecordConsent(ctx, m.Name, hash); err != nil {
			return store.Server{}, err
		}
	}
	return srv, nil
}

func (i *IndexInstaller) Uninstall(ctx context.Context, name string) error {
	if err := i.Store.DeleteManifest(ctx, name); err != nil {
		return err
	}
	if err := i.Store.DeleteServer(ctx, name); err != nil {
		return err
	}
	// name is schema-validated [a-z0-9-]+, so the glob is meta-character-free.
	matches, err := filepath.Glob(filepath.Join(i.DataDir, "servers", name+"@*"))
	if err != nil {
		return err
	}
	var errs []error
	for _, d := range matches {
		errs = append(errs, os.RemoveAll(d))
	}
	return errors.Join(errs...)
}

func (i *IndexInstaller) List(ctx context.Context) ([]store.Server, error) {
	return i.Store.ListServers(ctx)
}

// newPlaceholder returns a high-entropy sentinel. The proxy matches it as a
// SUBSTRING of the header value (proxy.Credential), so it must be unguessable
// and collision-free — this replaces the hardcoded "PLACEHOLDER".
func newPlaceholder() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "gigph-" + hex.EncodeToString(b[:]), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ~/Code/gigmcp && go test ./internal/registry/ -v 2>&1 | tail -5`
Expected: PASS (all)

- [ ] **Step 5: Commit**

```bash
cd ~/Code/gigmcp && git add internal/registry && git commit -m "feat(registry): record-only Installer — resolve, pull, verify, extract, record (seam 6.B)"
```

---

### Task 12: Resolver refactor — manifest hard cap + vault secret (seam §6.C)

**Files:**
- Modify: `internal/gateway/resolver.go`
- Create: `internal/gateway/resolver_test.go`

- [ ] **Step 1: Write the failing test**

`internal/gateway/resolver_test.go`:

```go
package gateway

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	kek := make([]byte, 32)
	v, err := vault.New(kek)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestResolveManifestBacked(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	v := testVault(t)
	ctx := context.Background()

	enc, err := v.Encrypt([]byte("real-secret"))
	if err != nil {
		t.Fatal(err)
	}
	// Credential row carries ONLY the secret (manifest-backed server) —
	// its legacy injection/allowlist columns are deliberately junk to prove
	// they are ignored.
	if err := st.PutCredential(ctx, store.Credential{
		Server: "slack-mcp", Tenant: "default", EncryptedKey: enc,
		InjectHeader: "X-IGNORED", InjectFormat: "ignored", Placeholder: "ignored",
		AllowedHosts: []string{"ignored.example"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "slack-mcp", Version: "1.0.0", Digest: "sha256:x", Tier: "sealed",
		Entrypoint: "/server", AllowedHosts: []string{"slack.com", "*.slack.com"},
		Injections: []store.Injection{{
			ID: "tok", Header: "Authorization", Format: "Bearer {token}", Placeholder: "gigph-deadbeef",
		}},
		ManifestHash: "h1",
	}); err != nil {
		t.Fatal(err)
	}

	r := &CredResolver{Store: st, Vault: v}
	cred, err := r.Resolve(proxy.Identity{Server: "slack-mcp", Tenant: "default"}, "slack.com")
	if err != nil {
		t.Fatal(err)
	}
	if cred.RealSecret != "real-secret" {
		t.Fatalf("secret = %q", cred.RealSecret)
	}
	// Manifest is the hard cap: injection + allowlist MUST come from it.
	if cred.InjectHeader != "Authorization" || cred.Placeholder != "gigph-deadbeef" {
		t.Fatalf("injection must come from manifest: %+v", cred)
	}
	if len(cred.AllowedHosts) != 2 || cred.AllowedHosts[0] != "slack.com" {
		t.Fatalf("allowlist must come from manifest: %v", cred.AllowedHosts)
	}
}

func TestResolveLegacyFallback(t *testing.T) {
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	v := testVault(t)
	ctx := context.Background()

	enc, _ := v.Encrypt([]byte("legacy-secret"))
	// No manifest row: legacy GIG_ECHO_BIN-style server — credential row
	// still carries injection + allowlist (unchanged demo flow).
	if err := st.PutCredential(ctx, store.Credential{
		Server: "echo", Tenant: "default", EncryptedKey: enc,
		InjectHeader: "Authorization", InjectFormat: "Bearer {token}",
		Placeholder: "PLACEHOLDER", AllowedHosts: []string{"api.example.com"},
	}); err != nil {
		t.Fatal(err)
	}
	r := &CredResolver{Store: st, Vault: v}
	cred, err := r.Resolve(proxy.Identity{Server: "echo", Tenant: "default"}, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if cred.RealSecret != "legacy-secret" || cred.InjectHeader != "Authorization" ||
		cred.Placeholder != "PLACEHOLDER" || cred.AllowedHosts[0] != "api.example.com" {
		t.Fatalf("legacy fallback broken: %+v", cred)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Code/gigmcp && go test ./internal/gateway/ -run TestResolve -v 2>&1 | tail -5`
Expected: `TestResolveManifestBacked` FAILS (injection comes from the credential row today); `TestResolveLegacyFallback` passes.

- [ ] **Step 3: Write the implementation**

Replace `Resolve` in `internal/gateway/resolver.go` (imports gain `errors`):

```go
// Resolve assembles the proxy credential from TWO sources (DESIGN #7,
// seam §6.C): the MANIFEST (by server) supplies the author-declared hard cap
// — allowlist + injection schema + placeholder; the VAULT (by server,tenant)
// supplies only the real secret. Servers without a manifest (legacy
// GIG_ECHO_BIN seeding) fall back to the credential row's own fields.
func (c *CredResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	ctx := context.Background()
	cred, err := c.Store.GetCredential(ctx, id.Server, id.Tenant)
	if err != nil {
		return proxy.Credential{}, err
	}
	secret, err := c.Vault.Decrypt(cred.EncryptedKey)
	if err != nil {
		return proxy.Credential{}, err
	}
	rec, err := c.Store.GetManifest(ctx, id.Server)
	if errors.Is(err, store.ErrManifestNotFound) {
		return proxy.Credential{
			RealSecret:   string(secret),
			InjectHeader: cred.InjectHeader,
			InjectFormat: cred.InjectFormat,
			Placeholder:  cred.Placeholder,
			AllowedHosts: cred.AllowedHosts,
		}, nil
	}
	if err != nil {
		return proxy.Credential{}, err
	}
	// v1 enforces the FIRST credential's injection (spec §7: multi-credential
	// rewrite is a follow-up; the schema already supports it).
	var inj store.Injection
	if len(rec.Injections) > 0 {
		inj = rec.Injections[0]
	}
	return proxy.Credential{
		RealSecret:   string(secret),
		InjectHeader: inj.Header,
		InjectFormat: inj.Format,
		Placeholder:  inj.Placeholder,
		AllowedHosts: rec.AllowedHosts,
	}, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd ~/Code/gigmcp && go test ./internal/gateway/ -run TestResolve -v 2>&1 | tail -3`
Expected: PASS (both)

- [ ] **Step 5: Commit**

```bash
cd ~/Code/gigmcp && git add internal/gateway && git commit -m "feat(gateway): resolver merges manifest hard-cap + vault secret (seam 6.C)"
```

---

### Task 13: Aggregator default-subset filter + backend-name validation

**Files:**
- Modify: `internal/gateway/gateway.go`
- Modify: `internal/gateway/gateway_test.go` (add tests; keep existing ones green)

- [ ] **Step 1: Write the failing tests** (append to `internal/gateway/gateway_test.go`; reuse the file's existing in-memory backend helper if one exists — if it spawns real sessions, follow the established pattern there for constructing a `Backend`)

```go
func TestNewRejectsBadBackendNames(t *testing.T) {
	ctx := context.Background()
	// Underscore breaks <backend>_<tool> parsing (DESIGN §5 follow-up).
	_, err := New(ctx, "test", []Backend{{Name: "bad_name"}})
	if err == nil || !strings.Contains(err.Error(), "_") {
		t.Fatalf("underscore name must be rejected, got %v", err)
	}
	_, err = New(ctx, "test", []Backend{{Name: "dup"}, {Name: "dup"}})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate names must be rejected, got %v", err)
	}
}
```

For the Expose filter, extend the existing aggregator test (the file already
builds a real echo backend session): after building a backend with TWO tools
(use the in-memory MCP server pattern already present in
`internal/gateway/gateway_test.go` / `e2e_test.go`), assert:

```go
// backend exposes tools "echo" and "loud" — Expose only allows "echo":
gw, err := New(ctx, "test", []Backend{{Name: "b", Session: sess, Expose: map[string]bool{"echo": true}}})
// connect a client to gw (same pattern as the existing test) and ListTools:
// want: "b_echo" present, "b_loud" absent.
```

(Write it concretely against whatever helper the existing test file uses to
build a session with two tools — add a second tool to the helper if needed.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ~/Code/gigmcp && go test ./internal/gateway/ -run 'TestNewRejects|TestExpose' -v 2>&1 | tail -5`
Expected: FAIL (no name validation; `Expose` field undefined)

- [ ] **Step 3: Implement** — in `internal/gateway/gateway.go`:

```go
// Backend is a connected upstream MCP server.
type Backend struct {
	Name    string // namespace prefix for its tools; must not contain "_"
	Session *mcp.ClientSession
	// Expose filters which tools are re-exposed (manifest default subset,
	// DESIGN #11). nil = expose all (legacy servers without a manifest).
	Expose map[string]bool
}

// New builds the aggregating MCP server over the given backends.
func New(ctx context.Context, version string, backends []Backend) (*mcp.Server, error) {
	gw := mcp.NewServer(&mcp.Implementation{Name: "gigmcp", Version: version}, nil)
	seen := map[string]bool{}
	for _, b := range backends {
		if strings.Contains(b.Name, "_") {
			return nil, fmt.Errorf("backend name %q must not contain '_' (it is the tool-namespace separator)", b.Name)
		}
		if seen[b.Name] {
			return nil, fmt.Errorf("duplicate backend name %q", b.Name)
		}
		seen[b.Name] = true
		sess := b.Session
		tools, err := sess.ListTools(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("list tools for backend %q: %w", b.Name, err)
		}
		for _, tool := range tools.Tools {
			if b.Expose != nil && !b.Expose[tool.Name] {
				continue // non-default tool: connected but not exposed (meta-tools path later)
			}
			upstream := tool.Name // captured per-iteration for the closure
			proxied := *tool
			proxied.Name = b.Name + "_" + upstream
			gw.AddTool(&proxied, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
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

(`strings` joins the imports. Name validation runs BEFORE `ListTools` so a bad
name fails fast even when the session is nil in tests.)

- [ ] **Step 4: Run the full gateway package tests**

Run: `cd ~/Code/gigmcp && go test ./internal/gateway/ 2>&1 | tail -3`
Expected: PASS (new + existing; sandbox E2Es skip on macOS)

- [ ] **Step 5: Commit**

```bash
cd ~/Code/gigmcp && git add internal/gateway && git commit -m "feat(gateway): manifest default-subset tool filter + backend name validation"
```

---

### Task 14: Spawn placeholder parameter

**Files:**
- Modify: `internal/gateway/spawn.go` (signature + env), `cmd/gateway/main.go` (call site), `internal/gateway/egress_e2e_test.go` + any other `SpawnEgressBackend` callers (`grep -rn "SpawnEgressBackend" --include='*.go'`)

- [ ] **Step 1: Change the signature** — add a trailing `placeholder string` param to `SpawnEgressBackend`; in the `Env` map replace the hardcoded sentinel:

```go
func SpawnEgressBackend(
	ctx context.Context,
	srv store.Server,
	alloc *netmgr.Allocator,
	reg *proxy.Registry,
	proxyPort int,
	caFile string,
	bootstrapPath string,
	placeholder string, // manifest-generated sentinel; "" = legacy "PLACEHOLDER"
) (*EgressBackend, error) {
```

and where the spec env is built:

```go
	if placeholder == "" {
		placeholder = "PLACEHOLDER" // legacy GIG_ECHO_BIN demo path
	}
	...
			Env: map[string]string{
				"HTTPS_PROXY":         fmt.Sprintf("http://%s:%d", proxyIP, proxyPort),
				"SSL_CERT_FILE":       "/etc/gigmcp-ca.pem",
				"NODE_EXTRA_CA_CERTS": "/etc/gigmcp-ca.pem",
				"GIG_PLACEHOLDER":     placeholder,
			},
```

- [ ] **Step 2: Update every caller** — `grep -rn "SpawnEgressBackend(" ~/Code/gigmcp --include='*.go'`; pass `""` at existing call sites (main.go gets the real value in Task 15).

- [ ] **Step 3: Verify it compiles and the suite passes**

Run: `cd ~/Code/gigmcp && go build ./... && go test ./... 2>&1 | tail -3`
Expected: PASS (Linux-only tests skip)

- [ ] **Step 4: Commit**

```bash
cd ~/Code/gigmcp && git add -A && git commit -m "feat(gateway): per-install placeholder sentinel reaches the sandbox env"
```

---

### Task 15: Config + `main.go` wiring (seam §6.D)

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go` (create if absent), `cmd/gateway/main.go`

- [ ] **Step 1: Write the failing config test**

`internal/config/config_test.go`:

```go
package config

import (
	"strings"
	"testing"
)

func TestFromEnvRegistryFields(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_ECHO_BIN", "")
	t.Setenv("GIG_INSTALL", "echo@0.1.0, fetch")
	t.Setenv("GIG_REGISTRY_INDEX_URL", "file:///tmp/index.json")
	t.Setenv("GIG_REGISTRY_PUBKEY", "abcd")
	t.Setenv("GIG_DATA_DIR", "")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Install != "echo@0.1.0, fetch" || cfg.RegistryIndexURL != "file:///tmp/index.json" {
		t.Fatalf("bad cfg: %+v", cfg)
	}
	if cfg.DataDir != "/data" {
		t.Fatalf("DataDir default = %q, want /data", cfg.DataDir)
	}
}

func TestEchoBinNowOptional(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_ECHO_BIN", "")
	t.Setenv("GIG_INSTALL", "")
	if _, err := FromEnv(); err != nil {
		t.Fatalf("GIG_ECHO_BIN must be optional now: %v", err)
	}
}

func TestInstallRequiresIndexURLAndKey(t *testing.T) {
	t.Setenv("GIG_BEARER_TOKEN", "tok")
	t.Setenv("GIG_INSTALL", "echo")
	t.Setenv("GIG_REGISTRY_INDEX_URL", "")
	t.Setenv("GIG_REGISTRY_PUBKEY", "")
	_, err := FromEnv()
	if err == nil || !strings.Contains(err.Error(), "GIG_REGISTRY") {
		t.Fatalf("GIG_INSTALL without index URL/pubkey must fail: %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ~/Code/gigmcp && go test ./internal/config/ 2>&1 | head -5`
Expected: FAIL (`Install` field undefined / `GIG_ECHO_BIN must be set`)

- [ ] **Step 3: Implement config changes** — in `internal/config/config.go` add fields and swap the EchoBinary check:

```go
	// ... existing fields ...
	RegistryIndexURL string // GIG_REGISTRY_INDEX_URL: https:// or file:// index.json location
	RegistryPubKey   string // GIG_REGISTRY_PUBKEY: 32-byte ed25519 hex (index trust root)
	Install          string // GIG_INSTALL: comma-separated refs installed at boot (auto-consented)
	DataDir          string // GIG_DATA_DIR, default "/data": extracted server binaries
```

in `FromEnv`:

```go
		RegistryIndexURL: os.Getenv("GIG_REGISTRY_INDEX_URL"),
		RegistryPubKey:   os.Getenv("GIG_REGISTRY_PUBKEY"),
		Install:          os.Getenv("GIG_INSTALL"),
		DataDir:          envOr("GIG_DATA_DIR", "/data"),
```

replace the `GIG_ECHO_BIN` requirement:

```go
	// GIG_ECHO_BIN is now an OPTIONAL legacy/dev fallback (registry-driven
	// install replaces seeding — handoff §6.D).
	if cfg.Install != "" && (cfg.RegistryIndexURL == "" || cfg.RegistryPubKey == "") {
		return Config{}, errors.New("GIG_INSTALL requires GIG_REGISTRY_INDEX_URL and GIG_REGISTRY_PUBKEY")
	}
```

- [ ] **Step 4: Wire `main.go`** — in `cmd/gateway/main.go`:

Replace the seeding block (lines ~74-77):

```go
	// Legacy dev fallback: seed the echo backend only if GIG_ECHO_BIN is set.
	if cfg.EchoBinary != "" {
		if _, err := st.EnsureServer(ctx, "echo", cfg.EchoBinary); err != nil {
			return fmt.Errorf("seed echo server: %w", err)
		}
	}

	// Registry-driven install of the configured boot set (GIG_INSTALL).
	if err := installFromIndex(ctx, st); err != nil {
		return err
	}
```

`installFromIndex` needs cfg — pass it: `installFromIndex(ctx, st, cfg)`.

Replace the spawn loop body with the helper call:

```go
	backends, cleanups, err := spawnInstalled(ctx, st, servers, alloc, reg, cfg, caFile)
	if err != nil {
		return err
	}
```

Append the helpers (mirroring `seedDemoCredential` style; imports gain
`github.com/gigmcp/gigmcp/internal/oci` and `github.com/gigmcp/gigmcp/internal/registry`):

```go
// installFromIndex installs each GIG_INSTALL ref from the signed registry
// index (record-only; spawning happens in spawnInstalled). Boot installs are
// operator-initiated, so consent is recorded at install time.
func installFromIndex(ctx context.Context, st store.Store, cfg config.Config) error {
	if cfg.Install == "" {
		return nil
	}
	inst := &registry.IndexInstaller{
		Store:       st,
		Client:      &registry.Client{IndexURL: cfg.RegistryIndexURL, PublicKeyHex: cfg.RegistryPubKey},
		Puller:      &oci.Puller{},
		DataDir:     cfg.DataDir,
		AutoConsent: true,
	}
	for _, ref := range strings.Split(cfg.Install, ",") {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if _, err := inst.Install(ctx, ref); err != nil {
			return fmt.Errorf("install %q: %w", ref, err)
		}
		log.Printf("installed %q from registry index", ref)
	}
	return nil
}

// spawnInstalled spawns every stored server, enforcing re-consent (fail
// closed) and wiring the manifest's placeholder + default tool subset.
func spawnInstalled(
	ctx context.Context,
	st store.Store,
	servers []store.Server,
	alloc *netmgr.Allocator,
	reg *proxy.Registry,
	cfg config.Config,
	caFile string,
) ([]gw.Backend, []func(), error) {
	var backends []gw.Backend
	var cleanups []func()
	for _, srv := range servers {
		placeholder := ""
		var expose map[string]bool
		rec, err := st.GetManifest(ctx, srv.Name)
		switch {
		case err == nil:
			if rec.NeedsReconsent() {
				log.Printf("backend %q requires re-consent (manifest changed); NOT spawning", srv.Name)
				continue
			}
			if len(rec.Injections) > 0 {
				placeholder = rec.Injections[0].Placeholder
			}
			expose = map[string]bool{}
			for _, tl := range rec.Tools {
				if tl.Default {
					expose[tl.Name] = true
				}
			}
		case errors.Is(err, store.ErrManifestNotFound):
			// legacy server (GIG_ECHO_BIN): no manifest, expose all tools
		default:
			return nil, nil, fmt.Errorf("manifest for %q: %w", srv.Name, err)
		}
		eb, err := gw.SpawnEgressBackend(ctx, srv, alloc, reg, cfg.ProxyPort, caFile, cfg.BootstrapPath, placeholder)
		if err != nil {
			return nil, nil, fmt.Errorf("spawn egress backend %q: %w", srv.Name, err)
		}
		cleanups = append(cleanups, eb.Cleanup)
		backends = append(backends, gw.Backend{Name: srv.Name, Session: eb.Session, Expose: expose})
		log.Printf("backend %q running in egress sandbox (pid=%d)", srv.Name, eb.ChildPID)
	}
	return backends, cleanups, nil
}
```

(`errors` joins main.go's imports.)

- [ ] **Step 5: Verify everything compiles and passes locally**

Run: `cd ~/Code/gigmcp && go build ./... && go test ./... 2>&1 | tail -3`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
cd ~/Code/gigmcp && git add -A && git commit -m "feat(gateway): registry-driven boot install + re-consent-gated spawn (seam 6.D)"
```

---### Task 16: Container E2E — install from signed fixture index → sandboxed spawn → subset visible

**Files:**
- Create: `internal/gateway/registry_e2e_test.go`

- [ ] **Step 1: Write the E2E test** (gating mirrors `egress_e2e_test.go:34`)

```go
package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gigmcp/gigmcp-registry/schema"
	"github.com/gigmcp/gigmcp/internal/netmgr"
	"github.com/gigmcp/gigmcp/internal/oci"
	"github.com/gigmcp/gigmcp/internal/oci/ocitest"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/registry"
	"github.com/gigmcp/gigmcp/internal/sandbox"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestRegistryInstallE2E proves the whole pipeline: signed index → resolve →
// pull by digest from an OCI layout → verify → extract → record → spawn in
// the real egress sandbox → tool callable through the aggregator.
func TestRegistryInstallE2E(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("registry E2E requires Linux + bwrap — run: make test")
	}
	if os.Geteuid() != 0 {
		t.Skip("registry E2E requires root (uid/gid map writes) — run: make test")
	}
	ctx := context.Background()

	// 1. Build the real echo-mcp static binary and package it as an image.
	bin := filepath.Join(t.TempDir(), "echo-mcp")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/gigmcp/gigmcp/cmd/echo-mcp")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build echo-mcp: %v\n%s", err, out)
	}
	binBytes, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	layoutDir := t.TempDir()
	digest, err := ocitest.WriteLayoutImage(layoutDir, map[string][]byte{"app/echo": binBytes})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Signed fixture index over a manifest pinning that digest.
	m := &schema.Manifest{
		SchemaVersion: 1, Name: "echo", Version: "0.1.0",
		Source: schema.Source{Repo: "github.com/gigmcp/gigmcp", Tag: "v0.1.0"},
		Image:  schema.Image{Ref: "ghcr.io/gigmcp/echo-mcp", Digest: digest, Entrypoint: "/app/echo"},
		Tier:   schema.TierSealed,
		Entitlements: schema.Entitlements{Egress: []string{"api.example.com"}},
		Credentials: []schema.Credential{{
			ID: "token", Type: "api_key", Provider: "example",
			Inject: schema.Inject{Header: "Authorization", Format: "Bearer {token}"},
		}},
		Tools: []schema.Tool{{Name: "echo", Default: true}},
	}
	ix, err := schema.BuildIndex([]*schema.Manifest{m}, "2026-06-06T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ix)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sig, _ := schema.Sign(hex.EncodeToString(priv), raw)
	idxPath := filepath.Join(t.TempDir(), "index.json")
	os.WriteFile(idxPath, raw, 0o644)
	os.WriteFile(idxPath+".sig", []byte(sig), 0o644)

	// 3. Install.
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	inst := &registry.IndexInstaller{
		Store:  st,
		Client: &registry.Client{IndexURL: "file://" + idxPath, PublicKeyHex: hex.EncodeToString(pub)},
		Puller: &oci.Puller{LayoutDir: layoutDir},
		DataDir: t.TempDir(), AutoConsent: true,
	}
	srv, err := inst.Install(ctx, "echo@0.1.0")
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	rec, err := st.GetManifest(ctx, "echo")
	if err != nil || rec.NeedsReconsent() {
		t.Fatalf("manifest record: %+v err=%v", rec, err)
	}

	// 4. Spawn the INSTALLED binary in the real egress sandbox (same harness
	// as egress_e2e_test).
	kek := make([]byte, 32)
	v, _ := vault.New(kek)
	reg := proxy.NewRegistry()
	resolver := &CredResolver{Store: st, Vault: v}
	egProxy, err := proxy.New(reg, resolver)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, egProxy.CACertPEM(), 0o644)
	alloc := netmgr.NewAllocator("10.97.0.0/16")
	bootstrapPath := os.Getenv("GIG_BOOTSTRAP_PATH")
	if bootstrapPath == "" {
		bootstrapPath = buildBootstrap(t) // reuse/extract the existing egress E2E helper for building cmd/bootstrap
	}
	eb, err := SpawnEgressBackend(ctx, srv, alloc, reg, 0, caFile, bootstrapPath, rec.Injections[0].Placeholder)
	if err != nil {
		t.Fatalf("spawn installed server: %v", err)
	}
	defer eb.Cleanup()

	// 5. Aggregate with the manifest's default subset and list tools.
	expose := map[string]bool{}
	for _, tl := range rec.Tools {
		if tl.Default {
			expose[tl.Name] = true
		}
	}
	gwServer, err := New(ctx, "test", []Backend{{Name: "echo", Session: eb.Session, Expose: expose}})
	if err != nil {
		t.Fatal(err)
	}
	cTransport, sTransport := mcp.NewInMemoryTransports()
	go gwServer.Run(ctx, sTransport)
	client := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	cs, err := client.Connect(ctx, cTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != "echo_echo" {
		t.Fatalf("want exactly [echo_echo], got %+v", tools.Tools)
	}
}
```

**Note:** `buildBootstrap` and the in-memory connect pattern: copy the
mechanics from `internal/gateway/egress_e2e_test.go` (it already builds
`cmd/bootstrap` and drives a sandboxed session). If that file exports no
helper, lift its bootstrap-build lines into this test verbatim. If
`mcp.NewInMemoryTransports` differs in the vendored SDK version, use the same
client-connection pattern `e2e_test.go` uses for the aggregator.

- [ ] **Step 2: Run on macOS to confirm it skips**

Run: `cd ~/Code/gigmcp && go test ./internal/gateway/ -run TestRegistryInstallE2E -v`
Expected: SKIP

- [ ] **Step 3: Run the full container suite**

Run: `cd ~/Code/gigmcp && make test 2>&1 | tail -10`
Expected: ALL PASS including `TestRegistryInstallE2E`

- [ ] **Step 4: Commit**

```bash
cd ~/Code/gigmcp && git add internal/gateway && git commit -m "test(e2e): signed index → install → sandboxed spawn → default-subset tools"
```

---

### Task 17: Static-build guard + Dockerfile note + handoff docs update

**Files:**
- Modify: `~/Code/gigmcp/Dockerfile` (comment only), `docs/handoffs/manifest-registry.md` (status note)

- [ ] **Step 1: Assert the static build still works with the OCI dep**

Run: `cd ~/Code/gigmcp && CGO_ENABLED=0 go build -o /tmp/gigmcp-gateway ./cmd/gateway && file /tmp/gigmcp-gateway && rm /tmp/gigmcp-gateway`
Expected: builds; `file` shows a static binary (on macOS it cross-checks the build; the container build is the real proof via `make test`'s dev image)

- [ ] **Step 2: Document the production-image caveat** — add to `Dockerfile` above `RUN go mod download`:

```dockerfile
# NOTE(manifest-registry): go.mod replaces github.com/gigmcp/gigmcp-registry/schema
# with ../gigmcp-registry (outside this build context). Until the registry repo
# is published and tagged (then: drop the replace, pin a version, set
# GOPRIVATE=github.com/gigmcp/*), build production images from a context that
# contains both repos or vendor the module. Dev/test flow (make test) mounts
# both repos and is unaffected.
```

- [ ] **Step 3: Commit**

```bash
cd ~/Code/gigmcp && git add Dockerfile && git commit -m "docs(build): note cross-repo schema module caveat for production images"
```

---

### Task 18: Publish `gigmcp-registry` to GitHub (requires owner/`gh` access)

**Files:** none (operational)

- [ ] **Step 1: Create and push the repo** (skip if no GitHub access; flag for the owner)

```bash
cd ~/Code/gigmcp-registry
gh repo create gigmcp/gigmcp-registry --public --source . --push || \
  echo "FLAG FOR OWNER: create github.com/gigmcp/gigmcp-registry and push"
```

- [ ] **Step 2: Generate the production signing key** (owner action — document it)

```bash
go run ./cmd/registryctl keygen
# → private key: GitHub Actions secret GIG_INDEX_SIGNING_KEY (repo settings)
# → public key:  gateway deployments set GIG_REGISTRY_PUBKEY
```

- [ ] **Step 3: Verify CI runs green on the pushed repo** (lint workflow on main)

---

### Task 19: Spike C — full-rootfs investigation (throwaway; feeds the follow-up plan)

**Files:**
- Create: `docs/superpowers/specs/2026-06-06-rootfs-spike-findings.md` (findings only — **no `internal/sandbox` changes**)

- [ ] **Step 1: In the dev container, extract a real interpreter-based image** (e.g. `registry.k8s.io`-hosted or any small Node/Python image) with `internal/oci`'s machinery into a temp rootfs dir; attempt to run its entrypoint via the existing single-binary mount. Expected: fails (missing interpreter/libs) — capture the exact error.

- [ ] **Step 2: Prototype (THROWAWAY, not committed to internal/sandbox)** a bwrap invocation that ro-binds the extracted rootfs top-level dirs (`--ro-bind <rootfs>/usr /usr` etc.) and confirm the interpreter starts under the same userns/netns flags the sandbox uses.

- [ ] **Step 3: Write findings** — what minimal `sandbox.Spec` extension is needed (e.g. `RootfsDir string` emitting per-top-dir ro-binds), interaction with seccomp/bootstrap, open risks. This document is the input to the rootfs follow-up plan to be agreed with the sandbox owner (handoff §6.E path 2).

- [ ] **Step 4: Commit the findings doc**

```bash
cd ~/Code/gigmcp && git add docs/superpowers/specs/2026-06-06-rootfs-spike-findings.md && git commit -m "docs(spike): rootfs-under-sandbox findings for follow-up plan"
```

---

## Plan self-review (done at write time)

- **Spec coverage:** schema module (T2-4) ✓, registryctl + CI + manifests + docs (T5-6) ✓, store (T8) ✓, oci (T9) ✓, client/installer (T10-11) ✓, resolver (T12) ✓, subset+names (T13) ✓, placeholder (T14) ✓, config/main (T15) ✓, container E2E (T16) ✓, static-build guard (T17) ✓, publish/keys (T18) ✓, Spike C (T19) ✓. Re-consent covered in T8/T11/T15/T16.
- **Known judgment points for the executor:** Task 13's Expose test and Task 16's bootstrap-build helper intentionally defer to existing test-file patterns (`gateway_test.go`, `egress_e2e_test.go`) rather than inventing parallel harnesses — read those files first.
- **Type consistency:** `store.ManifestRecord/Injection/ToolEntry`, `registry.IndexInstaller/Client`, `oci.Puller`, `gw.Backend.Expose`, `SpawnEgressBackend(..., placeholder string)` used consistently across tasks.

---

## Deviations & follow-ups (from final review)

- **Baked-in registry pubkey deferred** (spec decision #1): `internal/registry.DefaultPublicKeyHex` not added — blocked on T18 keygen (owner-gated). Until then `GIG_REGISTRY_PUBKEY` is required config; fail-closed.
- **Test fixtures are runtime-generated** (ocitest.WriteLayoutImage, writeSignedIndex) instead of committed testdata — hermetic and self-maintaining; intentional deviation.
- **Follow-ups:**
  - Prune previous version's extracted dir on upgrade (installer leaves `<name>@<oldver>` on disk until Uninstall).
  - Size ceiling for `oci.extractFile` io.Copy (mirror the index client's LimitReader).
  - Credential-less manifest servers cannot egress (resolver requires a credential row before consulting the manifest allowlist) — add a no-credential path when the registry gains unauthenticated servers.
  - Dial-time private-IP guard in the proxy as defense-in-depth behind the lint denylist.
  - gigmcp repo has no CI workflows (pre-existing); spec's "CGO_ENABLED=0 asserted in CI" is covered only by Dockerfile build + E2E.
