# Egress Proxy + Encrypted Vault Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A sandboxed MCP server reaches third-party APIs only through an embedded MITM egress proxy that (a) enforces a per-tenant domain allowlist, (b) injects the tenant's real credential — decrypted from an envelope-encrypted vault — in place of a placeholder, so the real key **never enters the sandbox**, and (c) cannot be bypassed because the sandbox's only network route is the proxy.

**Architecture:** Each sandbox runs in its own network namespace (created by bwrap via userns, `--unshare-net`). The gateway, holding **CAP_NET_ADMIN only**, moves a veth pair into the bwrap child (located via bwrap `--info-fd`) by host PID using netlink `LinkSetNsPid` (this avoids the named-netns bind-mount that would need CAP_SYS_ADMIN). A trusted Go **bootstrap** runs as the bwrap entrypoint: it waits on an inherited pipe for the gateway to finish veth injection, configures the link + default route via netlink, signals readiness on a second pipe, drops **all** capabilities, and `execve`s the untrusted server (uid 65534). The sandbox's only route is `default via <proxy-IP>`, so all egress hits the embedded **hand-rolled net/http CONNECT MITM proxy**, which identifies the tenant by the connection's source IP (unforgeable — the netns can only source its own /30), checks the manifest allowlist at CONNECT time, mints a per-host leaf under a runtime CA, and rewrites the `Authorization` header from placeholder → real key fetched from the vault. All empirically validated by spikes on 2026-06-06.

**Tech Stack:** Go; `golang.org/x/crypto/chacha20poly1305` (XChaCha20-Poly1305 envelope encryption); `github.com/vishvananda/netlink` + `github.com/vishvananda/netns` (veth/netns, no `ip` CLI); `golang.org/x/sys/unix` (capability drop); net/http + crypto/tls stdlib (proxy). Builds remain `CGO_ENABLED=0` static.

**Critical environment facts (from spikes — do not re-derive):**
- Dev machine is macOS; all netns/bwrap/proxy tests run in the Linux container via `make test`. Linux-only tests self-skip on macOS via `sandbox.Available()`.
- The gateway container needs `--cap-add NET_ADMIN` + the existing `seccomp=unconfined`,`apparmor=unconfined`,`systempaths=unconfined`. **No SYS_ADMIN, no privileged.**
- bwrap stays in the HOST netns; only its forked **child** enters the new netns. The veth must target the child's host PID (from `--info-fd`), never bwrap's own PID.
- Egress mode must NOT use `--unshare-all` (forces order/late net handling); decompose into `--unshare-user --unshare-net --unshare-pid --unshare-ipc --unshare-uts --unshare-cgroup`. (Note: egress mode DOES keep `--unshare-net` — bwrap creates the netns; the host injects the veth afterward. This is the opposite of a "join existing netns" design.)
- Every fresh netns auto-gets inert tunnel ifaces (`tunl0`,`gre0`,`sit0`,…) on LinuxKit — filter by name; the real link is the injected veth.
- `net.ipv4.ip_forward=1` by default in the container — do NOT rely on missing NAT; add an explicit `FORWARD -j DROP` as belt-and-suspenders.

**Verified API cheat sheet (trust over memory):**
- `chacha20poly1305.NewX(key []byte) (cipher.AEAD, error)` — KeySize 32, NonceSizeX 24; `aead.Seal(dst,nonce,plaintext,aad)`, `aead.Open(dst,nonce,ciphertext,aad)`.
- `netlink.NewVeth(netlink.LinkAttrs{Name:...}) *netlink.Veth` (set `.PeerName`); `netlink.LinkAdd(link)`; `netlink.LinkByName(name)`; `netlink.LinkSetNsPid(link, pid)`; `netlink.LinkSetUp(link)`; `netlink.AddrAdd(link, *netlink.Addr)`; `netlink.RouteAdd(*netlink.Route)`; `netlink.LinkDel(link)`. `netlink.ParseAddr("10.88.0.1/30")`.
- `netns.Get()/netns.GetFromPid(pid)/netns.Set(h)/h.Close()` for the bootstrap to operate inside its own netns (it already IS in it, so direct netlink calls apply to its own netns).
- Capability drop: `unix.Prctl(unix.PR_SET_NO_NEW_PRIVS,1,0,0,0)`; loop `unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(i),0,0,0)` for i in 0..40; `unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)`; `unix.Capset(&unix.CapUserHeader{Version:unix.LINUX_CAPABILITY_VERSION_3, Pid:0}, &unix.CapUserData{})` (zeroed effective/permitted/inheritable).
- bwrap flags available: `--info-fd N`, `--uid`, `--gid`, `--unshare-net`, `--unshare-user`.
- MCP SDK (unchanged from skeleton): see the skeleton plan's cheat sheet. The gateway↔backend stdio channel is UNCHANGED; this plan only adds network isolation + proxy for the backend's *outbound* HTTPS.

---

## File Structure

```
internal/
├── vault/
│   ├── vault.go          # T1: envelope encryption (KEK→DEK), Encrypt/Decrypt
│   └── vault_test.go
├── store/
│   ├── credentials.go    # T2: credentials table; Put/Get encrypted secret + injection meta
│   └── credentials_test.go
├── proxy/
│   ├── ca.go             # T3: runtime ECDSA CA + cached per-host leaf minting
│   ├── ca_test.go
│   ├── proxy.go          # T4: CONNECT MITM, identity-by-IP, allowlist, Tier-1 inject, audit
│   ├── proxy_test.go
│   ├── registry.go       # T4: sourceIP → tenant identity map (thread-safe)
│   └── registry_test.go
├── netmgr/
│   ├── netmgr.go         # T5: /30 allocator + veth create + LinkSetNsPid (host side)
│   └── netmgr_test.go    # Linux-only
├── sandbox/
│   ├── sandbox.go        # T6: egress mode — decomposed unshare, --info-fd, --uid, bootstrap entrypoint
│   └── sandbox_test.go   # extend
cmd/
├── bootstrap/main.go     # T7: in-sandbox trusted init: pipe handshake, netlink config, cap-drop, exec
├── fetch-mcp/main.go     # T8: test MCP server with an https-fetch tool (proves the swap)
└── gateway/main.go       # T9: spawn rework wiring netmgr+bootstrap+proxy+vault
deploy/ + Makefile        # T10: NET_ADMIN cap; FORWARD DROP; docs
```

Responsibilities stay layered: `vault` knows only crypto+KEK; `netmgr` knows only veth/netns; `proxy` knows only HTTP/TLS+identity lookup; `sandbox` knows only bwrap argv; `cmd/bootstrap` is the only code that runs *inside* the sandbox boundary; `cmd/gateway` composes them.

---

### Task 1: Vault — envelope encryption

**Files:** Create `internal/vault/vault.go`, `internal/vault/vault_test.go`

- [ ] **Step 1: Write the failing test** — `internal/vault/vault_test.go`

```go
package vault_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/gigmcp/gigmcp/internal/vault"
)

func newKEK(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	v, err := vault.New(newKEK(t))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	secret := []byte("ghp_realtoken_value")
	box, err := v.Encrypt(secret)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Contains(box, secret) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := v.Decrypt(box)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

func TestEncryptIsNondeterministic(t *testing.T) {
	v, _ := vault.New(newKEK(t))
	a, _ := v.Encrypt([]byte("x"))
	b, _ := v.Encrypt([]byte("x"))
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of same plaintext are identical — nonce reuse")
	}
}

func TestWrongKEKFails(t *testing.T) {
	v1, _ := vault.New(newKEK(t))
	v2, _ := vault.New(newKEK(t))
	box, _ := v1.Encrypt([]byte("secret"))
	if _, err := v2.Decrypt(box); err == nil {
		t.Fatal("decrypt with wrong KEK must fail")
	}
}

func TestTamperFails(t *testing.T) {
	v, _ := vault.New(newKEK(t))
	box, _ := v.Encrypt([]byte("secret"))
	box[len(box)-1] ^= 0xff
	if _, err := v.Decrypt(box); err == nil {
		t.Fatal("tampered ciphertext must fail authentication")
	}
}

func TestNewRejectsBadKEK(t *testing.T) {
	if _, err := vault.New(make([]byte, 16)); err == nil {
		t.Fatal("KEK must be 32 bytes")
	}
}
```

- [ ] **Step 2: Run test, verify it fails** — `go test ./internal/vault/` → undefined `vault.New`.

- [ ] **Step 3: Implement** — `internal/vault/vault.go`

```go
// Package vault provides envelope encryption for credentials at rest
// (DESIGN.md decision #15). Each secret gets a fresh random data key (DEK);
// the DEK is wrapped by the master key (KEK) supplied at startup. A DB dump
// without the KEK is useless. Ciphertext layout (all XChaCha20-Poly1305):
//
//	[1 byte version=1]
//	[24 byte nonce_kek][len-prefixed wrapped-DEK = Seal(KEK, nonce_kek, DEK)]
//	[24 byte nonce_dek][ciphertext = Seal(DEK, nonce_dek, plaintext)]
package vault

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const version = 1

// Vault encrypts/decrypts secrets using envelope encryption under a KEK.
type Vault struct {
	kek []byte
}

// New returns a Vault. kek must be exactly 32 bytes.
func New(kek []byte) (*Vault, error) {
	if len(kek) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("KEK must be %d bytes, got %d", chacha20poly1305.KeySize, len(kek))
	}
	dup := make([]byte, len(kek))
	copy(dup, kek)
	return &Vault{kek: dup}, nil
}

func seal(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, nil), nil
}

func open(key, nonce, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, nil)
}

// Encrypt wraps plaintext with a fresh DEK, itself wrapped by the KEK.
func (v *Vault) Encrypt(plaintext []byte) ([]byte, error) {
	dek := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	nKEK, wrapped, err := seal(v.kek, dek)
	if err != nil {
		return nil, err
	}
	nDEK, ct, err := seal(dek, plaintext)
	if err != nil {
		return nil, err
	}
	out := []byte{version}
	out = append(out, nKEK...)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(wrapped)))
	out = append(out, l[:]...)
	out = append(out, wrapped...)
	out = append(out, nDEK...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt reverses Encrypt.
func (v *Vault) Decrypt(box []byte) ([]byte, error) {
	const nx = chacha20poly1305.NonceSizeX
	if len(box) < 1+nx+4 || box[0] != version {
		return nil, errors.New("vault: malformed or unsupported ciphertext")
	}
	p := 1
	nKEK := box[p : p+nx]
	p += nx
	wlen := int(binary.BigEndian.Uint32(box[p : p+4]))
	p += 4
	if wlen < 0 || p+wlen+nx > len(box) {
		return nil, errors.New("vault: truncated ciphertext")
	}
	wrapped := box[p : p+wlen]
	p += wlen
	dek, err := open(v.kek, nKEK, wrapped)
	if err != nil {
		return nil, fmt.Errorf("vault: unwrap DEK: %w", err)
	}
	nDEK := box[p : p+nx]
	p += nx
	ct := box[p:]
	return open(dek, nDEK, ct)
}
```

- [ ] **Step 4: Run tests, verify pass** — `go test ./internal/vault/` → PASS (5 tests). Also `go get golang.org/x/crypto/chacha20poly1305 && go mod tidy`.

- [ ] **Step 5: Commit** — `git add internal/vault/ go.mod go.sum && git commit -m "feat: envelope-encryption vault (XChaCha20-Poly1305 KEK/DEK)"`

---

### Task 2: Credential store

**Files:** Create `internal/store/credentials.go`, `internal/store/credentials_test.go`. The credential row carries the encrypted secret plus the *injection metadata* and *allowlist* the proxy needs (in this slice the manifest is represented directly on the row; a later plan moves it to manifests).

- [ ] **Step 1: Write the failing test** — `internal/store/credentials_test.go`

```go
package store_test

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

func TestPutGetCredential(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cred := store.Credential{
		Server:        "github",
		Tenant:        "alice",
		EncryptedKey:  []byte{0x01, 0x02, 0x03},
		InjectHeader:  "Authorization",
		InjectFormat:  "Bearer {token}",
		Placeholder:   "PLACEHOLDER_GITHUB",
		AllowedHosts:  []string{"api.github.com"},
	}
	if err := st.PutCredential(ctx, cred); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := st.GetCredential(ctx, "github", "alice")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Server != "github" || got.Tenant != "alice" ||
		got.InjectHeader != "Authorization" || got.InjectFormat != "Bearer {token}" ||
		got.Placeholder != "PLACEHOLDER_GITHUB" {
		t.Fatalf("scalar mismatch: %+v", got)
	}
	if !reflect.DeepEqual(got.EncryptedKey, cred.EncryptedKey) {
		t.Fatalf("key bytes mismatch: %v", got.EncryptedKey)
	}
	if !reflect.DeepEqual(got.AllowedHosts, []string{"api.github.com"}) {
		t.Fatalf("allowlist mismatch: %v", got.AllowedHosts)
	}
}

func TestPutCredentialUpsert(t *testing.T) {
	ctx := context.Background()
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	defer st.Close()
	base := store.Credential{Server: "s", Tenant: "t", EncryptedKey: []byte{1},
		InjectHeader: "Authorization", InjectFormat: "Bearer {token}", Placeholder: "P", AllowedHosts: []string{"a.com"}}
	if err := st.PutCredential(ctx, base); err != nil {
		t.Fatal(err)
	}
	base.EncryptedKey = []byte{2, 2}
	base.AllowedHosts = []string{"b.com", "c.com"}
	if err := st.PutCredential(ctx, base); err != nil {
		t.Fatal(err)
	}
	got, _ := st.GetCredential(ctx, "s", "t")
	if !reflect.DeepEqual(got.EncryptedKey, []byte{2, 2}) || len(got.AllowedHosts) != 2 {
		t.Fatalf("upsert did not replace: %+v", got)
	}
}

func TestGetCredentialMissing(t *testing.T) {
	ctx := context.Background()
	st, _ := store.OpenSQLite(filepath.Join(t.TempDir(), "c.db"))
	defer st.Close()
	if _, err := st.GetCredential(ctx, "nope", "nobody"); err == nil {
		t.Fatal("expected error for missing credential")
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/store/ -run Credential` → undefined `store.Credential`.

- [ ] **Step 3: Implement** — `internal/store/credentials.go`

```go
package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// Credential is a stored, encrypted third-party secret plus the metadata the
// egress proxy needs to inject it and to enforce the per-tenant allowlist.
// EncryptedKey is an opaque vault ciphertext (see internal/vault).
type Credential struct {
	Server       string   // MCP server name (namespace)
	Tenant       string   // user/profile identity
	EncryptedKey []byte   // vault-encrypted real secret
	InjectHeader string   // e.g. "Authorization"
	InjectFormat string   // e.g. "Bearer {token}" — {token} replaced with the real secret
	Placeholder  string   // value the sandbox sends and the proxy looks for
	AllowedHosts []string // egress allowlist for this (server,tenant)
}

const credSchema = `
CREATE TABLE IF NOT EXISTS credentials (
	server        TEXT NOT NULL,
	tenant        TEXT NOT NULL,
	encrypted_key BLOB NOT NULL,
	inject_header TEXT NOT NULL,
	inject_format TEXT NOT NULL,
	placeholder   TEXT NOT NULL,
	allowed_hosts TEXT NOT NULL,
	PRIMARY KEY (server, tenant)
);`

// PutCredential upserts a credential by (server, tenant).
func (s *sqliteStore) PutCredential(ctx context.Context, c Credential) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO credentials (server,tenant,encrypted_key,inject_header,inject_format,placeholder,allowed_hosts)
		 VALUES (?,?,?,?,?,?,?)
		 ON CONFLICT(server,tenant) DO UPDATE SET
		   encrypted_key=excluded.encrypted_key, inject_header=excluded.inject_header,
		   inject_format=excluded.inject_format, placeholder=excluded.placeholder,
		   allowed_hosts=excluded.allowed_hosts`,
		c.Server, c.Tenant, c.EncryptedKey, c.InjectHeader, c.InjectFormat, c.Placeholder,
		strings.Join(c.AllowedHosts, "\n"))
	return err
}

// GetCredential fetches a credential by (server, tenant).
func (s *sqliteStore) GetCredential(ctx context.Context, server, tenant string) (Credential, error) {
	var c Credential
	var hosts string
	err := s.db.QueryRowContext(ctx,
		`SELECT server,tenant,encrypted_key,inject_header,inject_format,placeholder,allowed_hosts
		 FROM credentials WHERE server=? AND tenant=?`, server, tenant).
		Scan(&c.Server, &c.Tenant, &c.EncryptedKey, &c.InjectHeader, &c.InjectFormat, &c.Placeholder, &hosts)
	if errors.Is(err, sql.ErrNoRows) {
		return Credential{}, errors.New("store: credential not found")
	}
	if err != nil {
		return Credential{}, err
	}
	if hosts != "" {
		c.AllowedHosts = strings.Split(hosts, "\n")
	}
	return c, nil
}
```

Also extend the `Store` interface in `internal/store/store.go` with `PutCredential(ctx, Credential) error` and `GetCredential(ctx, server, tenant string) (Credential, error)`, and add `credSchema` to the schema executed in `OpenSQLite` (run both `schema` and `credSchema`).

- [ ] **Step 4: Run, verify pass** — `go test ./internal/store/` → PASS (existing + 3 new).

- [ ] **Step 5: Commit** — `git add internal/store/ && git commit -m "feat: encrypted credential store with injection + allowlist metadata"`

---

### Task 3: Proxy CA + leaf minting

**Files:** Create `internal/proxy/ca.go`, `internal/proxy/ca_test.go`

- [ ] **Step 1: Write the failing test** — `internal/proxy/ca_test.go`

```go
package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/gigmcp/gigmcp/internal/proxy"
)

func TestLeafChainsToCA(t *testing.T) {
	ca, err := proxy.NewCA()
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	leaf, err := ca.LeafFor("api.github.com")
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("CA PEM not appended")
	}
	x509Leaf, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "api.github.com"}); err != nil {
		t.Fatalf("leaf does not verify against CA for SNI: %v", err)
	}
}

func TestLeafCached(t *testing.T) {
	ca, _ := proxy.NewCA()
	a, _ := ca.LeafFor("example.com")
	b, _ := ca.LeafFor("example.com")
	if &a.Certificate[0][0] != &b.Certificate[0][0] {
		t.Fatal("leaf for same host should be cached (same backing array)")
	}
}

func TestCAUsableAsTLSConfig(t *testing.T) {
	ca, _ := proxy.NewCA()
	cfg := &tls.Config{GetCertificate: ca.GetCertificate}
	hello := &tls.ClientHelloInfo{ServerName: "slack.com"}
	cert, err := cfg.GetCertificate(hello)
	if err != nil || cert == nil {
		t.Fatalf("GetCertificate: %v", err)
	}
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/proxy/` → undefined `proxy.NewCA`.

- [ ] **Step 3: Implement** — `internal/proxy/ca.go`

```go
// Package proxy is the embedded MITM egress proxy. ca.go owns a runtime
// ECDSA P-256 certificate authority and mints per-host leaf certificates on
// demand (cached), so the proxy can terminate TLS for any allowed host. The
// CA cert is injected into sandboxes via NODE_EXTRA_CA_CERTS / SSL_CERT_FILE.
package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// CA is a runtime certificate authority that mints cached per-host leaves.
type CA struct {
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caPEM   []byte
	mu      sync.Mutex
	leaves  map[string]*tls.Certificate
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

// NewCA generates a fresh in-memory CA.
func NewCA() (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "gigmcp egress CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		caCert: caCert,
		caKey:  key,
		caPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		leaves: map[string]*tls.Certificate{},
	}, nil
}

// CertPEM returns the CA certificate in PEM form (for injection into sandboxes).
func (c *CA) CertPEM() []byte { return c.caPEM }

// LeafFor returns (and caches) a leaf certificate valid for host.
func (c *CA) LeafFor(host string) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if leaf, ok := c.leaves[host]; ok {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.caCert, &key.PublicKey, c.caKey)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	c.leaves[host] = leaf
	return leaf, nil
}

// GetCertificate adapts LeafFor to tls.Config.GetCertificate (uses SNI).
func (c *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello.ServerName == "" {
		return nil, fmt.Errorf("no SNI")
	}
	return c.LeafFor(hello.ServerName)
}
```

- [ ] **Step 4: Run, verify pass** — `go test ./internal/proxy/` → PASS (3 tests).

- [ ] **Step 5: Commit** — `git add internal/proxy/ && git commit -m "feat: proxy runtime CA with cached per-host leaf minting"`

---

### Task 4: Proxy identity registry + CONNECT MITM core

**Files:** Create `internal/proxy/registry.go`, `internal/proxy/registry_test.go`, `internal/proxy/proxy.go`, `internal/proxy/proxy_test.go`. The proxy resolves the tenant from the connection source IP, checks the allowlist at CONNECT time, MITMs TLS, and rewrites the configured injection header from placeholder → real key (resolved through a `CredentialResolver` the gateway supplies). Unit tests use loopback + a local TLS upstream — **no netns needed** (identity is injected directly in tests).

- [ ] **Step 1: Write the failing registry test** — `internal/proxy/registry_test.go`

```go
package proxy_test

import (
	"testing"

	"github.com/gigmcp/gigmcp/internal/proxy"
)

func TestRegistryLookupByIP(t *testing.T) {
	r := proxy.NewRegistry()
	id := proxy.Identity{Server: "github", Tenant: "alice"}
	r.Bind("10.88.0.2", id)
	got, ok := r.Lookup("10.88.0.2")
	if !ok || got != id {
		t.Fatalf("lookup: %+v ok=%v", got, ok)
	}
	if _, ok := r.Lookup("10.88.0.6"); ok {
		t.Fatal("unknown IP should not resolve")
	}
	r.Unbind("10.88.0.2")
	if _, ok := r.Lookup("10.88.0.2"); ok {
		t.Fatal("unbound IP should not resolve")
	}
}
```

- [ ] **Step 2: Implement registry** — `internal/proxy/registry.go`

```go
package proxy

import "sync"

// Identity is the tenant a sandbox connection belongs to.
type Identity struct {
	Server string
	Tenant string
}

// Registry maps a sandbox's source IP to its Identity. The mapping is
// authoritative (the gateway allocates the IP) and the source IP is
// unforgeable from inside the sandbox (its netns can only source its own /30).
type Registry struct {
	mu sync.RWMutex
	m  map[string]Identity
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{m: map[string]Identity{}} }

// Bind records ip → identity (called at sandbox spawn).
func (r *Registry) Bind(ip string, id Identity) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[ip] = id
}

// Unbind removes a mapping (called at sandbox reap).
func (r *Registry) Unbind(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, ip)
}

// Lookup resolves an IP to its identity.
func (r *Registry) Lookup(ip string) (Identity, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.m[ip]
	return id, ok
}
```

- [ ] **Step 3: Run registry test** — `go test ./internal/proxy/ -run Registry` → PASS.

- [ ] **Step 4: Write the failing proxy test** — `internal/proxy/proxy_test.go`

```go
package proxy_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gigmcp/gigmcp/internal/proxy"
)

// fakeResolver returns a fixed credential for any identity.
type fakeResolver struct {
	cred proxy.Credential
	err  error
}

func (f fakeResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	return f.cred, f.err
}

func startProxy(t *testing.T, reg *proxy.Registry, res proxy.CredentialResolver) *proxy.Proxy {
	t.Helper()
	p, err := proxy.New(reg, res)
	if err != nil {
		t.Fatalf("new proxy: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go p.Serve(ln)
	t.Cleanup(func() { ln.Close() })
	p.SetAddr(ln.Addr().String())
	return p
}

// clientThroughProxy builds an http.Client that uses the proxy and trusts its CA.
func clientThroughProxy(t *testing.T, p *proxy.Proxy) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(p.CACertPEM())
	pu, _ := url.Parse("http://" + p.Addr())
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(pu),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}
}

func TestProxyInjectsCredentialForAllowedHost(t *testing.T) {
	// Upstream records the Authorization header it actually received.
	var gotAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	upHost := upstream.Listener.Addr().String() // host:port

	reg := proxy.NewRegistry()
	reg.Bind("127.0.0.1", proxy.Identity{Server: "github", Tenant: "alice"})

	res := fakeResolver{cred: proxy.Credential{
		RealSecret:   "REALKEY",
		InjectHeader: "Authorization",
		InjectFormat: "Bearer {token}",
		Placeholder:  "PLACEHOLDER",
		AllowedHosts: []string{hostOnly(upHost)},
	}}
	p := startProxy(t, reg, res)
	// Proxy must trust the upstream's self-signed cert for this test.
	p.SetUpstreamRoots(upstreamPool(t, upstream))

	client := clientThroughProxy(t, p)
	req, _ := http.NewRequest("GET", "https://"+upHost+"/", nil)
	req.Header.Set("Authorization", "Bearer PLACEHOLDER")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if gotAuth != "Bearer REALKEY" {
		t.Fatalf("upstream saw %q, want %q", gotAuth, "Bearer REALKEY")
	}
}

func TestProxyBlocksDisallowedHost(t *testing.T) {
	reg := proxy.NewRegistry()
	reg.Bind("127.0.0.1", proxy.Identity{Server: "github", Tenant: "alice"})
	res := fakeResolver{cred: proxy.Credential{AllowedHosts: []string{"only.allowed.example"}}}
	p := startProxy(t, reg, res)
	client := clientThroughProxy(t, p)
	_, err := client.Get("https://evil.example.com/")
	if err == nil {
		t.Fatal("request to disallowed host must fail at CONNECT")
	}
}

func TestProxyRejectsUnknownSource(t *testing.T) {
	reg := proxy.NewRegistry() // no bindings
	res := fakeResolver{}
	p := startProxy(t, reg, res)
	client := clientThroughProxy(t, p)
	_, err := client.Get("https://anything.example.com/")
	if err == nil {
		t.Fatal("unknown source IP must be rejected")
	}
}
```

Add test helpers in the same file: `hostOnly(hostport string) string` (strip port via `net.SplitHostPort`), `upstreamPool(t, *httptest.Server) *x509.CertPool` (returns `x509.NewCertPool()` with `srv.Certificate()` added), and wire `p.SetUpstreamRoots`.

- [ ] **Step 5: Run, verify fail** — `go test ./internal/proxy/ -run Proxy` → undefined symbols.

- [ ] **Step 6: Implement** — `internal/proxy/proxy.go`

```go
package proxy

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

// Credential is what the resolver returns for a (identity, host): the real
// secret to inject plus how to inject it and which hosts are allowed.
type Credential struct {
	RealSecret   string
	InjectHeader string
	InjectFormat string // contains "{token}"
	Placeholder  string
	AllowedHosts []string
}

// CredentialResolver resolves a tenant identity + target host to a Credential.
// The gateway implements this against the vault + credential store.
type CredentialResolver interface {
	Resolve(id Identity, host string) (Credential, error)
}

// Proxy is the embedded MITM egress proxy.
type Proxy struct {
	reg          *Registry
	res          CredentialResolver
	ca           *CA
	addr         string
	upstreamRoots *x509.CertPool // nil = system roots
}

// New builds a Proxy with a fresh CA.
func New(reg *Registry, res CredentialResolver) (*Proxy, error) {
	ca, err := NewCA()
	if err != nil {
		return nil, err
	}
	return &Proxy{reg: reg, res: res, ca: ca}, nil
}

func (p *Proxy) CACertPEM() []byte             { return p.ca.CertPEM() }
func (p *Proxy) SetAddr(a string)              { p.addr = a }
func (p *Proxy) Addr() string                  { return p.addr }
func (p *Proxy) SetUpstreamRoots(c *x509.CertPool) { p.upstreamRoots = c }

// Serve accepts connections; only CONNECT is supported.
func (p *Proxy) Serve(ln net.Listener) error {
	srv := &http.Server{Handler: http.HandlerFunc(p.handle)}
	return srv.Serve(ln)
}

func hostname(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT supported", http.StatusMethodNotAllowed)
		return
	}
	srcIP := hostname(r.RemoteAddr)
	id, ok := p.reg.Lookup(srcIP)
	if !ok {
		http.Error(w, "unknown source", http.StatusForbidden)
		return
	}
	targetHost := hostname(r.Host)
	cred, err := p.res.Resolve(id, targetHost)
	if err != nil {
		http.Error(w, "no credential", http.StatusForbidden)
		return
	}
	if !allowed(targetHost, cred.AllowedHosts) {
		log.Printf("DENY src=%s tenant=%s/%s host=%s reason=not-in-allowlist", srcIP, id.Server, id.Tenant, targetHost)
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	leaf, err := p.ca.LeafFor(targetHost)
	if err != nil {
		return
	}
	tlsClient := tls.Server(clientConn, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	if err := tlsClient.Handshake(); err != nil {
		return
	}
	defer tlsClient.Close()

	if err := p.pump(tlsClient, r.Host, id, cred, srcIP); err != nil && err != io.EOF {
		log.Printf("proxy pump %s: %v", targetHost, err)
	}
}

// pump reads HTTP requests off the MITM'd client conn, injects the credential,
// forwards to the real upstream, and streams responses back. Handles keep-alive.
func (p *Proxy) pump(client *tls.Conn, hostport string, id Identity, cred Credential, srcIP string) error {
	upstream, err := tls.Dial("tcp", hostport, &tls.Config{
		ServerName: hostname(hostport),
		RootCAs:    p.upstreamRoots,
	})
	if err != nil {
		return err
	}
	defer upstream.Close()
	cr := bufio.NewReader(client)
	ur := bufio.NewReader(upstream)
	for {
		req, err := http.ReadRequest(cr)
		if err != nil {
			return err
		}
		// Tier-1 injection: replace the placeholder header value with the real secret.
		if cred.InjectHeader != "" && req.Header.Get(cred.InjectHeader) == cred.Placeholder {
			req.Header.Set(cred.InjectHeader, strings.ReplaceAll(cred.InjectFormat, "{token}", cred.RealSecret))
		}
		req.URL.Scheme = "https"
		req.URL.Host = hostport
		log.Printf("ALLOW src=%s tenant=%s/%s host=%s method=%s", srcIP, id.Server, id.Tenant, hostname(hostport), req.Method)
		if err := req.Write(upstream); err != nil {
			return err
		}
		resp, err := http.ReadResponse(ur, req)
		if err != nil {
			return err
		}
		if err := resp.Write(client); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()
		if req.Close || resp.Close {
			return nil
		}
	}
}

func allowed(host string, list []string) bool {
	for _, h := range list {
		if strings.EqualFold(host, h) {
			return true
		}
		if strings.HasPrefix(h, "*.") && strings.HasSuffix(strings.ToLower(host), strings.ToLower(h[1:])) {
			return true
		}
	}
	return false
}
```

(In the proxy test, `hostOnly` == call `hostname`; expose it or duplicate in test. `proxy.Credential` is used by the fakeResolver — it's defined here.)

- [ ] **Step 7: Run, verify pass** — `go test ./internal/proxy/` → PASS (CA + registry + 3 proxy tests). `go mod tidy` (no new deps expected). The injection-swap test is the crown-jewel unit proof: upstream saw `Bearer REALKEY` while the client only ever sent `Bearer PLACEHOLDER`.

- [ ] **Step 8: Commit** — `git add internal/proxy/ && git commit -m "feat: CONNECT MITM proxy — source-IP identity, allowlist, Tier-1 credential injection"`

---

### Task 5: netmgr — /30 allocator + veth + inject-by-PID (host side)

**Files:** Create `internal/netmgr/netmgr.go`, `internal/netmgr/netmgr_test.go` (Linux-only; gated on `sandbox.Available()` and NET_ADMIN). Uses `vishvananda/netlink`.

- [ ] **Step 1: Write the failing test** — `internal/netmgr/netmgr_test.go`

```go
package netmgr_test

import (
	"net"
	"testing"

	"github.com/gigmcp/gigmcp/internal/netmgr"
	"github.com/gigmcp/gigmcp/internal/sandbox"
)

func requireNet(t *testing.T) {
	t.Helper()
	if !sandbox.Available() {
		t.Skip("netmgr requires Linux + NET_ADMIN — run `make test`")
	}
}

func TestAllocatorHandsOutDistinctSubnets(t *testing.T) {
	a := netmgr.NewAllocator("10.88.0.0/16")
	s1, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if s1.HostIP.Equal(s2.HostIP) || s1.SandboxIP.Equal(s2.SandboxIP) {
		t.Fatalf("subnets overlap: %v %v", s1, s2)
	}
	// host and sandbox in same /30, distinct addresses
	if !s1.HostIP.Equal(net.ParseIP("10.88.0.1")) || !s1.SandboxIP.Equal(net.ParseIP("10.88.0.2")) {
		t.Fatalf("unexpected first /30: host=%v sb=%v", s1.HostIP, s1.SandboxIP)
	}
	a.Free(s1)
	s3, _ := a.Allocate()
	if !s3.HostIP.Equal(net.ParseIP("10.88.0.1")) {
		t.Fatalf("freed subnet not reused: %v", s3.HostIP)
	}
}

func TestCreateVethAndInject(t *testing.T) {
	requireNet(t)
	a := netmgr.NewAllocator("10.88.0.0/16")
	sub, _ := a.Allocate()
	// A long-lived child process in its OWN net namespace stands in for bwrap's child.
	child, cleanup, err := netmgr.SpawnNetnsChildForTest(t)
	if err != nil {
		t.Fatalf("spawn child: %v", err)
	}
	defer cleanup()

	link, err := netmgr.CreateVethToHost(sub)
	if err != nil {
		t.Fatalf("create veth: %v", err)
	}
	if err := netmgr.InjectPeer(link, child.Pid); err != nil {
		t.Fatalf("inject peer into pid %d: %v", child.Pid, err)
	}
	// Host side is up with the host IP; peer is now in the child netns.
	if err := netmgr.VerifyHostSide(sub); err != nil {
		t.Fatalf("host side not configured: %v", err)
	}
	netmgr.DeleteVeth(link) // cleanup
}
```

- [ ] **Step 2: Run, verify fail** — `go test ./internal/netmgr/` → undefined symbols.

- [ ] **Step 3: Implement** — `internal/netmgr/netmgr.go`

```go
// Package netmgr provisions per-sandbox networking on the HOST side of the
// boundary, using netlink (no `ip` CLI) with CAP_NET_ADMIN only. Per sandbox:
// allocate a /30, create a veth pair, bring the host end up with the host IP,
// and move the peer end into the bwrap child's network namespace by PID
// (LinkSetNsPid — avoids the named-netns bind-mount that needs CAP_SYS_ADMIN).
package netmgr

import (
	"fmt"
	"net"
	"os/exec"
	"sync"

	"github.com/vishvananda/netlink"
)

// Subnet is one /30 allocation: .1 host (proxy) side, .2 sandbox side.
type Subnet struct {
	Index     int
	HostIP    net.IP
	SandboxIP net.IP
	Mask      net.IPMask
	HostVeth  string // unique iface name, host side
	PeerVeth  string // unique iface name, sandbox side
}

// Allocator hands out non-overlapping /30s from a base network.
type Allocator struct {
	mu   sync.Mutex
	base net.IP
	used map[int]bool
	next int
}

// NewAllocator parses base (e.g. "10.88.0.0/16") and returns an allocator.
func NewAllocator(base string) *Allocator {
	ip, _, _ := net.ParseCIDR(base)
	return &Allocator{base: ip.To4(), used: map[int]bool{}}
}

// Allocate returns the next free /30. Index k → host=base+4k+1, sandbox=base+4k+2.
func (a *Allocator) Allocate() (Subnet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := 0
	for a.used[k] {
		k++
	}
	a.used[k] = true
	host := offset(a.base, 4*k+1)
	sb := offset(a.base, 4*k+2)
	return Subnet{
		Index: k, HostIP: host, SandboxIP: sb, Mask: net.CIDRMask(30, 32),
		HostVeth: fmt.Sprintf("vh%d", k), PeerVeth: fmt.Sprintf("vs%d", k),
	}, nil
}

// Free returns a subnet to the pool.
func (a *Allocator) Free(s Subnet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, s.Index)
}

func offset(base net.IP, n int) net.IP {
	v := make(net.IP, 4)
	copy(v, base.To4())
	u := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	u += uint32(n)
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u)).To4()
}

// CreateVethToHost creates the veth pair and configures the host side (addr+up).
func CreateVethToHost(s Subnet) (*netlink.Veth, error) {
	la := netlink.NewLinkAttrs()
	la.Name = s.HostVeth
	veth := &netlink.Veth{LinkAttrs: la, PeerName: s.PeerVeth}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("link add: %w", err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: s.HostIP, Mask: s.Mask}}
	if err := netlink.AddrAdd(veth, addr); err != nil {
		netlink.LinkDel(veth)
		return nil, fmt.Errorf("addr add host: %w", err)
	}
	if err := netlink.LinkSetUp(veth); err != nil {
		netlink.LinkDel(veth)
		return nil, fmt.Errorf("link up host: %w", err)
	}
	return veth, nil
}

// InjectPeer moves the peer end into the netns of the given (host) PID.
func InjectPeer(veth *netlink.Veth, pid int) error {
	peer, err := netlink.LinkByName(veth.PeerName)
	if err != nil {
		return fmt.Errorf("find peer: %w", err)
	}
	if err := netlink.LinkSetNsPid(peer, pid); err != nil {
		return fmt.Errorf("move peer to netns pid %d: %w", pid, err)
	}
	return nil
}

// VerifyHostSide confirms the host veth carries the host IP.
func VerifyHostSide(s Subnet) error {
	link, err := netlink.LinkByName(s.HostVeth)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.IP.Equal(s.HostIP) {
			return nil
		}
	}
	return fmt.Errorf("host veth %s missing %s", s.HostVeth, s.HostIP)
}

// DeleteVeth removes the host veth (also removes the peer).
func DeleteVeth(veth *netlink.Veth) {
	if l, err := netlink.LinkByName(veth.LinkAttrs.Name); err == nil {
		netlink.LinkDel(l)
	}
}

// netnsChild is a stand-in for bwrap's child during tests.
type netnsChild struct {
	Pid int
}

// SpawnNetnsChildForTest starts `unshare -n sleep` so a real netns exists to
// inject into. Test-only helper; uses unshare which needs the same caps tests run with.
func SpawnNetnsChildForTest(t interface{ Fatalf(string, ...any) }) (*netnsChild, func(), error) {
	cmd := exec.Command("sleep", "300")
	cmd.SysProcAttr = newNetnsSysProcAttr()
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return &netnsChild{Pid: cmd.Process.Pid}, func() { cmd.Process.Kill(); cmd.Wait() }, nil
}
```

Add `internal/netmgr/sysprocattr_linux.go` with `//go:build linux`:

```go
package netmgr

import "syscall"

func newNetnsSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWUSER}
}
```

And `internal/netmgr/sysprocattr_other.go` with `//go:build !linux` returning `nil` (so the package compiles on macOS for the host-only allocator test).

- [ ] **Step 4: Run** — `go get github.com/vishvananda/netlink && go mod tidy`; `make test` → netmgr tests pass on Linux (allocator runs everywhere; veth test runs on Linux). `make test-local` → veth test skips on macOS, allocator passes. If `CLONE_NEWUSER|CLONE_NEWNET` in the test helper fails under the container caps, fall back to `exec.Command("unshare","-n","-r","sleep","300")` and parse the pid — REPORT if so.

- [ ] **Step 5: Commit** — `git add internal/netmgr/ go.mod go.sum && git commit -m "feat: netmgr — /30 allocator, veth creation, inject-by-PID (NET_ADMIN only)"`

---

### Task 6: Bootstrap binary (in-sandbox trusted init)

**Files:** Create `cmd/bootstrap/main.go` (+ `cmd/bootstrap/main_linux.go` if build tags are needed for unix calls). This runs as the bwrap entrypoint. It: reads fd 3 (inject-done) until the gateway has moved the veth in; configures lo + the peer veth + default route via netlink (it is inside its own netns and holds NET_ADMIN in its userns); writes fd 4 (net-ready); drops all caps; `execve`s the real server (argv after `--`). Inherited fds: bwrap passes fd 3 and 4 through; the gateway sets up the pipes.

- [ ] **Step 1: Write the implementation** — `cmd/bootstrap/main.go`

```go
//go:build linux

// Command bootstrap is the trusted in-sandbox init. It runs as the bwrap
// entrypoint, completes per-sandbox network setup that requires being inside
// the netns, drops ALL capabilities, and execs the untrusted server. The real
// server never runs with any capability and never sees the credential.
//
// Protocol (fds inherited from the gateway via bwrap):
//   fd 3 (inject-done): gateway closes/writes 1 byte after moving the veth in.
//   fd 4 (net-ready):   bootstrap writes 1 byte after configuring the network.
// Args: bootstrap <sandboxCIDR> <proxyIP> <peerVeth> -- <server> [args...]
package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap:", err)
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]
	sep := indexOf(args, "--")
	if sep < 4 {
		return fmt.Errorf("usage: bootstrap <cidr> <proxyIP> <peerVeth> -- <server> [args...]")
	}
	cidr, proxyIP, peerVeth := args[0], args[1], args[2]
	serverArgv := args[sep+1:]

	// 1. Wait for the gateway to inject the veth (read 1 byte from fd 3).
	injectDone := os.NewFile(3, "inject-done")
	if injectDone == nil {
		return fmt.Errorf("fd 3 (inject-done) not inherited")
	}
	buf := make([]byte, 1)
	if _, err := injectDone.Read(buf); err != nil {
		return fmt.Errorf("await veth injection: %w", err)
	}

	// 2. Configure the network from inside our netns.
	if err := configureNet(cidr, proxyIP, peerVeth); err != nil {
		return err
	}

	// 3. Signal readiness to the gateway (write 1 byte to fd 4).
	if ready := os.NewFile(4, "net-ready"); ready != nil {
		ready.Write([]byte{1})
		ready.Close()
	}

	// 4. Drop all capabilities, then exec the untrusted server.
	if err := dropAllCaps(); err != nil {
		return fmt.Errorf("drop caps: %w", err)
	}
	path, err := lookPath(serverArgv[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, serverArgv, os.Environ())
}

func configureNet(cidr, proxyIP, peerVeth string) error {
	// Wait for the injected peer to appear (bounded).
	var link netlink.Link
	var err error
	for i := 0; i < 100; i++ {
		if link, err = netlink.LinkByName(peerVeth); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if link == nil {
		return fmt.Errorf("peer veth %s never appeared: %w", peerVeth, err)
	}
	if lo, e := netlink.LinkByName("lo"); e == nil {
		netlink.LinkSetUp(lo)
	}
	addr, err := netlink.ParseAddr(cidr) // e.g. "10.88.0.2/30"
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("addr add: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	gw := net.ParseIP(proxyIP)
	if err := netlink.RouteAdd(&netlink.Route{Gw: gw}); err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	return nil
}

func dropAllCaps() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	for i := 0; i <= 40; i++ {
		// Ignore EINVAL for caps above the kernel max.
		unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(i), 0, 0, 0)
	}
	unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data unix.CapUserData // all zero
	return unix.Capset(&hdr, &data)
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func lookPath(p string) (string, error) {
	if len(p) > 0 && (p[0] == '/' || p[0] == '.') {
		return p, nil
	}
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/local/bin"} {
		full := dir + "/" + p
		if _, err := os.Stat(full); err == nil {
			return full, nil
		}
	}
	return "", fmt.Errorf("not found in PATH: %s", p)
}
```

- [ ] **Step 2: Build check** — `GOOS=linux go build ./cmd/bootstrap/` must succeed; `go vet ./cmd/bootstrap/` clean. (No unit test here — it's exercised by the Task 10 integration test, which asserts CapEff=0 and connectivity. This matches the skeleton's treatment of `cmd/` entrypoints.)

- [ ] **Step 3: Commit** — `git add cmd/bootstrap/ && git commit -m "feat: in-sandbox bootstrap — netns config, cap-drop, exec untrusted server"`

---

### Task 7: sandbox egress mode

**Files:** Modify `internal/sandbox/sandbox.go`, extend `internal/sandbox/sandbox_test.go`. Add an egress mode: when enabled, `Command` decomposes the unshare flags (keeping `--unshare-net` so bwrap creates the netns), runs `cmd/bootstrap` as the entrypoint (with the server argv after `--`), passes `--info-fd`, `--uid 65534 --gid 65534`, and wires the two handshake pipes as inheritable fds 3/4.

- [ ] **Step 1: Write the failing argv test** — add to `internal/sandbox/sandbox_test.go`

```go
func TestEgressCommandArgv(t *testing.T) {
	spec := sandbox.Spec{
		Exec:   "/app/server",
		Mounts: []sandbox.Mount{{Src: "/h/server", Dst: "/app/server"}},
		Egress: &sandbox.Egress{
			BootstrapPath: "/usr/local/bin/bootstrap",
			SandboxCIDR:   "10.88.0.2/30",
			ProxyIP:       "10.88.0.1",
			PeerVeth:      "vs0",
			InfoFD:        5,
		},
	}
	cmd := sandbox.Command(spec)
	args := cmd.Args

	// Egress mode must NOT use --unshare-all (it sequences net wrong) ...
	if indexOf(args, "--unshare-all") != -1 {
		t.Error("egress mode must not pass --unshare-all")
	}
	// ... but MUST keep --unshare-net (bwrap creates the netns) and the others.
	for _, f := range []string{"--unshare-net", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup"} {
		if indexOf(args, f) == -1 {
			t.Errorf("egress mode missing %s", f)
		}
	}
	// Runs the bootstrap, with the real server after a literal --.
	idxBoot := indexOf(args, "/usr/local/bin/bootstrap")
	idxSep := lastIndexOf(args, "--")
	idxServer := indexOf(args, "/app/server")
	if idxBoot == -1 || idxServer == -1 || !(idxBoot < idxSep && idxSep < idxServer) {
		t.Fatalf("expected bootstrap ... -- /app/server; args=%v", args)
	}
	// uid/gid 65534 and info-fd present.
	if !hasPair(args, "--uid", "65534") || !hasPair(args, "--gid", "65534") {
		t.Error("egress mode must drop to uid/gid 65534")
	}
	if !hasPair(args, "--info-fd", "5") {
		t.Error("egress mode must pass --info-fd")
	}
}
```

Add small helpers `lastIndexOf` and `hasPair(args, flag, val)` to the test file (or reuse the existing `indexOf` from the skeleton test).

- [ ] **Step 2: Run, verify fail** — `go test ./internal/sandbox/ -run Egress` → `Spec` has no `Egress` field.

- [ ] **Step 3: Implement** — modify `internal/sandbox/sandbox.go`

Add the `Egress` type and field, and branch in `Command`:

```go
// Egress configures network egress for a sandbox. When set, bwrap creates a
// network namespace (the gateway then injects a veth into the bwrap child by
// PID), the cmd/bootstrap entrypoint configures the link + default route via
// the proxy and drops all caps before exec'ing Exec. See DESIGN.md decision #13.
type Egress struct {
	BootstrapPath string // host path to the bootstrap binary (mounted into the sandbox)
	SandboxCIDR   string // e.g. "10.88.0.2/30"
	ProxyIP       string // default route / proxy host-side IP
	PeerVeth      string // injected interface name inside the netns
	InfoFD        int    // bwrap --info-fd target (gateway reads child PID from it)
}
```

Add `Egress *Egress` to `Spec`. In `Command`, when `spec.Egress == nil` keep today's behavior (`--unshare-all`, etc.). When set, build:

```go
func Command(spec Spec) *exec.Cmd {
	if spec.Egress == nil {
		return commandNoNet(spec) // existing implementation, renamed
	}
	return commandEgress(spec)
}

func commandEgress(spec Spec) *exec.Cmd {
	e := spec.Egress
	args := []string{
		"--die-with-parent",
		"--new-session",
		// Decomposed: KEEP --unshare-net (bwrap creates the netns); drop --unshare-all.
		"--unshare-user", "--unshare-net", "--unshare-pid",
		"--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
		"--uid", "65534", "--gid", "65534",
		"--info-fd", strconv.Itoa(e.InfoFD),
		"--clearenv",
		"--setenv", "PATH", "/usr/bin:/bin",
	}
	// caller mounts first so fixed isolation mounts win on collision
	for _, m := range spec.Mounts {
		flag := "--ro-bind"
		if m.Optional {
			flag = "--ro-bind-try"
		}
		args = append(args, flag, m.Src, m.Dst)
	}
	// the bootstrap binary itself must be mounted in
	args = append(args, "--ro-bind", e.BootstrapPath, e.BootstrapPath)
	args = append(args,
		"--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--chdir", "/",
		// bootstrap is the entrypoint; the real server follows after --
		e.BootstrapPath, e.SandboxCIDR, e.ProxyIP, e.PeerVeth, "--", spec.Exec,
	)
	args = append(args, spec.Args...)
	return exec.Command("bwrap", args...)
}
```

(Refactor the existing body of `Command` into `commandNoNet`. Add `import "strconv"`. The gateway is responsible for attaching the inheritable pipe fds 3/4 to `cmd.ExtraFiles` and the `--info-fd` pipe — documented in Task 9; `Command` only builds argv.)

- [ ] **Step 4: Run, verify pass** — `go test ./internal/sandbox/` → existing tests still pass; `TestEgressCommandArgv` passes (runs on macOS — argv only). `make test` confirms the no-net isolation tests are unaffected.

- [ ] **Step 5: Commit** — `git add internal/sandbox/ && git commit -m "feat: sandbox egress mode — bootstrap entrypoint, decomposed unshare, uid 65534"`

---

### Task 8: Test fetch MCP server

**Files:** Create `cmd/fetch-mcp/main.go`. A tiny MCP server (built like echo) with one tool `fetch` that does an HTTPS GET to a URL given in its args, sending `Authorization: Bearer <PLACEHOLDER from env>` , and returns the upstream response body as text. Used by the integration test to prove the proxy swapped the header. It trusts the CA from `SSL_CERT_FILE`/`NODE_EXTRA_CA_CERTS` and uses `HTTPS_PROXY` from env (Go honors these automatically via `http.DefaultTransport`'s `ProxyFromEnvironment` and system cert pool — but since we run static with no system certs, load the CA explicitly).

- [ ] **Step 1: Implement** — `cmd/fetch-mcp/main.go`

```go
// Command fetch-mcp is a test MCP server with a single `fetch` tool that does
// an HTTPS GET with a placeholder Authorization header. Run sandboxed behind
// the egress proxy, the placeholder is swapped for the real key; the tool
// returns the upstream's response body so a test can assert what the upstream
// actually received. PLACEHOLDER comes from $GIG_PLACEHOLDER.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fetchArgs struct {
	URL string `json:"url" jsonschema:"the https URL to GET"`
}

func newClient() *http.Client {
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile := os.Getenv("SSL_CERT_FILE"); caFile != "" {
		if pem, err := os.ReadFile(caFile); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment, // honors HTTPS_PROXY
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	return &http.Client{Transport: tr}
}

func main() {
	placeholder := os.Getenv("GIG_PLACEHOLDER")
	client := newClient()
	s := mcp.NewServer(&mcp.Implementation{Name: "fetch-mcp", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "fetch", Description: "HTTPS GET a URL"},
		func(ctx context.Context, req *mcp.CallToolRequest, in fetchArgs) (*mcp.CallToolResult, any, error) {
			r, err := http.NewRequestWithContext(ctx, "GET", in.URL, nil)
			if err != nil {
				return nil, nil, err
			}
			r.Header.Set("Authorization", "Bearer "+placeholder)
			resp, err := client.Do(r)
			if err != nil {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: " + err.Error()}}}, nil, nil
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%d %s", resp.StatusCode, string(body))}}}, nil, nil
		})
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
```

- [ ] **Step 2: Build check** — `go build ./cmd/fetch-mcp/ && go vet ./cmd/fetch-mcp/` clean.

- [ ] **Step 3: Commit** — `git add cmd/fetch-mcp/ && git commit -m "test: fetch-mcp server (proves proxy credential swap)"`

---

### Task 9: Gateway spawn rework

**Files:** Modify `cmd/gateway/main.go` (and add `internal/gateway/resolver.go` implementing `proxy.CredentialResolver` over the store+vault). Wire: start the proxy on a host-side address; for each backend, allocate a /30, create the veth, launch bwrap in egress mode with `--info-fd` + the two handshake pipes, read the child PID from the info-fd, inject the peer, signal inject-done, await net-ready, register `sandboxIP → Identity` in the proxy registry, and set `HTTPS_PROXY` + `SSL_CERT_FILE` (+`NODE_EXTRA_CA_CERTS`) inside the sandbox via mounts/env. Because this is intricate orchestration with no pure-unit seam, its correctness is proven by the Task 10 integration test; keep this task's verification at build+vet+the integration test.

- [ ] **Step 1: Implement the resolver** — `internal/gateway/resolver.go`

```go
package gateway

import (
	"context"

	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// CredResolver implements proxy.CredentialResolver over the store + vault.
type CredResolver struct {
	Store store.Store
	Vault *vault.Vault
}

// Resolve fetches and decrypts the credential for the identity.
func (c *CredResolver) Resolve(id proxy.Identity, host string) (proxy.Credential, error) {
	cred, err := c.Store.GetCredential(context.Background(), id.Server, id.Tenant)
	if err != nil {
		return proxy.Credential{}, err
	}
	secret, err := c.Vault.Decrypt(cred.EncryptedKey)
	if err != nil {
		return proxy.Credential{}, err
	}
	return proxy.Credential{
		RealSecret:   string(secret),
		InjectHeader: cred.InjectHeader,
		InjectFormat: cred.InjectFormat,
		Placeholder:  cred.Placeholder,
		AllowedHosts: cred.AllowedHosts,
	}, nil
}
```

- [ ] **Step 2: Implement the spawn orchestration** — add to `cmd/gateway/main.go` a `spawnEgressBackend` helper and call it from the backend loop. Full helper:

```go
// spawnEgressBackend launches one MCP server in an egress-isolated sandbox and
// returns a connected MCP client session. Pipes: r3/w3 = inject-done (gateway
// writes after veth injection), r4/w4 = net-ready (bootstrap writes when up),
// rInfo/wInfo = bwrap --info-fd (gateway reads child PID).
// proxyPort is the port the embedded proxy listens on (bound 0.0.0.0 so it is
// reachable on every per-sandbox host-veth IP). Each sandbox routes via its OWN
// /30 gateway (sub.HostIP), NOT a single global proxy IP.
func spawnEgressBackend(ctx context.Context, srv store.Server, alloc *netmgr.Allocator,
	reg *proxy.Registry, proxyPort int, caFile, bootstrapPath string) (*mcp.ClientSession, func(), error) {

	sub, err := alloc.Allocate()
	if err != nil {
		return nil, nil, err
	}
	proxyIP := sub.HostIP.String() // this sandbox's default route = its own /30 gateway

	// handshake + info pipes
	r3, w3, _ := os.Pipe() // inject-done: gateway -> bootstrap
	r4, w4, _ := os.Pipe() // net-ready:  bootstrap -> gateway
	rInfo, wInfo, _ := os.Pipe()

	spec := sandbox.Spec{
		Exec: "/app/server",
		Mounts: []sandbox.Mount{
			{Src: srv.Binary, Dst: "/app/server"},
			{Src: caFile, Dst: "/etc/gigmcp-ca.pem"},
		},
		Egress: &sandbox.Egress{
			BootstrapPath: bootstrapPath,
			SandboxCIDR:   fmt.Sprintf("%s/30", sub.SandboxIP),
			ProxyIP:       proxyIP,
			PeerVeth:      sub.PeerVeth,
			InfoFD:        5,
		},
	}
	cmd := sandbox.Command(spec)
	// bwrap inherits: fd3=inject-done(r), fd4=net-ready(w), fd5=info(w).
	cmd.ExtraFiles = []*os.File{r3, w4, wInfo}
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HTTPS_PROXY=http://%s:%d", proxyIP, proxyPort),
		"SSL_CERT_FILE=/etc/gigmcp-ca.pem",
		"NODE_EXTRA_CA_CERTS=/etc/gigmcp-ca.pem",
		"GIG_PLACEHOLDER=PLACEHOLDER", // matches the stored credential's Placeholder
	)
	// MCP stdio is fd 0/1; create the transport over the command.
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("start bwrap: %w", err)
	}
	// close our copies of the child ends
	r3.Close()
	w4.Close()
	wInfo.Close()

	// 1. read child PID from bwrap --info-fd JSON
	childPid, err := readChildPid(rInfo)
	if err != nil {
		return nil, nil, err
	}
	// 2. create veth, inject peer into child netns
	veth, err := netmgr.CreateVethToHost(sub)
	if err != nil {
		return nil, nil, err
	}
	if err := netmgr.InjectPeer(veth, childPid); err != nil {
		return nil, nil, err
	}
	// 3. signal inject-done, await net-ready
	w3.Write([]byte{1})
	w3.Close()
	ack := make([]byte, 1)
	if _, err := r4.Read(ack); err != nil {
		return nil, nil, fmt.Errorf("await net-ready: %w", err)
	}
	// 4. register identity by sandbox source IP
	reg.Bind(sub.SandboxIP.String(), proxy.Identity{Server: srv.Name, Tenant: "default"})

	// NOTE: because cmd already started, wrap its stdio in the MCP transport.
	// Use CommandTransport with a pre-started cmd is not supported; instead the
	// real implementation must let CommandTransport own Start. See Step 3.
	_ = cmd
	cleanup := func() { netmgr.DeleteVeth(veth); alloc.Free(sub); reg.Unbind(sub.SandboxIP.String()) }
	return nil, cleanup, errors.New("see Step 3: integrate with CommandTransport lifecycle")
}
```

- [ ] **Step 3: Transport lifecycle — use `mcp.IOTransport` (RESOLVED, verified v1.6.1).** Do NOT use `CommandTransport` (it owns `cmd.Start()` and would begin the MCP handshake before the network is up). The SDK provides `mcp.IOTransport{Reader io.ReadCloser, Writer io.WriteCloser}` — use it. The flow is naturally ordered and needs no concurrency tricks because the bootstrap blocks the real MCP server from starting until the handshake completes:
  1. Build the bwrap `cmd` from `sandbox.Command(spec)`.
  2. `stdout, _ := cmd.StdoutPipe()` and `stdin, _ := cmd.StdinPipe()` (these are the MCP channel; the server speaks newline-JSON on its stdio once it execs).
  3. `cmd.ExtraFiles = []*os.File{r3, w4, wInfo}` (→ child fd 3,4,5), `cmd.Env = ...` (HTTPS_PROXY, SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, GIG_PLACEHOLDER).
  4. `cmd.Start()`. At this point only the bootstrap runs; it is blocked reading fd 3, so nothing is written to stdout yet.
  5. Network handshake (synchronous, in the spawning goroutine): `readChildPid(rInfo)` → `CreateVethToHost` → `InjectPeer(veth, childPid)` → `w3.Write([]byte{1})` (inject-done) → `r4.Read` (await net-ready). The bootstrap then drops caps and execs the real MCP server.
  6. `client.Connect(ctx, &mcp.IOTransport{Reader: stdout, Writer: stdin}, nil)` — the initialize handshake now succeeds because the real server is finally speaking stdio.
  7. `reg.Bind(sub.SandboxIP.String(), identity)`.
  Return the `*mcp.ClientSession` and a cleanup closure (`DeleteVeth`, `alloc.Free`, `reg.Unbind`, `cmd.Process.Kill`). Note: the Step-2 helper sketch returned an error placeholder for exactly this seam — replace that with the IOTransport connect above.

- [ ] **Step 4: readChildPid + main wiring** — implement:

```go
func readChildPid(r *os.File) (int, error) {
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	var info struct{ ChildPid int `json:"child-pid"` }
	if err := json.Unmarshal(data, &info); err != nil {
		return 0, fmt.Errorf("parse info-fd: %w (raw=%s)", err, data)
	}
	if info.ChildPid == 0 {
		return 0, fmt.Errorf("info-fd had no child-pid: %s", data)
	}
	return info.ChildPid, nil
}
```

In `run()`: build the vault from `GIG_MASTER_KEY` (hex/base64 → 32 bytes), open the store, construct `CredResolver`, `proxy.NewRegistry()`, `proxy.New(reg, resolver)`; write the proxy CA PEM to a temp file (`caFile`) for mounting; start the proxy listening on `proxyIP:8080` (host-side veth IPs are reachable because the proxy binds `0.0.0.0:8080` or each host IP). Replace the skeleton's `sandbox.Command(... no egress ...)` backend loop with `spawnEgressBackend`. Seed a demo credential at startup if `GIG_DEMO_TOKEN` is set (encrypt it, `PutCredential`) so the stack is usable like the skeleton.

- [ ] **Step 5: Build + vet** — `go build ./... && go vet ./...` clean. `go mod tidy`. (Behavioral proof is Task 10.)

- [ ] **Step 6: Commit** — `git add cmd/gateway/ internal/gateway/resolver.go go.mod go.sum && git commit -m "feat: gateway egress spawn — netns handshake, proxy registration, vault-backed resolver"`

---

### Task 10: End-to-end integration test (the payoff)

**Files:** Create `internal/gateway/egress_e2e_test.go` (Linux-only, `make test`). Proves the whole slice: a sandboxed fetch-mcp server calls a local HTTPS upstream with a placeholder; the proxy swaps in the real key (decrypted from the vault); an allowed host returns the upstream's view showing the REAL key; a disallowed host is blocked; and the sandbox env never contains the real key.

- [ ] **Step 1: Write the test** — `internal/gateway/egress_e2e_test.go`

```go
package gateway_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/sandbox"
	// plus the gateway's exported spawn entry (see note)
)

func TestEgressEndToEnd(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("egress E2E requires Linux + NET_ADMIN — run `make test`")
	}
	ctx := context.Background()

	// Local HTTPS upstream that reports the Authorization header it received.
	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	// Build the fetch-mcp + bootstrap binaries (CGO disabled, static).
	bin := func(pkg string) string {
		out := filepath.Join(t.TempDir(), filepath.Base(pkg))
		c := exec.Command("go", "build", "-o", out, "github.com/gigmcp/gigmcp/"+pkg)
		c.Env = append(c.Environ(), "CGO_ENABLED=0")
		if b, err := c.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", pkg, err, b)
		}
		return out
	}
	_ = bin("cmd/fetch-mcp")
	_ = bin("cmd/bootstrap")

	// Assemble a gateway in-process with: vault(random KEK), store with a
	// credential {server:"fetch", tenant:"default", real:"REALKEY",
	// placeholder:"PLACEHOLDER", allow:[upstream host]}, proxy, and one
	// egress-sandboxed fetch backend. (Use the gateway package's exported
	// test harness — add a TestHarness constructor in cmd/gateway or
	// internal/gateway that wires spawnEgressBackend; see note below.)

	gw := startEgressGatewayForTest(t, ctx, fetchBin, bootstrapBin, upstream)
	defer gw.Close()

	// Allowed host: tool returns upstream body; upstream saw the REAL key.
	res := gw.CallTool(t, ctx, "fetch_fetch", map[string]any{"url": upstream.URL})
	if !strings.Contains(res, "upstream-ok") {
		t.Fatalf("allowed fetch failed: %q", res)
	}
	if sawAuth != "Bearer REALKEY" {
		t.Fatalf("upstream saw %q, want Bearer REALKEY (proxy did not inject)", sawAuth)
	}

	// Disallowed host: blocked at the proxy.
	bad := gw.CallTool(t, ctx, "fetch_fetch", map[string]any{"url": "https://evil.example.com/"})
	if !strings.Contains(bad, "ERROR") {
		t.Fatalf("disallowed fetch should error, got %q", bad)
	}

	// The real key never entered the sandbox environment.
	if gw.SandboxEnvContains(t, "REALKEY") {
		t.Fatal("real key leaked into sandbox environment")
	}
}
```

Note: this test needs a small exported test harness. Add `internal/gateway/testharness.go` (build tag `//go:build linux`) exposing `startEgressGatewayForTest(...)` returning a struct with `CallTool`, `SandboxEnvContains` (reads the sandbox's `/proc/<pid>/environ` via the gateway-held child pid — assert the placeholder is present and REALKEY absent), and `Close`. It reuses the `spawnEgressBackend` logic (refactor that into `internal/gateway` so both `cmd/gateway` and the harness call it). Keep `upstream` trusted by the proxy by pointing the proxy's `SetUpstreamRoots` at `upstream.Certificate()`.

- [ ] **Step 2: Run** — `make test` → `TestEgressEndToEnd` runs on Linux and passes; full suite green. `make test-local` → it skips on macOS. If the SandboxEnvContains check can't read `/proc/<pid>/environ` (perm), assert instead that the spawn `cmd.Env` passed to bwrap contains only `PLACEHOLDER` and never `REALKEY` (bwrap `--clearenv` + explicit setenv already guarantee this) — REPORT which form you used.

- [ ] **Step 3: Commit** — `git add internal/gateway/egress_e2e_test.go internal/gateway/testharness.go && git commit -m "test: egress E2E — sandboxed server, proxy key swap, allowlist, no key in sandbox"`

---

### Task 11: Capabilities, hardening, docs

**Files:** Modify `Makefile`, `docker-compose.yml`, `Dockerfile`, `README.md`, `DESIGN.md`.

- [ ] **Step 1: Makefile** — add `--cap-add NET_ADMIN` to the `test` target's `docker run` (alongside the existing security-opts). Comment: `# NET_ADMIN: egress proxy creates veth pairs + moves them into sandbox netns (no SYS_ADMIN needed).`

- [ ] **Step 2: docker-compose.yml** — add to the gateway service:

```yaml
    cap_add:
      - NET_ADMIN
    # belt-and-suspenders: ip_forward=1 by default in the container; deny
    # inter-veth forwarding so sandboxes can't reach each other or the internet
    # except via the proxy (route isolation is primary; this is defense-in-depth).
```

Add an entrypoint or startup step that runs `iptables -P FORWARD DROP` (document that the image must include `iptables`, or do it via netlink at gateway startup). If adding iptables to the image is heavy, implement the FORWARD-drop in Go at gateway start via netlink/nftables and note it; otherwise document the manual step. Add `GIG_MASTER_KEY` (via `_FILE` secret) and `GIG_DEMO_TOKEN` envs.

- [ ] **Step 3: Dockerfile** — ensure the runtime image builds `bootstrap` and `fetch-mcp` too (`go build -o /out/bootstrap ./cmd/bootstrap` etc.) and copies them to `/usr/local/bin/`. Bootstrap must be present for egress spawns.

- [ ] **Step 4: README + DESIGN** — README: update the status block (egress proxy + vault now real; note the `NET_ADMIN` requirement and `GIG_MASTER_KEY`). DESIGN: decisions #3 and #13 were already updated; add a one-line note to §3 threat model that egress runs NET_ADMIN-only (no SYS_ADMIN/privileged) and that route-isolation — not env vars — is the enforcement.

- [ ] **Step 5: Full verification** — `make test` (all green incl. egress E2E), `make test-local` (Linux-only tests skip). Then boot the stack: `GIG_MASTER_KEY=$(openssl rand -hex 32) GIG_DEMO_TOKEN=xyz docker compose up --build -d` and confirm the gateway logs a sandboxed egress backend coming up. Tear down.

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat: NET_ADMIN cap, FORWARD-drop hardening, egress build + docs"`

---

## Done criteria

- `make test` green including `TestEgressEndToEnd`: a sandboxed MCP server's outbound HTTPS is MITM'd; the placeholder header is swapped for the vault-decrypted real key; the upstream sees the real key; the sandbox never holds it; a disallowed host is blocked at CONNECT.
- Gateway runs with `NET_ADMIN` only (no SYS_ADMIN, no privileged).
- Vault: secrets encrypted at rest (envelope encryption); wrong-KEK and tamper both fail.
- Proxy identity is by unforgeable source IP; allowlist enforced before TLS termination.

## Explicitly out of scope (later plans)

Tier-2 (real secret in sandbox env for DB/cert-pinned servers) · per-request audit log persistence (currently `log.Printf`) · manifests/registry as the allowlist source (allowlist currently on the credential row) · idle reaping of egress sandboxes · multiple tenants per server end-to-end (registry supports it; wiring uses "default") · OIDC/dashboard · the NET_ADMIN-only path's `--info-fd` race hardening under high concurrency · scoped seccomp profile to replace `unconfined`.

## Risks carried from the spikes

- bwrap child PID must come from `--info-fd`, not bwrap's PID (Task 9 Step 4).
- A stray `--unshare-net`-less or `--unshare-all` egress command fails closed (no egress) — Task 7's argv test guards it.
- `ip_forward=1` default → FORWARD DROP (Task 11).
- Tunnel ifaces auto-appear in new netns → the bootstrap waits for the *named* peer veth specifically (Task 6), not "any non-lo iface".
- The `CommandTransport` lifecycle vs. the network handshake ordering (Task 9 Step 3) is the integration's trickiest seam — if the SDK lacks an io-based transport, the documented fallback is a concurrent handshake goroutine.
