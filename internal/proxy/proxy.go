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
	"sync"
	"syscall"
	"time"

	"github.com/gigmcp/gigmcp/internal/netguard"
)

// upstreamDialTimeout bounds the proxy's upstream TLS dial so a hung or
// black-holed target cannot pin a pump goroutine indefinitely.
const upstreamDialTimeout = 30 * time.Second

// maxConcurrentPerIdentity caps the number of simultaneously-live CONNECT
// tunnels a single sandbox identity (server+tenant) may hold. Without it a
// malicious sandbox could spam CONNECTs to exhaust the host's fds, goroutines,
// and memory. Tune here if a legitimate workload needs more parallelism.
const maxConcurrentPerIdentity = 64

// connLimiter caps concurrent CONNECTs per Identity. Identity is a comparable
// struct (two strings) so it is used directly as the map key.
type connLimiter struct {
	mu    sync.Mutex
	count map[Identity]int
	max   int
}

func newConnLimiter(max int) *connLimiter {
	return &connLimiter{count: make(map[Identity]int), max: max}
}

// acquire reserves a slot for id. It returns false (without reserving) if id is
// already at the cap; on true the caller MUST call release exactly once.
func (l *connLimiter) acquire(id Identity) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count[id] >= l.max {
		return false
	}
	l.count[id]++
	return true
}

// release frees a slot previously taken by a successful acquire.
func (l *connLimiter) release(id Identity) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count[id] <= 1 {
		delete(l.count, id) // keep the map from growing unboundedly
		return
	}
	l.count[id]--
}

// guardDialControl is the production net.Dialer Control callback: it runs AFTER
// name resolution on the CONCRETE resolved IP:port, immediately before the
// socket connects, and refuses any destination netguard.IsBlockedIP rejects
// (loopback / RFC1918 private / link-local / unspecified / CGNAT). Because it
// inspects the address actually being dialed, it closes DNS rebinding (the IP
// checked IS the IP connected to) and blocks SSRF to cloud metadata
// (169.254.169.254, 100.100.100.200) or internal RFC1918 space even when an
// allowlisted hostname points there.
func guardDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address) // post-resolution IP:port
	if err != nil {
		return err
	}
	if netguard.IsBlockedIP(net.ParseIP(host)) {
		return fmt.Errorf("egress ssrf guard: refusing connection to %s", address)
	}
	return nil
}

// Credential is what the resolver returns for a (identity, host): the real
// secret to inject plus how to inject it and which hosts are allowed.
type Credential struct {
	RealSecret   string
	InjectHeader string
	InjectFormat string // contains "{token}"
	// Placeholder must be a high-entropy sentinel — it is matched as a substring;
	// a short/common value risks unintended matches.
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
	reg           *Registry
	res           CredentialResolver
	ca            *CA
	addr          string
	upstreamRoots *x509.CertPool // nil = system roots
	// dialControl is the net.Dialer Control callback applied to every upstream
	// dial. In production (New with no override) it is guardDialControl, which
	// refuses connections to private/metadata/loopback IPs at connect time. Tests
	// that legitimately need a loopback upstream inject a permissive callback via
	// WithDialControl.
	dialControl func(network, address string, c syscall.RawConn) error
	// limiter caps concurrent CONNECT tunnels per identity so a malicious
	// sandbox cannot exhaust fds/goroutines/memory by spamming CONNECTs.
	limiter *connLimiter
}

// Option customizes a Proxy at construction.
type Option func(*Proxy)

// WithDialControl overrides the net.Dialer Control callback used for upstream
// dials. Production callers pass no options and get the SSRF guard
// (guardDialControl); egress tests inject a permissive callback (allowDialControl)
// so loopback httptest upstreams remain reachable.
func WithDialControl(ctrl func(network, address string, c syscall.RawConn) error) Option {
	return func(p *Proxy) { p.dialControl = ctrl }
}

// allowDialControl is a permissive Control callback (permits every address). It
// exists for egress tests whose upstreams run on loopback; production never uses
// it. Exported so gateway-package e2e tests can inject it via WithDialControl.
func allowDialControl(_, _ string, _ syscall.RawConn) error { return nil }

// AllowLoopbackDialControl returns the permissive Control callback for tests
// (gateway e2e) that run upstreams on loopback. NEVER use in production.
func AllowLoopbackDialControl() func(network, address string, c syscall.RawConn) error {
	return allowDialControl
}

// New builds a Proxy with a fresh CA. By default the upstream dial is guarded by
// guardDialControl (closes DNS-rebinding SSRF / blocks private+metadata IPs);
// pass WithDialControl to override (tests needing loopback upstreams).
func New(reg *Registry, res CredentialResolver, opts ...Option) (*Proxy, error) {
	ca, err := NewCA()
	if err != nil {
		return nil, err
	}
	p := &Proxy{reg: reg, res: res, ca: ca, dialControl: guardDialControl, limiter: newConnLimiter(maxConcurrentPerIdentity)}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

func (p *Proxy) CACertPEM() []byte { return p.ca.CertPEM() }

// SetAddr and SetUpstreamRoots must be called before Serve; the values are
// read by request handlers without locking.
func (p *Proxy) SetAddr(a string)                  { p.addr = a }
func (p *Proxy) Addr() string                      { return p.addr }
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
	// Cap concurrent CONNECTs per identity BEFORE hijacking so a malicious
	// sandbox cannot exhaust fds/goroutines/memory by spamming tunnels. On a
	// successful acquire we release in a defer covering every return path below.
	if !p.limiter.acquire(id) {
		log.Printf("DENY src=%s tenant=%s/%s reason=too-many-connections cap=%d", srcIP, id.Server, id.Tenant, maxConcurrentPerIdentity)
		http.Error(w, "too many concurrent connections", http.StatusTooManyRequests)
		return
	}
	defer p.limiter.release(id)
	targetHost := hostname(r.Host)
	cred, err := p.res.Resolve(id, targetHost)
	if err != nil {
		http.Error(w, "no credential", http.StatusForbidden)
		return
	}
	if !HostAllowed(targetHost, cred.AllowedHosts) {
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
	// Dial through a net.Dialer whose Control callback runs on the ACTUAL
	// resolved address right before connect. In production that callback
	// (guardDialControl) refuses private/metadata/loopback IPs, closing
	// DNS-rebinding SSRF: the hostname passed the allowlist, but the IP it
	// resolves to at dial time is the IP we check.
	dialer := &net.Dialer{Timeout: upstreamDialTimeout, Control: p.dialControl}
	upstream, err := tls.DialWithDialer(dialer, "tcp", hostport, &tls.Config{
		ServerName: hostname(hostport),
		RootCAs:    p.upstreamRoots,
	})
	if err != nil {
		return fmt.Errorf("dial upstream %s: %w", hostport, err)
	}
	defer upstream.Close()
	cr := bufio.NewReader(client)
	ur := bufio.NewReader(upstream)
	for {
		req, err := http.ReadRequest(cr)
		if err != nil {
			return err
		}
		// Inject only when the sandbox put the placeholder in the configured header
		// (signals intent to use the credential). The final value is dictated by the
		// TRUSTED InjectFormat, not by whatever framing the untrusted sandbox sent —
		// so a sandbox sending "Basic PLACEHOLDER" still gets the server-defined
		// "Bearer <realkey>", and the real secret never depends on sandbox input.
		if cred.InjectHeader != "" && cred.Placeholder != "" {
			if v := req.Header.Get(cred.InjectHeader); strings.Contains(v, cred.Placeholder) {
				injected := cred.RealSecret
				if cred.InjectFormat != "" {
					injected = strings.ReplaceAll(cred.InjectFormat, "{token}", cred.RealSecret)
				}
				req.Header.Set(cred.InjectHeader, injected)
			}
		}
		// Clear RequestURI so req.Write uses the URL path (HTTP/1.1, not proxy form).
		req.RequestURI = ""
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

// HostAllowed reports whether host is permitted by the allowlist. It is the
// single source of truth for egress allowlist matching; both the proxy and the
// gateway's AuditingResolver call it so the credential-exfiltration boundary
// can never drift between them.
//
// An entry is either an exact host (matched case-insensitively against the full
// host, so "github.com" matches only the apex) or a "*.SUFFIX" wildcard. A
// wildcard matches exactly ONE label: "*.github.com" matches "api.github.com"
// but NOT "a.b.github.com", "evil.com.github.com", or the bare apex
// "github.com". To allow the apex too, add a separate exact entry — as the
// manifests do with ["slack.com", "*.slack.com"].
func HostAllowed(host string, list []string) bool {
	hostLower := strings.ToLower(host)
	for _, h := range list {
		if strings.EqualFold(host, h) {
			return true
		}
		if strings.HasPrefix(h, "*.") {
			suffix := strings.ToLower(h[1:]) // ".github.com"
			if !strings.HasSuffix(hostLower, suffix) {
				continue
			}
			label := hostLower[:len(hostLower)-len(suffix)]
			if label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
	}
	return false
}
