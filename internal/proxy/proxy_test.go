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

// hostOnly strips the port from a host:port string.
func hostOnly(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return h
}

// upstreamPool returns a cert pool containing the upstream test server's certificate.
func upstreamPool(t *testing.T, srv *httptest.Server) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	for _, c := range srv.TLS.Certificates {
		for _, der := range c.Certificate {
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("parse upstream cert: %v", err)
			}
			pool.AddCert(cert)
		}
	}
	return pool
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

// TestProxyNoInjectionEmptySecretAllowsEntitledHost covers the credential-less
// "sealed" server case (e.g. hackernews, a public API): the resolver returns a
// Credential with an empty secret/header/placeholder but a populated allowlist.
// The proxy must allow egress to the entitled host and perform NO injection —
// any header the sandbox sent is forwarded verbatim, untouched.
func TestProxyNoInjectionEmptySecretAllowsEntitledHost(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	upHost := upstream.Listener.Addr().String()

	reg := proxy.NewRegistry()
	reg.Bind("127.0.0.1", proxy.Identity{Server: "hackernews", Tenant: "default"})

	// No secret, no inject header, no placeholder — only an allowlist.
	res := fakeResolver{cred: proxy.Credential{
		AllowedHosts: []string{hostOnly(upHost)},
	}}
	p := startProxy(t, reg, res)
	p.SetUpstreamRoots(upstreamPool(t, upstream))

	client := clientThroughProxy(t, p)
	req, _ := http.NewRequest("GET", "https://"+upHost+"/", nil)
	// Sandbox sends something in Authorization; the proxy must NOT rewrite it
	// (no injection config), and must NOT panic on the empty credential.
	req.Header.Set("Authorization", "untouched")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("entitled host with empty secret must be allowed: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotAuth != "untouched" {
		t.Fatalf("upstream saw %q, want %q (no injection for empty credential)", gotAuth, "untouched")
	}
}

// TestProxyEmptySecretDeniesNonEntitledHost confirms default-deny still holds
// for a credential-less server: a host outside the manifest allowlist is denied.
func TestProxyEmptySecretDeniesNonEntitledHost(t *testing.T) {
	reg := proxy.NewRegistry()
	reg.Bind("127.0.0.1", proxy.Identity{Server: "hackernews", Tenant: "default"})
	res := fakeResolver{cred: proxy.Credential{AllowedHosts: []string{"hn.algolia.com"}}}
	p := startProxy(t, reg, res)
	client := clientThroughProxy(t, p)
	_, err := client.Get("https://evil.example.com/")
	if err == nil {
		t.Fatal("non-entitled host must be denied even for a credential-less server")
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

// TestProxyEnforcesTrustedFormat verifies that even when the sandbox sends a
// different framing (e.g. "Basic PLACEHOLDER"), the header value forwarded to
// the upstream is dictated by the trusted InjectFormat ("Bearer {token}") and
// not by the sandbox-supplied framing.
func TestProxyEnforcesTrustedFormat(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	upHost := upstream.Listener.Addr().String()

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
	p.SetUpstreamRoots(upstreamPool(t, upstream))

	client := clientThroughProxy(t, p)
	// Sandbox sends a different framing ("Basic") to try to influence the output.
	req, _ := http.NewRequest("GET", "https://"+upHost+"/", nil)
	req.Header.Set("Authorization", "Basic PLACEHOLDER")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Trusted InjectFormat must win: upstream MUST see "Bearer REALKEY", not "Basic REALKEY".
	if gotAuth != "Bearer REALKEY" {
		t.Fatalf("upstream saw %q, want %q (trusted InjectFormat must dictate framing)", gotAuth, "Bearer REALKEY")
	}
}
