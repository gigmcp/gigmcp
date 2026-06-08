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
}

// New builds a Proxy with a fresh CA.
func New(reg *Registry, res CredentialResolver) (*Proxy, error) {
	ca, err := NewCA()
	if err != nil {
		return nil, err
	}
	return &Proxy{reg: reg, res: res, ca: ca}, nil
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
