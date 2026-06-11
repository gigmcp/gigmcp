package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/auth"
	"github.com/gigmcp/gigmcp/internal/proxy"
	"github.com/gigmcp/gigmcp/internal/store"
	"github.com/gigmcp/gigmcp/internal/vault"
)

// The placeholder the sandbox is configured to send; the proxy swaps it for the
// real bearer. This is the value the sandbox process "holds".
const e2ePlaceholder = "GIG_PLACEHOLDER_HIGH_ENTROPY_SENTINEL_XYZ"

func TestOAuthEgressInjectsBearerSandboxNeverHoldsToken(t *testing.T) {
	ctx := context.Background()

	// 1. Fake OAuth provider (authorize bounces a code; token mints access+refresh).
	prov := newE2EProvider(t)

	// 2. Real store + vault + broker.
	st, err := store.OpenSQLite(filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	v, err := vault.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	encSecret, err := v.Encrypt([]byte("client-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutAuthConfig(ctx, store.AuthConfig{
		Vendor: "acme", AuthorizeURL: prov.URL + "/authorize", TokenURL: prov.URL + "/token",
		ClientID: "cid", EncryptedClientSecret: encSecret, Mode: "byo", PKCE: true,
	}); err != nil {
		t.Fatal(err)
	}
	broker, err := auth.NewOAuthBroker(st, v,
		"http://gw/api/connections/oauth/callback", "http://gw",
		auth.WithHTTPClient(http.DefaultClient))
	if err != nil {
		t.Fatal(err)
	}

	// 3. Connect: drive start→callback so the user has a stored account.
	startReq := httptest.NewRequest("GET", "/api/connections/oauth/start?vendor=acme", nil)
	startRec := httptest.NewRecorder()
	broker.StartHandler(startRec, startReq, 42, []string{"read"}, "/done")
	loc, err := url.Parse(startRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse start redirect location: %v", err)
	}

	// Follow the provider's authorize endpoint — it 302s back to the callback URL.
	// Use a non-following client so we capture the redirect rather than following it
	// to the (unreachable) gateway callback address.
	noFollow := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authResp, err := noFollow.Get(loc.String())
	if err != nil {
		t.Fatalf("provider authorize: %v", err)
	}
	cbLoc, err := authResp.Location()
	if err != nil {
		t.Fatalf("provider authorize location: %v", err)
	}
	_ = authResp.Body.Close()

	// Extract the flow cookie from the start response.
	var flow *http.Cookie
	for _, c := range startRec.Result().Cookies() {
		if c.Name == "gig_oauth_flow" {
			flow = c
		}
	}
	if flow == nil {
		t.Fatal("gig_oauth_flow cookie not set by StartHandler")
	}

	// Drive the callback handler with the code+state from the provider redirect.
	cbReq := httptest.NewRequest("GET", "/api/connections/oauth/callback?"+cbLoc.RawQuery, nil)
	cbReq.AddCookie(flow)
	cbRec := httptest.NewRecorder()
	broker.CallbackHandler(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("connect callback failed: %d %s", cbRec.Code, cbRec.Body.String())
	}

	// 4. Install an oauth2 manifest for server "acmeapp" / vendor "acme".
	//    The upstream host is the fake upstream we start below.
	upstream, upstreamHost := newE2EUpstream(t)
	// AllowedHosts uses only the bare hostname (no port); the proxy's allowed()
	// function compares against hostname(CONNECT host) which strips the port.
	upstreamBareHost, _, _ := net.SplitHostPort(upstreamHost)
	if err := st.PutManifest(ctx, store.ManifestRecord{
		Server: "acmeapp", Version: "1.0.0", Digest: "sha256:x", Tier: "sealed",
		Entrypoint: "/app/server", AllowedHosts: []string{upstreamBareHost},
		Injections: []store.Injection{{
			ID: "oauth", Type: "oauth2", Provider: "acme", Scopes: []string{"read"},
			Header: "Authorization", Format: "Bearer {token}", Placeholder: e2ePlaceholder,
		}},
		ManifestHash: "h1",
	}); err != nil {
		t.Fatal(err)
	}

	// 5. Real proxy with the real resolver wired to the broker.
	reg := proxy.NewRegistry()
	resolver := &CredResolver{Store: st, Vault: v, Broker: broker}
	p, err := proxy.New(reg, resolver)
	if err != nil {
		t.Fatal(err)
	}
	// Trust the fake upstream's cert from the proxy's upstream dial.
	p.SetUpstreamRoots(upstream.certPool)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	p.SetAddr(ln.Addr().String())
	go p.Serve(ln)

	// Register the sandbox identity for the proxy's source-IP lookup.
	// The proxy maps 127.0.0.1 → the acmeapp identity for user 42.
	reg.Bind("127.0.0.1", proxy.Identity{Server: "acmeapp", Tenant: store.UserTenant(42)})

	// 6. As the "sandbox", send a request THROUGH the proxy with ONLY the
	//    placeholder in Authorization — never the real token.
	client := proxyClientE2E(t, p, upstream.certPool)
	req, err := http.NewRequest("GET", "https://"+upstreamHost+"/resource", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+e2ePlaceholder)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upstream status %d", resp.StatusCode)
	}

	// 7. Assertions: upstream saw the REAL bearer; the placeholder (what the
	//    sandbox held) was NOT forwarded as the bearer.
	gotAuth := upstream.lastAuth()
	if !strings.HasPrefix(gotAuth, "Bearer access-") {
		t.Fatalf("upstream did not receive the real bearer: %q", gotAuth)
	}
	if strings.Contains(gotAuth, e2ePlaceholder) {
		t.Fatalf("SECURITY: the sandbox placeholder reached the upstream as the bearer: %q", gotAuth)
	}

	// 8. Default-deny: a non-entitled host must be refused.
	badReq, _ := http.NewRequest("GET", "https://evil.example.com/x", nil)
	if _, err := client.Do(badReq); err == nil {
		t.Fatal("egress to a non-entitled host must be denied")
	}
}

// newE2EProvider returns a fake OAuth2 provider server. The /authorize endpoint
// redirects back with a fixed code; /token issues a fresh access + refresh token.
func newE2EProvider(t *testing.T) *httptest.Server {
	t.Helper()
	seq := 0
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		ru, err := url.Parse(r.URL.Query().Get("redirect_uri"))
		if err != nil {
			http.Error(w, "bad redirect_uri", http.StatusBadRequest)
			return
		}
		q := ru.Query()
		q.Set("code", "code-xyz")
		q.Set("state", r.URL.Query().Get("state"))
		ru.RawQuery = q.Encode()
		http.Redirect(w, r, ru.String(), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		seq++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-" + strconv.Itoa(seq),
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "refresh-tok",
			"scope":         "read",
		})
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// e2eUpstream is a TLS server that records the Authorization header it received.
type e2eUpstream struct {
	srv      *httptest.Server
	certPool *x509.CertPool
	mu       chan string
}

func newE2EUpstream(t *testing.T) (*e2eUpstream, string) {
	t.Helper()
	u := &e2eUpstream{mu: make(chan string, 8)}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu <- r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	u.srv = srv
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u.certPool = pool
	host := strings.TrimPrefix(srv.URL, "https://")
	return u, host
}

func (u *e2eUpstream) lastAuth() string {
	select {
	case v := <-u.mu:
		return v
	case <-time.After(2 * time.Second):
		return ""
	}
}

// proxyClientE2E builds an http.Client whose transport CONNECTs through the proxy
// and trusts the proxy's MITM CA (so the sandbox-side TLS verifies).
func proxyClientE2E(t *testing.T, p *proxy.Proxy, _ *x509.CertPool) *http.Client {
	t.Helper()
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(p.CACertPEM())
	proxyURL, _ := url.Parse("http://" + p.Addr())
	return &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: caPool},
	}}
}
