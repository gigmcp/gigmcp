package auth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gigmcp/gigmcp/internal/store"
)

// TestIsBlockedIP is a direct unit test of the SSRF guard predicate, covering
// the existing rejection set plus the CGNAT (RFC 6598 100.64.0.0/10) range and
// confirming a public address is still allowed.
func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},       // loopback
		{"10.0.0.1", true},        // RFC1918 private
		{"192.168.1.1", true},     // RFC1918 private
		{"169.254.169.254", true}, // link-local (cloud metadata)
		{"0.0.0.0", true},         // unspecified
		{"100.64.0.0", true},      // CGNAT lower bound
		{"100.100.100.200", true}, // CGNAT (Alibaba metadata)
		{"100.127.255.255", true}, // CGNAT upper bound
		{"8.8.8.8", false},        // public
		{"1.1.1.1", false},        // public
		{"100.128.0.0", false},    // just outside CGNAT /10
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("test bug: unparseable IP %q", c.ip)
		}
		if got := isBlockedIP(ip); got != c.blocked {
			t.Errorf("isBlockedIP(%s) = %v, want %v", c.ip, got, c.blocked)
		}
	}
	if !isBlockedIP(nil) {
		t.Error("isBlockedIP(nil) must be true (unparseable address)")
	}
}

// TestGuardedClientRefusesLoopback is a direct unit test of the SSRF
// connection-time guard: a plain GET to a loopback address must be refused at
// dial time (the net.Dialer Control callback rejects the resolved 127.0.0.1).
func TestGuardedClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := newGuardedHTTPClient()
	resp, err := client.Get(srv.URL) // srv.URL is http://127.0.0.1:<port>/
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("guarded client must refuse a loopback destination")
	}
	if !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("error should mention the ssrf guard, got: %v", err)
	}
}

// TestBrokerWithGuardBlocksRefreshToLoopbackTokenURL builds a broker with the
// PRODUCTION (guarded) client — no WithHTTPClient override — and points a BYO
// config's token_url at a loopback httptest server. An expired account forces a
// refresh; the guard must refuse the dial so the refresh_token grant fails. This
// is the connection-time backstop that catches what input validation can miss
// (non-canonical IP encodings and DNS rebinding to a private address).
func TestBrokerWithGuardBlocksRefreshToLoopbackTokenURL(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true // must never be reached: the dial is refused first
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"leaked","token_type":"Bearer","expires_in":3600}`))
	}))
	defer srv.Close()

	fs := &fakeBrokerStore{
		cfg: store.AuthConfig{
			Vendor: "google", TokenURL: srv.URL + "/token", ClientID: "cid",
			EncryptedClientSecret: []byte("enc:sek"), Mode: "byo",
		},
		account: &store.ConnectedAccount{
			UserID: 42, Vendor: "google",
			EncryptedRefreshToken: []byte("enc:refresh-tok"),
			EncryptedAccessToken:  []byte("enc:stale-access"),
			ExpiresAt:             time.Now().Add(-time.Minute), // expired → forces refresh
			GrantedScopes:         []string{"email"},
		},
	}

	// Production constructor: NO WithHTTPClient, so the broker uses the guarded
	// client. This is the whole point of the test.
	b, err := NewOAuthBroker(fs, passthroughVault{},
		"http://localhost:8080/api/connections/oauth/callback", "http://localhost:8080")
	if err != nil {
		t.Fatal(err)
	}

	_, err = b.EnsureFreshToken(context.Background(), 42, "google")
	if err == nil {
		t.Fatal("refresh through the guarded client to a loopback token_url must fail")
	}
	if !strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("refresh error should mention the ssrf guard, got: %v", err)
	}
	if called {
		t.Fatal("SECURITY: the loopback token endpoint was reached despite the SSRF guard")
	}
}
