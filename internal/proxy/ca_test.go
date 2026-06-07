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
