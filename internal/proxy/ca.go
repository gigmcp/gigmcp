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
	"net"
	"sync"
	"time"
)

// CA is a runtime certificate authority that mints cached per-host leaves.
type CA struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caPEM  []byte
	mu     sync.Mutex
	leaves map[string]*tls.Certificate
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
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	// Use IPAddresses SAN for bare IP addresses; DNSNames for hostnames.
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
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
