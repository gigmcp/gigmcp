package registry

import (
	"context"
	"net/http"
	"net/http/httptest"
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

func TestFetchIndexOverHTTP(t *testing.T) {
	url, pub := writeSignedIndex(t, fixtureManifest("echo", "0.1.0", validDigest))
	path := strings.TrimPrefix(url, "file://")
	raw, _ := os.ReadFile(path)
	sig, _ := os.ReadFile(path + ".sig")
	mux := http.NewServeMux()
	mux.HandleFunc("/index.json", func(w http.ResponseWriter, r *http.Request) { w.Write(raw) })
	mux.HandleFunc("/index.json.sig", func(w http.ResponseWriter, r *http.Request) { w.Write(sig) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{IndexURL: srv.URL + "/index.json", PublicKeyHex: pub}
	if _, err := c.FetchIndex(context.Background()); err != nil {
		t.Fatalf("FetchIndex over http: %v", err)
	}
	// missing signature → error mentioning the .sig fetch
	c2 := &Client{IndexURL: srv.URL + "/missing.json", PublicKeyHex: pub}
	if _, err := c2.FetchIndex(context.Background()); err == nil {
		t.Fatal("missing index must fail")
	}
}
