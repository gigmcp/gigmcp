package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/api"
	"github.com/gigmcp/gigmcp/internal/registry"
	"github.com/gigmcp/registry/schema"
)

// catalogManifest returns a minimal Validate-clean manifest for index fixtures.
func catalogManifest(name, version string) *schema.Manifest {
	return &schema.Manifest{
		SchemaVersion: 1,
		Name:          name,
		Version:       version,
		Source:        schema.Source{Repo: "github.com/gigmcp/gigmcp", Tag: "v" + version},
		Image: schema.Image{
			Ref:        "ghcr.io/gigmcp/" + name,
			Digest:     "sha256:" + strings.Repeat("a", 64),
			Entrypoint: "/app/server",
		},
		Tier:  schema.TierSealed,
		Tools: []schema.Tool{{Name: "echo", Default: true}},
	}
}

// writeSignedIndex compiles manifests into a signed index on disk (the same
// fabrication as internal/registry's fixture) and returns a verifying
// *registry.Client over its file:// URL.
func writeSignedIndex(t *testing.T, manifests ...*schema.Manifest) *registry.Client {
	t.Helper()
	ix, err := schema.BuildIndex(manifests, "2026-06-07T00:00:00Z")
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
	indexPath := filepath.Join(t.TempDir(), "index.json")
	if err := os.WriteFile(indexPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath+".sig", []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	return &registry.Client{IndexURL: "file://" + indexPath, PublicKeyHex: hex.EncodeToString(pub)}
}

// countingFetcher counts FetchIndex calls (cache-hit assertions).
type countingFetcher struct {
	calls int
	ix    *schema.Index
	err   error
}

func (f *countingFetcher) FetchIndex(context.Context) (*schema.Index, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.ix, nil
}

func TestRegistryCatalog(t *testing.T) {
	tests := []struct {
		name     string
		registry api.IndexFetcher // nil = unconfigured
		wantCode int
		wantBody string // substring of the response body
	}{
		{
			name:     "registry unconfigured returns 501",
			registry: nil,
			wantCode: http.StatusNotImplemented,
			wantBody: `"registry_disabled"`,
		},
		{
			// Two servers added out of order: the response must be sorted by
			// name ascending, carry latest, and include the description key
			// even while it is always empty.
			name:     "happy path lists signed index sorted by name",
			registry: writeSignedIndex(t, catalogManifest("zeta", "0.2.0"), catalogManifest("ably", "0.1.0")),
			wantCode: http.StatusOK,
			wantBody: `{"servers":[{"name":"ably","description":"","latest":"0.1.0"},{"name":"zeta","description":"","latest":"0.2.0"}]}`,
		},
		{
			name:     "fetch failure returns 502",
			registry: &countingFetcher{err: errors.New("index host down")},
			wantCode: http.StatusBadGateway,
			wantBody: `"registry_unavailable"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, ts, st, _ := newTestAPI(t)
			srv.Registry = tc.registry
			_, cookie := seedUserSession(t, st, "user@x", "user")

			code, body := doJSON(t, ts, cookie, "GET", "/api/registry/servers", "")
			if code != tc.wantCode {
				t.Fatalf("status: want %d, got %d: %s", tc.wantCode, code, body)
			}
			if !strings.Contains(string(body), tc.wantBody) {
				t.Fatalf("body: want substring %s, got %s", tc.wantBody, body)
			}
		})
	}
}

// TestRegistryCatalogDescription verifies the catalog surfaces the latest
// manifest's Description, and nil-guards a missing latest version (no panic).
func TestRegistryCatalogDescription(t *testing.T) {
	// "ably" has a Description on its latest manifest.
	branded := catalogManifest("ably", "0.1.0")
	branded.Description = "Realtime messaging."

	// "ghost" has a Latest that points at a version absent from Versions →
	// srv.Versions[srv.Latest] is nil and must not panic.
	nilLatest := &schema.Index{
		SchemaVersion: 1,
		Servers: map[string]schema.IndexServer{
			"ghost": {Latest: "9.9.9", Versions: map[string]*schema.Manifest{}},
		},
	}

	t.Run("description from latest manifest", func(t *testing.T) {
		srv, ts, st, _ := newTestAPI(t)
		srv.Registry = writeSignedIndex(t, branded)
		_, cookie := seedUserSession(t, st, "user@x", "user")

		code, body := doJSON(t, ts, cookie, "GET", "/api/registry/servers", "")
		if code != http.StatusOK {
			t.Fatalf("status: want 200, got %d: %s", code, body)
		}
		if !strings.Contains(string(body), `"description":"Realtime messaging."`) {
			t.Fatalf("want description surfaced, got %s", body)
		}
	})

	t.Run("nil latest manifest yields empty description, no panic", func(t *testing.T) {
		srv, ts, st, _ := newTestAPI(t)
		srv.Registry = &countingFetcher{ix: nilLatest}
		_, cookie := seedUserSession(t, st, "user@x", "user")

		code, body := doJSON(t, ts, cookie, "GET", "/api/registry/servers", "")
		if code != http.StatusOK {
			t.Fatalf("status: want 200, got %d: %s", code, body)
		}
		if !strings.Contains(string(body), `{"name":"ghost","description":"","latest":"9.9.9"}`) {
			t.Fatalf("want empty description for nil latest, got %s", body)
		}
	})
}

func TestRegistryCatalogRequiresSession(t *testing.T) {
	srv, ts, _, _ := newTestAPI(t)
	srv.Registry = &countingFetcher{ix: &schema.Index{SchemaVersion: 1}}

	code, body := doJSON(t, ts, nil, "GET", "/api/registry/servers", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("unauthed catalog: want 401, got %d: %s", code, body)
	}
}

// TestRegistryCatalogCachesIndex verifies the second request within the TTL
// is served from the in-memory cache (no re-fetch), and that a failed fetch
// is NOT cached (the next request retries).
func TestRegistryCatalogCachesIndex(t *testing.T) {
	ix, err := schema.BuildIndex([]*schema.Manifest{catalogManifest("ably", "0.1.0")}, "2026-06-07T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &countingFetcher{ix: ix, err: errors.New("cold start outage")}

	srv, ts, st, _ := newTestAPI(t)
	srv.Registry = fetcher
	_, cookie := seedUserSession(t, st, "user@x", "user")

	// Failed fetch: 502 and nothing cached.
	if code, body := doJSON(t, ts, cookie, "GET", "/api/registry/servers", ""); code != http.StatusBadGateway {
		t.Fatalf("outage: want 502, got %d: %s", code, body)
	}
	if fetcher.calls != 1 {
		t.Fatalf("outage: want 1 fetch, got %d", fetcher.calls)
	}

	// Recovery fetch populates the cache; the next request must not re-fetch.
	fetcher.err = nil
	for i := 0; i < 2; i++ {
		code, body := doJSON(t, ts, cookie, "GET", "/api/registry/servers", "")
		if code != http.StatusOK || !strings.Contains(string(body), `"ably"`) {
			t.Fatalf("request %d: %d %s", i, code, body)
		}
	}
	if fetcher.calls != 2 {
		t.Fatalf("cache hit: want 2 total fetches (1 failed + 1 cached), got %d", fetcher.calls)
	}
}
