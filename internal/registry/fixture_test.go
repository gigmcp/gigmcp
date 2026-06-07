package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/registry/schema"
)

// fixtureManifest returns a valid manifest for a server packaged at
// entrypoint /app/server with the given image digest.
func fixtureManifest(name, version, digest string) *schema.Manifest {
	return &schema.Manifest{
		SchemaVersion: 1,
		Name:          name,
		Version:       version,
		Source:        schema.Source{Repo: "github.com/gigmcp/gigmcp", Tag: "v" + version},
		Image:         schema.Image{Ref: "ghcr.io/gigmcp/" + name, Digest: digest, Entrypoint: "/app/server"},
		Tier:          schema.TierSealed,
		Entitlements:  schema.Entitlements{Egress: []string{"api.example.com"}},
		Credentials: []schema.Credential{{
			ID: "token", Type: "api_key", Provider: "example",
			Inject: schema.Inject{Header: "Authorization", Format: "Bearer {token}"},
		}},
		Tools: []schema.Tool{{Name: "echo", Default: true}, {Name: "loud-echo", Default: false}},
	}
}

// writeSignedIndex compiles manifests into a signed index on disk and returns
// the file:// URL and the hex public key.
func writeSignedIndex(t *testing.T, manifests ...*schema.Manifest) (indexURL, pubHex string) {
	t.Helper()
	ix, err := schema.BuildIndex(manifests, "2026-06-06T00:00:00Z")
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
	dir := t.TempDir()
	indexPath := filepath.Join(dir, "index.json")
	if err := os.WriteFile(indexPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath+".sig", []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	return "file://" + indexPath, hex.EncodeToString(pub)
}

// validDigest is a well-formed (but content-less) digest for client tests.
var validDigest = "sha256:" + strings.Repeat("a", 64)
