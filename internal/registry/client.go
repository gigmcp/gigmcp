// Package registry fetches and verifies the signed registry index and
// installs servers from it: resolve → pull by digest → verify → extract →
// record. Record-only: spawning stays in the gateway run-loop.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gigmcp/registry/schema"
)

// Client fetches index.json + index.json.sig and verifies the ed25519
// signature over the RAW index bytes BEFORE parsing anything (DESIGN #8:
// runners consume the signed index, never the raw repo).
type Client struct {
	IndexURL     string       // https://... or file:///...; signature at IndexURL + ".sig"
	PublicKeyHex string       // 32-byte ed25519 public key, hex
	HTTP         *http.Client // nil → http.DefaultClient
}

// FetchIndex downloads, verifies, and parses the registry index.
func (c *Client) FetchIndex(ctx context.Context) (*schema.Index, error) {
	raw, err := c.fetch(ctx, c.IndexURL)
	if err != nil {
		return nil, fmt.Errorf("registry: fetch index: %w", err)
	}
	sig, err := c.fetch(ctx, c.IndexURL+".sig")
	if err != nil {
		return nil, fmt.Errorf("registry: fetch index signature: %w", err)
	}
	if err := schema.Verify(c.PublicKeyHex, raw, string(sig)); err != nil {
		return nil, fmt.Errorf("registry: UNTRUSTED index: %w", err)
	}
	var ix schema.Index
	if err := json.Unmarshal(raw, &ix); err != nil {
		return nil, fmt.Errorf("registry: parse index: %w", err)
	}
	if ix.SchemaVersion != 1 {
		return nil, fmt.Errorf("registry: unsupported index schemaVersion %d", ix.SchemaVersion)
	}
	return &ix, nil
}

func (c *Client) fetch(ctx context.Context, url string) ([]byte, error) {
	if path, ok := strings.CutPrefix(url, "file://"); ok {
		return os.ReadFile(path)
	}
	httpc := c.HTTP
	if httpc == nil {
		httpc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MB ceiling — index is small; guards a hostile CDN
}
