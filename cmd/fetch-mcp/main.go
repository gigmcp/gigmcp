// Command fetch-mcp is a test MCP server with a single `fetch` tool that does
// an HTTPS GET with a placeholder Authorization header. Run sandboxed behind
// the egress proxy, the placeholder is swapped for the real key; the tool
// returns the upstream's response body so a test can assert what the upstream
// actually received. PLACEHOLDER comes from $GIG_PLACEHOLDER.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type fetchArgs struct {
	URL string `json:"url" jsonschema:"the https URL to GET"`
}

func newClient() *http.Client {
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if caFile := os.Getenv("SSL_CERT_FILE"); caFile != "" {
		if pem, err := os.ReadFile(caFile); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}

	// Build a proxy function that always uses HTTPS_PROXY, bypassing Go's
	// default loopback-exclusion logic (which would skip the proxy for
	// 127.0.0.1 targets — defeating the test harness).
	var proxyFn func(*http.Request) (*url.URL, error)
	if proxyStr := os.Getenv("HTTPS_PROXY"); proxyStr != "" {
		proxyURL, err := url.Parse(proxyStr)
		if err == nil {
			proxyFn = http.ProxyURL(proxyURL)
		}
	}
	if proxyFn == nil {
		proxyFn = http.ProxyFromEnvironment
	}

	tr := &http.Transport{
		Proxy:           proxyFn,
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	return &http.Client{Transport: tr}
}

func main() {
	placeholder := os.Getenv("GIG_PLACEHOLDER")
	client := newClient()
	s := mcp.NewServer(&mcp.Implementation{Name: "fetch-mcp", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "fetch", Description: "HTTPS GET a URL"},
		func(ctx context.Context, req *mcp.CallToolRequest, in fetchArgs) (*mcp.CallToolResult, any, error) {
			r, err := http.NewRequestWithContext(ctx, "GET", in.URL, nil)
			if err != nil {
				return nil, nil, err
			}
			r.Header.Set("Authorization", "Bearer "+placeholder)
			resp, err := client.Do(r)
			if err != nil {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: " + err.Error()}}}, nil, nil
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("%d %s", resp.StatusCode, string(body))}}}, nil, nil
		})
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatal(err)
	}
}
