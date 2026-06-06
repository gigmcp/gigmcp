//go:build linux

package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigemcp/gigemcp/internal/gateway"
	"github.com/gigemcp/gigemcp/internal/sandbox"
)

// buildBin compiles a Go package as a CGO_ENABLED=0 static binary and returns
// the path to the binary. Fatal on build failure.
func buildBin(t *testing.T, pkg string) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), filepath.Base(pkg))
	c := exec.Command("go", "build", "-o", out, "github.com/gigemcp/gigemcp/"+pkg)
	c.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := c.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	return out
}

func TestEgressEndToEnd(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("egress E2E requires Linux + NET_ADMIN — run: docker run --rm --cap-add NET_ADMIN ...")
	}
	ctx := context.Background()

	// 1. Local HTTPS upstream that records the Authorization header it received.
	var sawAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()
	t.Logf("upstream URL: %s", upstream.URL)

	// 2. Build static binaries (CGO_ENABLED=0).
	t.Log("building fetch-mcp...")
	fetchBin := buildBin(t, "cmd/fetch-mcp")
	t.Log("building bootstrap...")
	bootstrapBin := buildBin(t, "cmd/bootstrap")
	t.Logf("fetchBin=%s bootstrapBin=%s", fetchBin, bootstrapBin)

	// 3. Assemble upstream TLS info for the harness.
	// upstream.TLS.Certificates[0] is the server's certificate.
	upstreamCert := &upstream.TLS.Certificates[0]
	upstreamInfo, err := gateway.NewTLSServerInfo(upstream.URL, upstreamCert)
	if err != nil {
		t.Fatalf("upstream info: %v", err)
	}

	// 4. Start the egress gateway (proxy + sandbox + vault + store).
	gw := gateway.StartEgressGatewayForTest(t, ctx, fetchBin, bootstrapBin, upstreamInfo)
	defer gw.Close()

	// 5. ALLOWED host: the sandbox fetches the upstream URL.
	// The fetch-mcp tool is named "fetch"; we call it directly on the backend session.
	t.Log("calling fetch tool (allowed host)...")
	res := gw.CallTool(t, ctx, "fetch", map[string]any{"url": upstream.URL})
	t.Logf("result: %q", res)
	t.Logf("upstream saw Authorization: %q", sawAuth)

	if !strings.Contains(res, "upstream-ok") {
		t.Fatalf("allowed fetch failed; tool returned: %q", res)
	}
	if sawAuth != "Bearer REALKEY" {
		t.Fatalf("upstream saw %q, want \"Bearer REALKEY\" — proxy did not inject real key", sawAuth)
	}

	// 6. DISALLOWED host: must be blocked (proxy 403s at CONNECT; fetch returns ERROR).
	t.Log("calling fetch tool (disallowed host)...")
	bad := gw.CallTool(t, ctx, "fetch", map[string]any{"url": "https://evil.example.com/"})
	t.Logf("disallowed result: %q", bad)
	if !strings.Contains(bad, "ERROR") {
		t.Fatalf("disallowed fetch should return ERROR, got: %q", bad)
	}

	// 7. KEY-NOT-IN-SANDBOX assertion.
	//
	// Behavioral proof (already demonstrated above): the upstream received
	// "Bearer REALKEY" while the sandbox only ever knew "PLACEHOLDER"
	// (GIGE_PLACEHOLDER=PLACEHOLDER is the only env var referencing the credential;
	// REALKEY lives exclusively in the vault and is injected by the proxy
	// after leaving the sandbox boundary).
	//
	// Structural proof: SpawnEgressBackend uses bwrap --clearenv + explicit
	// --setenv flags (from sandbox.commandEgress). The only credential-related
	// env var passed into the sandbox is GIGE_PLACEHOLDER=PLACEHOLDER.
	// REALKEY is never in bwrap's argv or environment — it only exists in the
	// gateway process's memory (in the vault, decrypted on-demand by the proxy).
	//
	// We assert this structurally: confirm REALKEY is absent from the bwrap
	// process's own environment and arguments. Since bwrap uses --clearenv
	// (stripping even bwrap's own parent env from the child), and only the
	// --setenv flags reach the sandboxed server, REALKEY cannot enter the sandbox.
	// The test verifies the placeholder (not the real key) is what the sandbox sends.
	t.Log("asserting key-not-in-sandbox...")
	assertKeyNotInSandboxEnv(t, gw)
}

// assertKeyNotInSandboxEnv documents and enforces the key-isolation guarantee.
// The assertion has two parts:
//  1. The behavioral assertion (above, in the main test): the upstream received the
//     real key, which can ONLY happen if the proxy — not the sandbox — injected it.
//  2. The structural assertion here: SpawnEgressBackend exposes a way to confirm
//     the spawn environment (the bwrap argv seen by the process) never contains
//     "REALKEY". We read this from the gateway harness.
func assertKeyNotInSandboxEnv(t *testing.T, gw *gateway.EgressTestGateway) {
	t.Helper()
	// Read the bwrap command line that was used to spawn the sandbox.
	// This is available from the harness for exactly this assertion.
	spawnEnv := gw.SpawnEnv()
	for _, v := range spawnEnv {
		if strings.Contains(v, "REALKEY") {
			t.Errorf("REALKEY found in spawn environment: %q", v)
		}
	}
	t.Log("REALKEY absent from spawn environment — key isolation confirmed")

	// Also confirm the placeholder IS present (proves the sandbox knew what to send).
	foundPlaceholder := false
	for _, v := range spawnEnv {
		if strings.Contains(v, "PLACEHOLDER") {
			foundPlaceholder = true
			break
		}
	}
	if !foundPlaceholder {
		t.Errorf("PLACEHOLDER not found in spawn environment — sandbox may not have sent the placeholder header")
	}
}
