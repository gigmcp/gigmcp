package sandbox_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/sandbox"
)

func requireSandbox(t *testing.T) {
	t.Helper()
	if !sandbox.Available() {
		t.Skip("sandbox requires Linux with bwrap installed — run `make test`")
	}
}

func runShell(t *testing.T, script string) (string, error) {
	t.Helper()
	cmd := sandbox.Command(sandbox.Spec{
		Exec:   "/bin/sh",
		Args:   []string{"-c", script},
		Mounts: sandbox.ShellMounts(),
	})
	out, err := cmd.Output()
	return string(out), err
}

func TestRunsCommand(t *testing.T) {
	requireSandbox(t)
	out, err := runShell(t, "echo hi")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(out); got != "hi" {
		t.Errorf("got %q, want %q", got, "hi")
	}
}

func TestNoNetworkInterfaces(t *testing.T) {
	requireSandbox(t)
	out, err := runShell(t, "cat /proc/net/dev")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "lo:") {
		t.Errorf("expected loopback to exist, got:\n%s", out)
	}
	if strings.Contains(out, "eth0") {
		t.Errorf("sandbox sees host network interface eth0:\n%s", out)
	}
}

func TestHostFilesHidden(t *testing.T) {
	requireSandbox(t)
	// Canary in the current working directory (e.g. /src in the dev
	// container), which is NOT bind-mounted into the sandbox — and NOT
	// under /tmp, so the --tmpfs mask is not what hides it.
	secret, err := os.CreateTemp(".", "gig-canary-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(secret.Name())
	if _, err := secret.WriteString("key-material"); err != nil {
		t.Fatal(err)
	}
	secret.Close()
	abs, err := filepath.Abs(secret.Name())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runShell(t, "cat "+abs); err == nil {
		t.Fatal("sandbox could read an unmounted host file outside /tmp")
	}
	// A host file that definitely exists must also be invisible: the
	// sandbox only sees the read-only binds it was granted.
	if _, err := runShell(t, "cat /etc/os-release"); err == nil {
		t.Fatal("sandbox could read host /etc/os-release")
	}
}

func TestEnvCleared(t *testing.T) {
	requireSandbox(t)
	t.Setenv("GIG_SECRET_CANARY", "leak")
	out, err := runShell(t, "env")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "GIG_SECRET_CANARY") {
		t.Errorf("host environment leaked into sandbox:\n%s", out)
	}
}

func TestProcIsPrivate(t *testing.T) {
	requireSandbox(t)
	// A fresh procfs in the sandbox's pid namespace reflects only the
	// sandbox's own process tree. We detect a host /proc leak by
	// checking /proc/self/status: in a fresh pid namespace the kernel
	// assigns low PIDs (≤ 10) starting from 1; a bind-mounted /proc
	// exposes the outer-namespace PID, which is always higher because
	// the host already has many longer-lived processes allocated below it.
	out, err := runShell(t, "while read f v; do case $f in Pid:) echo $v; break;; esac; done < /proc/self/status")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		t.Fatalf("parse %q: %v", out, err)
	}
	if n > 10 {
		t.Errorf("sandbox /proc/self/status shows Pid %d — host /proc is leaking (expected ≤ 10 in fresh pid namespace)", n)
	}
}

func TestCommandArgvHardening(t *testing.T) {
	cmd := sandbox.Command(sandbox.Spec{
		Exec:   "--share-net", // adversarial, option-like
		Args:   []string{"-c", "true"},
		Mounts: []sandbox.Mount{{Src: "/host/x", Dst: "/proc"}}, // tries to clobber /proc
	})
	args := cmd.Args // args[0] == "bwrap"

	// The caller's /proc bind must appear BEFORE the fixed --proc, so the
	// fixed fresh procfs wins (later mount overrides earlier in bwrap).
	idxBind := indexOfPair(args, "--ro-bind", "/host/x", "/proc")
	idxProc := indexOf(args, "--proc")
	if idxBind == -1 {
		t.Fatal("caller --ro-bind for /proc not found")
	}
	if idxProc == -1 || idxProc < idxBind {
		t.Fatalf("fixed --proc (%d) must come after caller /proc bind (%d)", idxProc, idxBind)
	}

	// A literal -- must precede the option-like Exec.
	idxSep := indexOf(args, "--")
	idxExec := indexOf(args, "--share-net")
	if idxSep == -1 || idxExec == -1 || idxSep >= idxExec {
		t.Fatalf("-- (%d) must come before Exec (%d)", idxSep, idxExec)
	}
}

func TestEgressCommandArgv(t *testing.T) {
	spec := sandbox.Spec{
		Exec:   "/app/server",
		Mounts: []sandbox.Mount{{Src: "/h/server", Dst: "/app/server"}},
		Egress: &sandbox.Egress{
			BootstrapPath: "/usr/local/bin/bootstrap",
			SandboxCIDR:   "10.88.0.2/30",
			ProxyIP:       "10.88.0.1",
			PeerVeth:      "vs0",
			InfoFD:        5,
			Env: map[string]string{
				"HTTPS_PROXY":     "http://10.88.0.1:8081",
				"GIG_PLACEHOLDER": "PLACEHOLDER",
			},
		},
	}
	cmd := sandbox.Command(spec)
	args := cmd.Args

	// Egress mode must NOT use --unshare-all (it sequences net wrong) ...
	if indexOf(args, "--unshare-all") != -1 {
		t.Error("egress mode must not pass --unshare-all")
	}
	// ... but MUST keep --unshare-net (bwrap creates the netns) and the others.
	for _, f := range []string{"--unshare-net", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup"} {
		if indexOf(args, f) == -1 {
			t.Errorf("egress mode missing %s", f)
		}
	}
	// Egress argv must contain TWO literal "--" separators:
	//   1st "--": ends bwrap option parsing (before bootstrap path)
	//   2nd "--": bootstrap's own arg separator (before the real server)
	// Ordering assertion: first "--" < bootstrap (as cmd) < last "--" < server.
	//
	// Note: the mount args also contain "/usr/local/bin/bootstrap" and
	// "/app/server" as --ro-bind values; lastIndexOf finds the last occurrence
	// of each, which is the entrypoint/server position (after the 1st "--").
	var sepIndices []int
	for i, v := range args {
		if v == "--" {
			sepIndices = append(sepIndices, i)
		}
	}
	if len(sepIndices) < 2 {
		t.Fatalf("expected at least two '--' in egress argv (got %d); args=%v", len(sepIndices), args)
	}
	firstSep := sepIndices[0]
	lastSep := sepIndices[len(sepIndices)-1]
	idxBoot := lastIndexOf(args, "/usr/local/bin/bootstrap")
	idxServer := lastIndexOf(args, "/app/server")
	if idxBoot == -1 || idxServer == -1 {
		t.Fatalf("bootstrap or server path not found in egress argv; args=%v", args)
	}
	// first "--" < bootstrap (entrypoint) < last "--" < server
	if !(firstSep < idxBoot && idxBoot < lastSep && lastSep < idxServer) {
		t.Fatalf("expected: first '--' (%d) < bootstrap (%d) < last '--' (%d) < server (%d); args=%v",
			firstSep, idxBoot, lastSep, idxServer, args)
	}
	// info-fd must be present; --uid/--gid are NOT passed to bwrap because the
	// bootstrap must run as uid 0 in the user namespace to hold CAP_NET_ADMIN for
	// network configuration. Bootstrap itself does setuid(65534)/setgid(65534)
	// before exec'ing the untrusted server.
	if hasPair(args, "--uid", "65534") || hasPair(args, "--gid", "65534") {
		t.Error("egress mode must NOT pass --uid/--gid 65534 to bwrap (bootstrap needs uid 0 for NET_ADMIN)")
	}
	if !hasPair(args, "--info-fd", "5") {
		t.Error("egress mode must pass --info-fd")
	}
	// Env vars must be emitted as --setenv K V triples inside the sandbox (not cmd.Env,
	// which is wiped by --clearenv).
	if !hasTriple(args, "--setenv", "HTTPS_PROXY", "http://10.88.0.1:8081") {
		t.Error("egress mode missing --setenv HTTPS_PROXY http://10.88.0.1:8081")
	}
	if !hasTriple(args, "--setenv", "GIG_PLACEHOLDER", "PLACEHOLDER") {
		t.Error("egress mode missing --setenv GIG_PLACEHOLDER PLACEHOLDER")
	}
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func lastIndexOf(s []string, v string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == v {
			return i
		}
	}
	return -1
}

func hasPair(s []string, flag, val string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == flag && s[i+1] == val {
			return true
		}
	}
	return false
}

func hasTriple(s []string, flag, key, val string) bool {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == flag && s[i+1] == key && s[i+2] == val {
			return true
		}
	}
	return false
}

func indexOfPair(s []string, flag, a, b string) int {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == flag && s[i+1] == a && s[i+2] == b {
			return i
		}
	}
	return -1
}
