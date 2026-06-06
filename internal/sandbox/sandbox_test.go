package sandbox_test

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gigemcp/gigemcp/internal/sandbox"
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
	secret, err := os.CreateTemp(".", "gige-canary-*.txt")
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
	t.Setenv("GIGE_SECRET_CANARY", "leak")
	out, err := runShell(t, "env")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "GIGE_SECRET_CANARY") {
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

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func indexOfPair(s []string, flag, a, b string) int {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == flag && s[i+1] == a && s[i+2] == b {
			return i
		}
	}
	return -1
}
