package sandbox_test

import (
	"os"
	"path/filepath"
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
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("key-material"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The host path is not bind-mounted, so reading it must fail.
	if _, err := runShell(t, "cat "+secret); err == nil {
		t.Fatal("sandbox could read an unmounted host file")
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
