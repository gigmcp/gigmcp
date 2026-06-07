//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/gigemcp/gigemcp/internal/sandbox"
)

// buildBootstrap compiles the bootstrap binary into dir and returns its path.
// CGO_ENABLED=0 to match production builds.
func buildBootstrap(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	binPath := filepath.Join(dir, "bootstrap")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build bootstrap failed: %v\n%s", err, out)
	}
	return binPath
}

// TestSeccompBlocksUnshare verifies that the seccomp filter kills the process
// with SIGSYS (signal 31, exit code 159) when unshare(CLONE_NEWUSER) is called.
// This proves the nested-user-namespace escape is closed decisively.
func TestSeccompBlocksUnshare(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("bwrap not available; skipping seccomp block test")
	}
	if os.Geteuid() != 0 {
		t.Skip("seccomp block test must run as root (needs PR_SET_NO_NEW_PRIVS from uid=0)")
	}

	binPath := buildBootstrap(t)

	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), "GIGE_SECCOMPTEST=block")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected bootstrap to be killed, but it exited 0")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected *exec.ExitError, got %T: %v", err, err)
	}

	ws, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok {
		t.Fatalf("could not get WaitStatus from ExitError")
	}

	// The process should be killed by SIGSYS (31) — seccomp KILL_PROCESS action.
	// On Linux, WaitStatus.Signaled() is true and Signal() == syscall.SIGSYS.
	// The shell exit code is 128+31 = 159.
	if ws.Signaled() && ws.Signal() == syscall.SIGSYS {
		t.Logf("PASS: process killed by SIGSYS (seccomp KILL_PROCESS) as expected")
		return
	}
	// Some kernels/Docker setups may deliver the kill as a non-zero exit without
	// signal info. Accept exit code 159 as well.
	if !ws.Signaled() && ws.ExitStatus() == 159 {
		t.Logf("PASS: exit code 159 (128+SIGSYS) indicates seccomp kill")
		return
	}
	t.Errorf("expected SIGSYS kill (signal=31 or exit=159), got: signaled=%v signal=%v exitCode=%v",
		ws.Signaled(), ws.Signal(), ws.ExitStatus())
}

// TestSeccompAllowsNormalWork verifies that the seccomp filter does NOT break
// the Go runtime (which uses clone for OS threads) or basic networking. The
// "work" mode spawns 20 goroutines and does loopback TCP dials. Exit 0 = pass.
func TestSeccompAllowsNormalWork(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("bwrap not available; skipping seccomp work test")
	}
	if os.Geteuid() != 0 {
		t.Skip("seccomp work test must run as root")
	}

	binPath := buildBootstrap(t)

	cmd := exec.Command(binPath)
	cmd.Env = append(os.Environ(), "GIGE_SECCOMPTEST=work")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit 0, got error: %v\noutput:\n%s", err, out)
	}
	t.Logf("PASS: bootstrap GIGE_SECCOMPTEST=work exited 0")
}
