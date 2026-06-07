//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/sandbox"
)

// TestCapDropDeterministic builds the bootstrap binary, runs it 10 times with
// GIG_CAPTEST=1, and asserts that every iteration exits with all-zero caps
// and NoNewPrivs=1.  This exercises the LockOSThread + [2]CapUserData fixes:
// without them the test is either flaky (wrong thread) or leaves CapInh/CapBnd
// non-zero.
func TestCapDropDeterministic(t *testing.T) {
	if !sandbox.Available() {
		t.Skip("bwrap not available; skipping cap-drop test")
	}
	if os.Geteuid() != 0 {
		t.Skip("cap-drop test must run as root (needs CAP_SETPCAP etc.)")
	}

	// Build the bootstrap binary into a temp dir.
	dir := t.TempDir()
	binPath := filepath.Join(dir, "bootstrap")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	// Fields we must see in /proc/self/status output from the exec'd cat.
	wantZero := []string{
		"CapEff:\t0000000000000000",
		"CapPrm:\t0000000000000000",
		"CapInh:\t0000000000000000",
		"CapBnd:\t0000000000000000",
		"CapAmb:\t0000000000000000",
	}
	wantNNP := "NoNewPrivs:\t1"
	// All four uid fields (real, effective, saved, filesystem) must be 65534.
	wantUID := "Uid:\t65534\t65534\t65534\t65534"
	wantGID := "Gid:\t65534\t65534\t65534\t65534"

	for i := 0; i < 10; i++ {
		cmd := exec.Command(binPath)
		cmd.Env = append(os.Environ(), "GIG_CAPTEST=1")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("iteration %d: bootstrap exited with error: %v\nstdout:\n%s", i, err, out)
		}
		status := string(out)

		for _, want := range wantZero {
			if !strings.Contains(status, want) {
				t.Errorf("iteration %d: missing %q in /proc/self/status:\n%s", i, want, status)
			}
		}
		if !strings.Contains(status, wantNNP) {
			t.Errorf("iteration %d: missing %q in /proc/self/status:\n%s", i, wantNNP, status)
		}
		if !strings.Contains(status, wantUID) {
			t.Errorf("iteration %d: missing %q in /proc/self/status:\n%s", i, wantUID, status)
		}
		if !strings.Contains(status, wantGID) {
			t.Errorf("iteration %d: missing %q in /proc/self/status:\n%s", i, wantGID, status)
		}
	}
}
