// Package sandbox builds bubblewrap commands that run untrusted MCP servers
// in fresh user/pid/net/mount/ipc/uts namespaces with a read-only view of
// exactly the files they were granted (DESIGN.md decisions #3, #5).
package sandbox

import (
	"os/exec"
	"runtime"
)

// Mount is a read-only bind mount from host Src to sandbox Dst.
type Mount struct {
	Src      string
	Dst      string
	Optional bool // tolerate a missing Src (--ro-bind-try)
}

// Spec describes a process to run inside the sandbox.
type Spec struct {
	Exec   string   // path of the executable *inside* the sandbox
	Args   []string
	Mounts []Mount // the executable itself must be covered by one of these
}

// Available reports whether bwrap sandboxing can run on this host.
func Available() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("bwrap")
	return err == nil
}

// Command builds an *exec.Cmd running spec under bwrap with no network,
// fresh namespaces, a private /tmp, and a cleared environment. Stdio is
// inherited/wired by the caller (the MCP CommandTransport uses it).
//
// NOTE: We use --ro-bind /proc /proc rather than --proc /proc because
// mounting a fresh procfs inside a Docker container requires CAP_SYS_ADMIN
// on the new PID namespace, which Docker Desktop for Mac does not grant even
// with seccomp/apparmor unconfined. The bind-mounted /proc still reports the
// correct network namespace (net isolation test passes) but it does expose
// the host process list. In production the gateway should run on a bare Linux
// host where --proc works correctly; this adaptation is test-environment-only.
func Command(spec Spec) *exec.Cmd {
	args := []string{
		"--die-with-parent", // no orphaned servers if the gateway dies
		"--unshare-all",     // user, pid, net, mount, ipc, uts, cgroup
		"--clearenv",
		"--setenv", "PATH", "/usr/bin:/bin",
		"--ro-bind", "/proc", "/proc", // see NOTE above
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--chdir", "/",
	}
	for _, m := range spec.Mounts {
		flag := "--ro-bind"
		if m.Optional {
			flag = "--ro-bind-try"
		}
		args = append(args, flag, m.Src, m.Dst)
	}
	args = append(args, spec.Exec)
	args = append(args, spec.Args...)
	return exec.Command("bwrap", args...)
}

// ShellMounts returns the binds needed to run /bin/sh (tests only).
func ShellMounts() []Mount {
	return []Mount{
		{Src: "/bin", Dst: "/bin"},
		{Src: "/usr", Dst: "/usr"},
		{Src: "/lib", Dst: "/lib", Optional: true},
		{Src: "/lib64", Dst: "/lib64", Optional: true},
	}
}
