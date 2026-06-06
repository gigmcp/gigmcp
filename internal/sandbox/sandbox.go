// Package sandbox builds bubblewrap commands that run untrusted MCP servers
// in fresh user/pid/net/mount/ipc/uts/cgroup namespaces with a read-only view of
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
// --proc /proc mounts a fresh procfs inside the sandbox's new PID namespace,
// so the sandboxed process sees only its own process tree and never the host's.
// This requires that Docker's /proc masks are removed; run the dev container
// with --security-opt systempaths=unconfined (see Makefile test target).
func Command(spec Spec) *exec.Cmd {
	args := []string{
		"--die-with-parent", // no orphaned servers if the gateway dies
		// --new-session blocks TIOCSTI terminal-injection from sandboxed code.
		"--new-session",
		"--unshare-all", // user, pid, net, mount, ipc, uts, cgroup
		"--clearenv",
		"--setenv", "PATH", "/usr/bin:/bin",
	}

	// Caller mounts come first so that the fixed isolation mounts below
	// can override them on path collisions.
	for _, m := range spec.Mounts {
		flag := "--ro-bind"
		if m.Optional {
			flag = "--ro-bind-try"
		}
		args = append(args, flag, m.Src, m.Dst)
	}

	// Fixed isolation mounts come AFTER caller mounts so they always win on path collisions (bwrap applies mounts last-one-wins).
	args = append(args,
		"--proc", "/proc", // fresh procfs — sandbox sees only its own pid namespace
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--chdir", "/",
	)

	// -- ends bwrap option parsing; Exec is always treated as the command.
	args = append(args, "--")
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
