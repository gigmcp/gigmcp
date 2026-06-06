// Package sandbox builds bubblewrap commands that run untrusted MCP servers
// in fresh user/pid/net/mount/ipc/uts/cgroup namespaces with a read-only view of
// exactly the files they were granted (DESIGN.md decisions #3, #5).
// Landlock, per-sandbox seccomp, and cgroup limits are deferred to the
// hardening plan (DESIGN.md §5 item 7); this skeleton relies on namespaces,
// --clearenv, read-only binds, and a private procfs.
package sandbox

import (
	"os/exec"
	"runtime"
	"strconv"
)

// Mount is a read-only bind mount from host Src to sandbox Dst.
type Mount struct {
	Src      string
	Dst      string
	Optional bool // tolerate a missing Src (--ro-bind-try)
}

// Egress configures network egress for a sandbox. When set, bwrap creates a
// network namespace (the gateway then injects a veth into the bwrap child by
// PID), the cmd/bootstrap entrypoint configures the link + default route via
// the proxy and drops all caps before exec'ing Exec. See DESIGN.md decision #13.
type Egress struct {
	BootstrapPath string // host path to the bootstrap binary (mounted into the sandbox)
	SandboxCIDR   string // e.g. "10.88.0.2/30"
	ProxyIP       string // default route / proxy host-side IP
	PeerVeth      string // injected interface name inside the netns
	InfoFD        int    // bwrap --info-fd target (gateway reads child PID from it)
}

// Spec describes a process to run inside the sandbox.
type Spec struct {
	Exec   string   // path of the executable *inside* the sandbox
	Args   []string
	Mounts []Mount  // the executable itself must be covered by one of these
	Egress *Egress  // if non-nil, enable egress mode (bootstrap entrypoint, veth netns)
}

// Available reports whether bwrap sandboxing can run on this host.
func Available() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("bwrap")
	return err == nil
}

// Command builds an *exec.Cmd running spec under bwrap. If spec.Egress is nil
// the sandbox has no network access (original behaviour). If spec.Egress is
// set, bwrap creates a dedicated network namespace and the cmd/bootstrap binary
// runs as the entrypoint, configuring the veth + default route and dropping all
// capabilities before exec'ing the real server.
//
// --proc /proc mounts a fresh procfs inside the sandbox's new PID namespace,
// so the sandboxed process sees only its own process tree and never the host's.
// This requires that Docker's /proc masks are removed; run the dev container
// with --security-opt systempaths=unconfined (see Makefile test target).
func Command(spec Spec) *exec.Cmd {
	if spec.Egress == nil {
		return commandNoNet(spec)
	}
	return commandEgress(spec)
}

// commandNoNet is the original no-network implementation, unchanged.
func commandNoNet(spec Spec) *exec.Cmd {
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

// commandEgress builds bwrap argv for the egress-enabled path. It uses
// decomposed unshare flags (keeping --unshare-net so bwrap creates the netns),
// sets uid/gid to 65534, passes --info-fd for child-PID discovery, and uses
// the bootstrap binary as the entrypoint with the real server after a literal --.
func commandEgress(spec Spec) *exec.Cmd {
	e := spec.Egress
	args := []string{
		"--die-with-parent",
		"--new-session",
		// Decomposed: KEEP --unshare-net (bwrap creates the netns); drop --unshare-all.
		"--unshare-user", "--unshare-net", "--unshare-pid",
		"--unshare-ipc", "--unshare-uts", "--unshare-cgroup",
		"--uid", "65534", "--gid", "65534",
		"--info-fd", strconv.Itoa(e.InfoFD),
		"--clearenv",
		"--setenv", "PATH", "/usr/bin:/bin",
	}

	// Caller mounts first so fixed isolation mounts win on collision.
	for _, m := range spec.Mounts {
		flag := "--ro-bind"
		if m.Optional {
			flag = "--ro-bind-try"
		}
		args = append(args, flag, m.Src, m.Dst)
	}

	// The bootstrap binary itself must be mounted in.
	args = append(args, "--ro-bind", e.BootstrapPath, e.BootstrapPath)

	// Fixed isolation mounts.
	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--chdir", "/",
	)

	// Bootstrap is the entrypoint; the real server follows after --.
	args = append(args, e.BootstrapPath, e.SandboxCIDR, e.ProxyIP, e.PeerVeth, "--", spec.Exec)
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
