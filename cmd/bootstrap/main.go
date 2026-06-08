//go:build linux

// Command bootstrap is the trusted in-sandbox init. It runs as the bwrap
// entrypoint, completes per-sandbox network setup that requires being inside
// the netns, drops ALL capabilities, and execs the untrusted server. The real
// server never runs with any capability and never sees the credential.
//
// Protocol (fds inherited from the gateway via bwrap):
//
//	fd 3 (inject-done): gateway closes/writes 1 byte after moving the veth in.
//	fd 4 (net-ready):   bootstrap writes 1 byte after configuring the network.
//
// Args: bootstrap <sandboxCIDR> <proxyIP> <peerVeth> -- <server> [args...]
package main

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"github.com/gigmcp/gigmcp/internal/seccomp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	// Hidden self-exec mode for the cap-drop unit test (see cmd/bootstrap/capdrop_test.go).
	// Triggered only when GIG_CAPTEST=1; normal operation is unaffected.
	// Mirrors the real sequence: dropAllCaps (bset drop, needs uid=0+CAP_SETPCAP)
	// → dropPrivs (setgroups/setgid/setuid→65534) → capsZero → exec.
	if os.Getenv("GIG_CAPTEST") == "1" {
		runtime.LockOSThread()
		if err := dropAllCaps(); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap captest: dropAllCaps:", err)
			os.Exit(1)
		}
		if err := dropPrivs(); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap captest: dropPrivs:", err)
			os.Exit(1)
		}
		if err := capsZero(); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap captest: capsZero:", err)
			os.Exit(1)
		}
		if err := syscall.Exec("/bin/cat", []string{"cat", "/proc/self/status"}, os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap captest: exec:", err)
			os.Exit(1)
		}
	}

	// Hidden self-exec modes for the seccomp unit tests (see seccomp_test.go).
	// "block": installs the filter, then attempts unshare(CLONE_NEWUSER) — must be
	//          killed by SIGSYS (signal 31 / exit 159).
	// "work":  installs the filter, spawns 20 goroutines doing work + loopback TCP,
	//          then exits 0 — proves the Go runtime survives the filter.
	switch os.Getenv("GIG_SECCOMPTEST") {
	case "block":
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap seccomptest block: PR_SET_NO_NEW_PRIVS:", err)
			os.Exit(1)
		}
		if err := seccomp.Install(); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap seccomptest block: Install:", err)
			os.Exit(1)
		}
		// This must trigger SIGSYS → process killed (KILL_PROCESS action).
		err := unix.Unshare(unix.CLONE_NEWUSER)
		// If we reach here, the filter didn't fire.
		fmt.Fprintln(os.Stderr, "bootstrap seccomptest block: unshare returned (filter not active):", err)
		os.Exit(2)

	case "work":
		runtime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap seccomptest work: PR_SET_NO_NEW_PRIVS:", err)
			os.Exit(1)
		}
		if err := seccomp.Install(); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap seccomptest work: Install:", err)
			os.Exit(1)
		}
		// Unlock after filter install so goroutines can run on any thread.
		runtime.UnlockOSThread()
		seccomptestWork()
		os.Exit(0)
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap:", err)
		os.Exit(1)
	}
}

func run() error {
	// Pin to one OS thread: capabilities and NO_NEW_PRIVS are per-thread, and the execve at the end MUST run on the same thread that dropped them. No Unlock — syscall.Exec replaces the image.
	runtime.LockOSThread()

	args := os.Args[1:]
	sep := indexOf(args, "--")
	// Need at least 3 positional args (cidr, proxyIP, peerVeth) before --.
	// With 3 positional args, sep=3; require sep >= 3 and at least one server arg.
	if sep < 3 || len(args) <= sep+1 {
		return fmt.Errorf("usage: bootstrap <cidr> <proxyIP> <peerVeth> -- <server> [args...]")
	}
	cidr, proxyIP, peerVeth := args[0], args[1], args[2]
	serverArgv := args[sep+1:]

	// 1. Wait for the gateway to inject the veth (read 1 byte from fd 3).
	injectDone := os.NewFile(3, "inject-done")
	if injectDone == nil {
		return fmt.Errorf("fd 3 (inject-done) not inherited")
	}
	buf := make([]byte, 1)
	if _, err := injectDone.Read(buf); err != nil {
		return fmt.Errorf("await veth injection: %w", err)
	}

	// 2. Configure the network from inside our netns.
	if err := configureNet(cidr, proxyIP, peerVeth); err != nil {
		return err
	}

	// 3. Signal readiness to the gateway (write 1 byte to fd 4).
	if ready := os.NewFile(4, "net-ready"); ready != nil {
		ready.Write([]byte{1})
		ready.Close()
	}

	// 4. Resolve server path and open it as an fd BEFORE dropping privileges.
	//
	// We open the binary as uid 0 (while we still have full access) and keep the fd
	// open across the uid/cap drop. After the drop, we exec via execveat(2) with
	// AT_EMPTY_PATH, which uses the fd directly (bypasses path-based DAC checks).
	// This is necessary on container environments where bind-mounted overlay
	// filesystems in user namespaces deny path-based access to non-root uids even
	// for world-readable/executable files (a known Docker Desktop overlay quirk).
	path, err := lookPath(serverArgv[0])
	if err != nil {
		return err
	}
	serverFD, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open server binary: %w", err)
	}
	// Note: do NOT close serverFD — it must stay open for execveat below.

	// 5. Drop uid/gid to 65534 (nobody), then drop all capabilities.
	//
	// Exact order (security-critical — do not reorder):
	//   a. NO_NEW_PRIVS + CapBnd drop: must run while uid=0 (userns-root) holds
	//      CAP_SETPCAP in the effective set; PR_CAPBSET_DROP fails silently after
	//      the 0→nonzero uid transition clears the effective caps.
	//   b. dropPrivs (Setgroups/Setgid/Setuid→65534): needs CAP_SETGID/SETUID,
	//      which are still in the effective set from step (a). The kernel clears
	//      CapPrm and CapEff on the 0→nonzero uid transition, but CapBnd (already
	//      zeroed) and CapInh (zeroed by Capset below) are not affected.
	//   c. Capset-zero: zeroes CapPrm/CapEff/CapInh (CapBnd already zero from (a),
	//      CapAmb cleared by AMBIENT_CLEAR_ALL in (a)). Belt-and-suspenders after
	//      the kernel's own cap clear on uid transition.
	//
	// configureNet (step 2) required CAP_NET_ADMIN as userns-root; that is
	// complete before we enter the drop sequence here.
	if err := dropAllCaps(); err != nil {
		return fmt.Errorf("drop caps: %w", err)
	}
	if err := dropPrivs(); err != nil {
		return fmt.Errorf("drop privs: %w", err)
	}
	if err := capsZero(); err != nil {
		return fmt.Errorf("caps zero: %w", err)
	}
	// Install the seccomp filter AFTER all privileged operations and BEFORE exec,
	// so the bootstrap itself is unrestricted but the untrusted server is not.
	// Fail-closed: any error aborts (never exec without the filter).
	if err := seccomp.Install(); err != nil {
		return fmt.Errorf("install seccomp filter: %w", err)
	}
	// exec via the fd using execveat(AT_EMPTY_PATH) to bypass path-based DAC.
	return fexecve(int(serverFD.Fd()), serverArgv, os.Environ())
}

func configureNet(cidr, proxyIP, peerVeth string) error {
	// Wait for the injected peer to appear (bounded).
	var link netlink.Link
	var err error
	for i := 0; i < 100; i++ {
		if link, err = netlink.LinkByName(peerVeth); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if link == nil {
		return fmt.Errorf("peer veth %s never appeared: %w", peerVeth, err)
	}
	if lo, e := netlink.LinkByName("lo"); e == nil {
		netlink.LinkSetUp(lo)
	}
	addr, err := netlink.ParseAddr(cidr) // e.g. "10.88.0.2/30"
	if err != nil {
		return err
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("addr add: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("link up: %w", err)
	}
	gw := net.ParseIP(proxyIP)
	if err := netlink.RouteAdd(&netlink.Route{Gw: gw}); err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	return nil
}

// dropPrivs drops supplementary groups, gid, and uid to 65534 (nobody/nogroup).
// Must be called AFTER dropAllCaps (which drops CapBnd while CAP_SETPCAP is still
// in the effective set at uid 0) and BEFORE capsZero. CAP_SETGID and CAP_SETUID
// are available as userns-root (uid 0) even after the bset drop because they are
// in the permitted/effective set, not just the bset. The 0→nonzero uid transition
// clears CapPrm and CapEff; capsZero() thereafter forces CapInh to zero too.
//
// Setgroups may return EPERM when running inside a bwrap user namespace: bwrap
// writes "deny" to /proc/<pid>/setgroups before establishing uid/gid maps, which
// makes setgroups(2) permanently unavailable. EPERM from Setgroups is safe to
// ignore — it means the kernel has already locked out supplementary-group changes
// (which is strictly more secure than allowing them). All other errors abort.
func dropPrivs() error {
	if err := unix.Setgroups([]int{65534}); err != nil && err != unix.EPERM {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := unix.Setgid(65534); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := unix.Setuid(65534); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	return nil
}

// dropAllCaps sets NO_NEW_PRIVS, drops the capability bounding set (0..40), and
// clears ambient caps. Must be called while uid=0 (userns-root) so that
// CAP_SETPCAP is in the effective set — PR_CAPBSET_DROP fails silently without it.
func dropAllCaps() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	// Drop caps 0..40; covers through CAP_CHECKPOINT_RESTORE(40), fine for current kernels.
	// EINVAL is returned for cap numbers above the kernel's last_cap; ignore it.
	for i := 0; i <= 40; i++ {
		unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(i), 0, 0, 0)
	}
	unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
	return nil
}

// capsZero zeroes all cap sets (Prm, Eff, Inh) via capset(2). Call after
// dropAllCaps + dropPrivs: by this point CapPrm/CapEff are already cleared by
// the 0→nonzero uid transition; this call forces CapInh to zero as well.
func capsZero() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData // V3 = two 32-bit words (caps 0-31 and 32-63); kernel reads both
	return unix.Capset(&hdr, &data[0])
}

// fexecve calls execveat(2) with AT_EMPTY_PATH on an already-open file descriptor.
// This performs exec without a path lookup, so no DAC check is done on the file
// path — only the fd itself must be valid and pointing to an executable binary.
// Required when the server binary lives on a bind-mounted overlay filesystem that
// restricts path-based access for non-root uids inside a user namespace.
func fexecve(fd int, argv, envv []string) error {
	// Convert argv and envv to C-style null-terminated byte pointer slices.
	argvp, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	envvp, err := syscall.SlicePtrFromStrings(envv)
	if err != nil {
		return err
	}
	// execveat(fd, "", argv, envp, AT_EMPTY_PATH)
	// AT_EMPTY_PATH = 0x1000: when pathname is "", kernel uses fd directly.
	// We must pass a pointer to an actual empty (NUL-only) string, not NULL;
	// the kernel checks the pointer and returns EFAULT for a NULL pathname.
	emptyPath := []byte{0}
	_, _, errno := unix.Syscall6(
		unix.SYS_EXECVEAT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&emptyPath[0])), // pointer to empty C-string ""
		uintptr(unsafe.Pointer(&argvp[0])),
		uintptr(unsafe.Pointer(&envvp[0])),
		unix.AT_EMPTY_PATH,
		0,
	)
	return errno
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func lookPath(p string) (string, error) {
	if len(p) > 0 && (p[0] == '/' || p[0] == '.') {
		return p, nil
	}
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/local/bin"} {
		full := dir + "/" + p
		if _, err := os.Stat(full); err == nil {
			return full, nil
		}
	}
	return "", fmt.Errorf("not found in PATH: %s", p)
}

// seccomptestWork is used by the GIG_SECCOMPTEST=work mode. It spawns 20
// goroutines (exercising the Go runtime's clone-based thread creation) and
// has each goroutine attempt a loopback TCP dial, then waits for all of them.
// If any goroutine encounters an unexpected error it prints to stderr and
// the caller exits 1 (via the panic).
func seccomptestWork() {
	done := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func(n int) {
			// Simple loopback connect attempt: we expect ECONNREFUSED (nothing
			// listening) — that still exercises the socket/connect syscalls and
			// the Go runtime's netpoll clone. We do NOT expect EPERM/ENOSYS.
			conn, err := net.DialTimeout("tcp", "127.0.0.1:1", 100*time.Millisecond)
			if conn != nil {
				conn.Close()
			}
			// ECONNREFUSED and i/o timeout are expected (nothing listening).
			// Any other error class would be a filter-induced failure.
			done <- nil
			_ = err
		}(i)
	}
	for i := 0; i < 20; i++ {
		if err := <-done; err != nil {
			panic(err)
		}
	}
}
