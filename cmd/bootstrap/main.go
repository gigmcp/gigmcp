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

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	// Hidden self-exec mode for the cap-drop unit test (see cmd/bootstrap/capdrop_test.go).
	// Triggered only when GIGE_CAPTEST=1; normal operation is unaffected.
	if os.Getenv("GIGE_CAPTEST") == "1" {
		runtime.LockOSThread()
		if err := dropAllCaps(); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap captest: dropAllCaps:", err)
			os.Exit(1)
		}
		if err := syscall.Exec("/bin/cat", []string{"cat", "/proc/self/status"}, os.Environ()); err != nil {
			fmt.Fprintln(os.Stderr, "bootstrap captest: exec:", err)
			os.Exit(1)
		}
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

	// 4. Resolve server path BEFORE dropping caps so os.Stat is not a
	// goroutine-migration point between the cap-drop and execve.
	path, err := lookPath(serverArgv[0])
	if err != nil {
		return err
	}

	// 5. Drop all capabilities, then exec the untrusted server.
	// bwrap creates a user namespace where bootstrap runs as uid 0 (to hold
	// CAP_NET_ADMIN for network config). After the capability drop, the server
	// runs with no capabilities. The uid inside the user namespace is 0, which
	// maps to an unprivileged uid in the parent namespace (no real host root).
	// Nothing between the drop and Exec except the syscall itself.
	if err := dropAllCaps(); err != nil {
		return fmt.Errorf("drop caps: %w", err)
	}
	return syscall.Exec(path, serverArgv, os.Environ())
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

func dropAllCaps() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	// Drop caps 0..40; covers through CAP_CHECKPOINT_RESTORE(40), fine for current kernels.
	for i := 0; i <= 40; i++ {
		// Ignore EINVAL for caps above the kernel max.
		unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(i), 0, 0, 0)
	}
	unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData // V3 = two 32-bit words (caps 0-31 and 32-63); kernel reads both
	return unix.Capset(&hdr, &data[0])
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
