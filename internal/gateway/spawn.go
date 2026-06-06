package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gigemcp/gigemcp/internal/netmgr"
	"github.com/gigemcp/gigemcp/internal/proxy"
	"github.com/gigemcp/gigemcp/internal/sandbox"
	"github.com/gigemcp/gigemcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// writeUIDGIDMaps writes uid_map and gid_map for the given child PID so that the
// bwrap sandbox has access to uids 0..65534.
//
// Why a range of 65535: bwrap's --uid flag creates a single-entry uid_map (0→X, count=1),
// making setuid(65534) inside the sandbox impossible because that uid is not mapped.
// By omitting --uid/--gid from the bwrap command and writing the maps ourselves here,
// we can create a range that covers both uid 0 (bootstrap needs userns-root with
// CAP_NET_ADMIN for veth setup) and uid 65534 (nobody, for the server process after
// bootstrap drops privileges). Bind-mounted files owned by uid 0 in the host remain
// readable/executable by uid 65534 inside the sandbox (0755 mode, "other" bits apply).
//
// Must be called after reading the child PID from bwrap --info-fd and BEFORE closing
// the userns-block-fd (which unblocks the child). Requires the caller to be root (uid 0
// in the parent user namespace) or to hold CAP_SETUID/CAP_SETGID in that namespace.
func writeUIDGIDMaps(childPID int) error {
	// "deny" must be written to setgroups BEFORE writing gid_map (kernel requirement
	// for user namespaces when the caller is in a user namespace: prevents group-based
	// privilege escalation). In our case the caller is container/host root so it would
	// succeed anyway, but writing "deny" is belt-and-suspenders.
	sgPath := fmt.Sprintf("/proc/%d/setgroups", childPID)
	if err := os.WriteFile(sgPath, []byte("deny"), 0); err != nil {
		return fmt.Errorf("write setgroups: %w", err)
	}
	// Map uids 0..65534 (count=65535): inside-uid → outside-uid.
	// The parent process (gateway) runs as uid 0, which maps to uid 0 in the child.
	// Format: <child-start-uid> <parent-start-uid> <count>
	uidMap := "0 0 65535\n"
	uidPath := fmt.Sprintf("/proc/%d/uid_map", childPID)
	if err := os.WriteFile(uidPath, []byte(uidMap), 0); err != nil {
		return fmt.Errorf("write uid_map: %w", err)
	}
	gidPath := fmt.Sprintf("/proc/%d/gid_map", childPID)
	if err := os.WriteFile(gidPath, []byte(uidMap), 0); err != nil {
		return fmt.Errorf("write gid_map: %w", err)
	}
	return nil
}

// EgressBackend is returned by SpawnEgressBackend and groups the connected MCP
// session, the sandbox payload PID, and a cleanup function.
//
// ChildPID is the PID (in the caller's namespace) of the process that is
// running the sandboxed server (bootstrap exec'd into the real server via
// fexecve). It is the GRANDCHILD of the bwrap supervisor: bwrap forks an
// intermediate child (the bwrap --info-fd "child-pid"), which in turn forks
// the actual payload (the sandbox init, PID 1 inside the new PID namespace).
// ChildPID points to the payload so /proc/<ChildPID>/environ reflects the
// server's environment (with --setenv vars and without the real credential).
type EgressBackend struct {
	Session  *mcp.ClientSession
	ChildPID int
	Cleanup  func()
}

// sandboxPayloadPID returns the PID of the actual sandboxed payload process
// (the first child of bwrapChildPID in the host namespace). bwrap with
// --unshare-pid forks an intermediate "supervisor" child (bwrapChildPID),
// which in turn forks the real sandbox init (the payload). Reading
// /proc/<bwrapChildPID>/task/<bwrapChildPID>/children gives the list of
// children of the intermediate child.
//
// We retry briefly because the intermediate child may not have forked the
// payload immediately when we read.
func sandboxPayloadPID(bwrapChildPID int) (int, error) {
	childrenPath := fmt.Sprintf("/proc/%d/task/%d/children", bwrapChildPID, bwrapChildPID)
	for i := 0; i < 20; i++ {
		raw, err := os.ReadFile(childrenPath)
		if err != nil {
			return 0, fmt.Errorf("read children of pid %d: %w", bwrapChildPID, err)
		}
		fields := strings.Fields(string(raw))
		if len(fields) > 0 {
			pid, err := strconv.Atoi(fields[0])
			if err != nil {
				return 0, fmt.Errorf("parse child pid %q: %w", fields[0], err)
			}
			return pid, nil
		}
		// Child not yet forked; wait briefly.
		time.Sleep(10 * time.Millisecond)
	}
	return 0, fmt.Errorf("no child found for pid %d after retries", bwrapChildPID)
}

// SpawnEgressBackend launches one MCP server in an egress-isolated sandbox and
// returns an EgressBackend with the connected MCP client session, the sandbox
// child PID, and a cleanup function.
//
// Pipe protocol:
//   - r3/w3: inject-done  — gateway writes 1 byte after veth injection (bootstrap reads fd 3)
//   - r4/w4: net-ready    — bootstrap writes 1 byte after configuring the network (gateway reads fd 4)
//   - rInfo/wInfo: bwrap --info-fd — gateway reads child PID (bwrap writes to fd 5)
//
// The sandbox's default route goes to sub.HostIP (the /30 host side), so the
// proxy must be listening on 0.0.0.0:<proxyPort>; every per-sandbox veth
// address is reachable from it. HTTPS_PROXY is set to http://<hostIP>:<proxyPort>.
func SpawnEgressBackend(
	ctx context.Context,
	srv store.Server,
	alloc *netmgr.Allocator,
	reg *proxy.Registry,
	proxyPort int,
	caFile string,
	bootstrapPath string,
) (*EgressBackend, error) {
	sub, err := alloc.Allocate()
	if err != nil {
		return nil, fmt.Errorf("allocate subnet: %w", err)
	}
	proxyIP := sub.HostIP.String()

	// Create handshake pipes.
	r3, w3, err := os.Pipe() // inject-done: gateway → bootstrap (fd3 in child)
	if err != nil {
		alloc.Free(sub)
		return nil, fmt.Errorf("pipe inject-done: %w", err)
	}
	r4, w4, err := os.Pipe() // net-ready: bootstrap → gateway (fd4 in child)
	if err != nil {
		r3.Close()
		w3.Close()
		alloc.Free(sub)
		return nil, fmt.Errorf("pipe net-ready: %w", err)
	}
	rInfo, wInfo, err := os.Pipe() // bwrap --info-fd (fd5 in child)
	if err != nil {
		r3.Close()
		w3.Close()
		r4.Close()
		w4.Close()
		alloc.Free(sub)
		return nil, fmt.Errorf("pipe info-fd: %w", err)
	}
	// userns-block: gateway closes rBlock after writing uid/gid maps, which
	// unblocks the bwrap child to begin executing. The child holds rBlock (fd6)
	// and blocks until it becomes readable (EOF from close of rBlock by us).
	rBlock, wBlock, err := os.Pipe() // bwrap --userns-block-fd (fd6 in child)
	if err != nil {
		r3.Close()
		w3.Close()
		r4.Close()
		w4.Close()
		rInfo.Close()
		wInfo.Close()
		alloc.Free(sub)
		return nil, fmt.Errorf("pipe userns-block: %w", err)
	}

	spec := sandbox.Spec{
		Exec: "/app/server",
		Mounts: []sandbox.Mount{
			{Src: srv.Binary, Dst: "/app/server"},
			{Src: caFile, Dst: "/etc/gigemcp-ca.pem"},
		},
		Egress: &sandbox.Egress{
			BootstrapPath: bootstrapPath,
			SandboxCIDR:   fmt.Sprintf("%s/30", sub.SandboxIP),
			ProxyIP:       proxyIP,
			PeerVeth:      sub.PeerVeth,
			InfoFD:        5, // child fd 5 = ExtraFiles[2] = wInfo
			UsernsBlockFD: 6, // child fd 6 = ExtraFiles[3] = rBlock
			// These vars must reach the server INSIDE the sandbox.
			// cmd.Env is useless here because bwrap uses --clearenv;
			// they are emitted as --setenv K V flags by commandEgress.
			// None of these are secrets: proxy URL, CA path, placeholder.
			Env: map[string]string{
				"HTTPS_PROXY":         fmt.Sprintf("http://%s:%d", proxyIP, proxyPort),
				"SSL_CERT_FILE":       "/etc/gigemcp-ca.pem",
				"NODE_EXTRA_CA_CERTS": "/etc/gigemcp-ca.pem",
				"GIGE_PLACEHOLDER":    "PLACEHOLDER",
			},
		},
	}

	cmd := sandbox.Command(spec)

	// Capture MCP stdio before Start (StdoutPipe/StdinPipe must be called before Start).
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		r3.Close()
		w3.Close()
		r4.Close()
		w4.Close()
		rInfo.Close()
		wInfo.Close()
		rBlock.Close()
		wBlock.Close()
		alloc.Free(sub)
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		r3.Close()
		w3.Close()
		r4.Close()
		w4.Close()
		rInfo.Close()
		wInfo.Close()
		rBlock.Close()
		wBlock.Close()
		alloc.Free(sub)
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	// ExtraFiles[0]→fd3 (r3), ExtraFiles[1]→fd4 (w4), ExtraFiles[2]→fd5 (wInfo),
	// ExtraFiles[3]→fd6 (rBlock, --userns-block-fd).
	cmd.ExtraFiles = []*os.File{r3, w4, wInfo, rBlock}
	// Route bwrap/bootstrap stderr to the process stderr so failures are visible.
	cmd.Stderr = os.Stderr
	// cmd.Env controls the bwrap process itself (not the sandboxed server):
	// bwrap uses --clearenv, so sandbox-internal vars are passed via Egress.Env
	// which commandEgress emits as --setenv K V flags in the bwrap argv.
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		r3.Close()
		w3.Close()
		r4.Close()
		w4.Close()
		rInfo.Close()
		wInfo.Close()
		rBlock.Close()
		wBlock.Close()
		alloc.Free(sub)
		return nil, fmt.Errorf("start bwrap: %w", err)
	}

	// Close our (parent) copies of the child-side fds; child holds the only copies now.
	r3.Close()
	w4.Close()
	wInfo.Close()
	rBlock.Close() // close the read end; only we (parent) hold the write end now

	// earlyCleanup is used on error after Start before finalCleanup is set.
	// It is safe to call multiple times (wBlock close is idempotent: after the
	// normal unblock below wBlock is set to nil).
	earlyCleanup := func() {
		if wBlock != nil {
			wBlock.Close() // unblock the child so it can exit
			wBlock = nil
		}
		alloc.Free(sub)
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}

	// Step 1: read child PID from bwrap --info-fd.
	childPid, err := readChildPid(rInfo)
	if err != nil {
		earlyCleanup()
		return nil, fmt.Errorf("read child pid: %w", err)
	}

	// Step 1b: write uid_map and gid_map to allow both uid 0 (for CAP_NET_ADMIN
	// in bootstrap) and uid 65534 (nobody, for the server after privilege drop).
	// Must happen before closing wBlock (which unblocks the child).
	if err := writeUIDGIDMaps(childPid); err != nil {
		earlyCleanup()
		return nil, fmt.Errorf("write uid/gid maps: %w", err)
	}
	// Unblock the child: closing the write end of the userns-block pipe causes
	// the child's read end to return EOF, which bwrap interprets as "proceed".
	wBlock.Close()
	wBlock = nil // prevent double-close in earlyCleanup

	// Step 2: create veth pair and inject peer into child netns.
	netlinkVeth, err := netmgr.CreateVethToHost(sub)
	if err != nil {
		earlyCleanup()
		return nil, fmt.Errorf("create veth: %w", err)
	}
	if err := netmgr.InjectPeer(netlinkVeth, childPid); err != nil {
		netmgr.DeleteVeth(netlinkVeth)
		earlyCleanup()
		return nil, fmt.Errorf("inject peer: %w", err)
	}

	// Step 3: signal inject-done, await net-ready.
	if _, err := w3.Write([]byte{1}); err != nil {
		netmgr.DeleteVeth(netlinkVeth)
		earlyCleanup()
		return nil, fmt.Errorf("write inject-done: %w", err)
	}
	w3.Close()

	ack := make([]byte, 1)
	if _, err := r4.Read(ack); err != nil {
		netmgr.DeleteVeth(netlinkVeth)
		earlyCleanup()
		return nil, fmt.Errorf("await net-ready: %w", err)
	}
	r4.Close()

	// Step 4: register sandbox source IP → tenant identity in the proxy registry.
	reg.Bind(sub.SandboxIP.String(), proxy.Identity{Server: srv.Name, Tenant: "default"})
	log.Printf("backend %q egress sandbox up: bwrap-child-pid=%d subnet=%s/%s", srv.Name, childPid, sub.SandboxIP, sub.HostIP)

	// Step 5: connect the MCP session over the already-started process's stdio.
	// The bootstrap has now exec'd the real server, which speaks MCP stdio.
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "gigemcp-gw", Version: "0.1.0"}, nil)
	sess, err := mcpClient.Connect(ctx, &mcp.IOTransport{Reader: stdout, Writer: stdin}, nil)
	if err != nil {
		netmgr.DeleteVeth(netlinkVeth)
		reg.Unbind(sub.SandboxIP.String())
		earlyCleanup()
		return nil, fmt.Errorf("connect MCP session for %q: %w", srv.Name, err)
	}

	// Step 5b: resolve the payload PID (bwrap's grandchild = the actual server process).
	// childPid is the bwrap intermediate supervisor child. The real server runs as
	// childPid's child (PID 1 inside the new PID namespace, seen from outside as
	// childPid+1 in a quiet system, but reliably found via /proc/<pid>/task/<pid>/children).
	payloadPID, err := sandboxPayloadPID(childPid)
	if err != nil {
		netmgr.DeleteVeth(netlinkVeth)
		reg.Unbind(sub.SandboxIP.String())
		earlyCleanup()
		return nil, fmt.Errorf("find payload pid: %w", err)
	}

	finalCleanup := func() {
		sess.Close()
		netmgr.DeleteVeth(netlinkVeth)
		reg.Unbind(sub.SandboxIP.String())
		alloc.Free(sub)
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}
	return &EgressBackend{Session: sess, ChildPID: payloadPID, Cleanup: finalCleanup}, nil
}

// readChildPid reads and parses the bwrap --info-fd JSON to extract the child PID.
// bwrap writes {"child-pid": N} to the fd once the child has been forked.
func readChildPid(r *os.File) (int, error) {
	defer r.Close()
	var info struct {
		ChildPid int `json:"child-pid"`
	}
	// bwrap writes one JSON object to --info-fd at startup and keeps the fd
	// open for the container lifetime, so we must decode a single object
	// rather than read to EOF (which would block forever).
	if err := json.NewDecoder(r).Decode(&info); err != nil {
		return 0, fmt.Errorf("parse bwrap info-fd: %w", err)
	}
	if info.ChildPid == 0 {
		return 0, fmt.Errorf("bwrap info-fd had no child-pid")
	}
	return info.ChildPid, nil
}
