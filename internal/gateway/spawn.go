package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/gigemcp/gigemcp/internal/netmgr"
	"github.com/gigemcp/gigemcp/internal/proxy"
	"github.com/gigemcp/gigemcp/internal/sandbox"
	"github.com/gigemcp/gigemcp/internal/store"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// SpawnEgressBackend launches one MCP server in an egress-isolated sandbox and
// returns a connected MCP client session plus a cleanup function.
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
) (*mcp.ClientSession, func(), error) {
	sub, err := alloc.Allocate()
	if err != nil {
		return nil, nil, fmt.Errorf("allocate subnet: %w", err)
	}
	proxyIP := sub.HostIP.String()

	// Create handshake pipes.
	r3, w3, err := os.Pipe() // inject-done: gateway → bootstrap (fd3 in child)
	if err != nil {
		alloc.Free(sub)
		return nil, nil, fmt.Errorf("pipe inject-done: %w", err)
	}
	r4, w4, err := os.Pipe() // net-ready: bootstrap → gateway (fd4 in child)
	if err != nil {
		r3.Close()
		w3.Close()
		alloc.Free(sub)
		return nil, nil, fmt.Errorf("pipe net-ready: %w", err)
	}
	rInfo, wInfo, err := os.Pipe() // bwrap --info-fd (fd5 in child)
	if err != nil {
		r3.Close()
		w3.Close()
		r4.Close()
		w4.Close()
		alloc.Free(sub)
		return nil, nil, fmt.Errorf("pipe info-fd: %w", err)
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
			// These vars must reach the server INSIDE the sandbox.
			// cmd.Env is useless here because bwrap uses --clearenv;
			// they are emitted as --setenv K V flags by commandEgress.
			// None of these are secrets: proxy URL, CA path, placeholder.
			Env: map[string]string{
				"HTTPS_PROXY":          fmt.Sprintf("http://%s:%d", proxyIP, proxyPort),
				"SSL_CERT_FILE":        "/etc/gigemcp-ca.pem",
				"NODE_EXTRA_CA_CERTS":  "/etc/gigemcp-ca.pem",
				"GIGE_PLACEHOLDER":     "PLACEHOLDER",
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
		alloc.Free(sub)
		return nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		r3.Close()
		w3.Close()
		r4.Close()
		w4.Close()
		rInfo.Close()
		wInfo.Close()
		alloc.Free(sub)
		return nil, nil, fmt.Errorf("stdin pipe: %w", err)
	}

	// ExtraFiles[0]→fd3 (r3), ExtraFiles[1]→fd4 (w4), ExtraFiles[2]→fd5 (wInfo).
	cmd.ExtraFiles = []*os.File{r3, w4, wInfo}
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
		alloc.Free(sub)
		return nil, nil, fmt.Errorf("start bwrap: %w", err)
	}

	// Close our (parent) copies of the child-side fds; child holds the only copies now.
	r3.Close()
	w4.Close()
	wInfo.Close()

	// earlyCleanup is used on error after Start before finalCleanup is set.
	earlyCleanup := func() {
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
		return nil, nil, fmt.Errorf("read child pid: %w", err)
	}

	// Step 2: create veth pair and inject peer into child netns.
	netlinkVeth, err := netmgr.CreateVethToHost(sub)
	if err != nil {
		earlyCleanup()
		return nil, nil, fmt.Errorf("create veth: %w", err)
	}
	if err := netmgr.InjectPeer(netlinkVeth, childPid); err != nil {
		netmgr.DeleteVeth(netlinkVeth)
		earlyCleanup()
		return nil, nil, fmt.Errorf("inject peer: %w", err)
	}

	// Step 3: signal inject-done, await net-ready.
	if _, err := w3.Write([]byte{1}); err != nil {
		netmgr.DeleteVeth(netlinkVeth)
		earlyCleanup()
		return nil, nil, fmt.Errorf("write inject-done: %w", err)
	}
	w3.Close()

	ack := make([]byte, 1)
	if _, err := r4.Read(ack); err != nil {
		netmgr.DeleteVeth(netlinkVeth)
		earlyCleanup()
		return nil, nil, fmt.Errorf("await net-ready: %w", err)
	}
	r4.Close()

	// Step 4: register sandbox source IP → tenant identity in the proxy registry.
	reg.Bind(sub.SandboxIP.String(), proxy.Identity{Server: srv.Name, Tenant: "default"})
	log.Printf("backend %q egress sandbox up: pid=%d subnet=%s/%s", srv.Name, childPid, sub.SandboxIP, sub.HostIP)

	// Step 5: connect the MCP session over the already-started process's stdio.
	// The bootstrap has now exec'd the real server, which speaks MCP stdio.
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "gigemcp-gw", Version: "0.1.0"}, nil)
	sess, err := mcpClient.Connect(ctx, &mcp.IOTransport{Reader: stdout, Writer: stdin}, nil)
	if err != nil {
		netmgr.DeleteVeth(netlinkVeth)
		reg.Unbind(sub.SandboxIP.String())
		earlyCleanup()
		return nil, nil, fmt.Errorf("connect MCP session for %q: %w", srv.Name, err)
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
	return sess, finalCleanup, nil
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
