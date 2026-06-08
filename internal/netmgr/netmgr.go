// Package netmgr provisions per-sandbox networking on the HOST side of the
// boundary, using netlink (no `ip` CLI) with CAP_NET_ADMIN only. Per sandbox:
// allocate a /30, create a veth pair, bring the host end up with the host IP,
// and move the peer end into the bwrap child's network namespace by PID
// (LinkSetNsPid — avoids the named-netns bind-mount that needs CAP_SYS_ADMIN).
package netmgr

import (
	"fmt"
	"net"
	"os/exec"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
)

// Subnet is one /30 allocation: .1 host (proxy) side, .2 sandbox side.
type Subnet struct {
	Index     int
	HostIP    net.IP
	SandboxIP net.IP
	Mask      net.IPMask
	HostVeth  string // unique iface name, host side
	PeerVeth  string // unique iface name, sandbox side
}

// Allocator hands out non-overlapping /30s from a base network.
type Allocator struct {
	mu   sync.Mutex
	base net.IP
	used map[int]bool
}

// NewAllocator parses base (e.g. "10.88.0.0/16") and returns an allocator.
func NewAllocator(base string) *Allocator {
	ip, _, _ := net.ParseCIDR(base)
	return &Allocator{base: ip.To4(), used: map[int]bool{}}
}

// Allocate returns the next free /30. Index k → host=base+4k+1, sandbox=base+4k+2.
func (a *Allocator) Allocate() (Subnet, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	k := 0
	for a.used[k] {
		k++
	}
	a.used[k] = true
	host := offset(a.base, 4*k+1)
	sb := offset(a.base, 4*k+2)
	return Subnet{
		Index: k, HostIP: host, SandboxIP: sb, Mask: net.CIDRMask(30, 32),
		HostVeth: fmt.Sprintf("vh%d", k), PeerVeth: fmt.Sprintf("vs%d", k),
	}, nil
}

// Free returns a subnet to the pool.
func (a *Allocator) Free(s Subnet) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, s.Index)
}

func offset(base net.IP, n int) net.IP {
	v := make(net.IP, 4)
	copy(v, base.To4())
	u := uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
	u += uint32(n)
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u)).To4()
}

// CreateVethToHost creates the veth pair and configures the host side (addr+up).
func CreateVethToHost(s Subnet) (*netlink.Veth, error) {
	la := netlink.NewLinkAttrs()
	la.Name = s.HostVeth
	veth := &netlink.Veth{LinkAttrs: la, PeerName: s.PeerVeth}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("link add: %w", err)
	}
	addr := &netlink.Addr{IPNet: &net.IPNet{IP: s.HostIP, Mask: s.Mask}}
	if err := netlink.AddrAdd(veth, addr); err != nil {
		netlink.LinkDel(veth)
		return nil, fmt.Errorf("addr add host: %w", err)
	}
	if err := netlink.LinkSetUp(veth); err != nil {
		netlink.LinkDel(veth)
		return nil, fmt.Errorf("link up host: %w", err)
	}
	return veth, nil
}

// InjectPeer moves the peer end into the netns of the given (host) PID.
func InjectPeer(veth *netlink.Veth, pid int) error {
	peer, err := netlink.LinkByName(veth.PeerName)
	if err != nil {
		return fmt.Errorf("find peer: %w", err)
	}
	if err := netlink.LinkSetNsPid(peer, pid); err != nil {
		return fmt.Errorf("move peer to netns pid %d: %w", pid, err)
	}
	return nil
}

// VerifyHostSide confirms the host veth carries the host IP.
func VerifyHostSide(s Subnet) error {
	link, err := netlink.LinkByName(s.HostVeth)
	if err != nil {
		return err
	}
	addrs, err := netlink.AddrList(link, syscall.AF_INET)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if a.IP.Equal(s.HostIP) {
			return nil
		}
	}
	return fmt.Errorf("host veth %s missing %s", s.HostVeth, s.HostIP)
}

// DeleteVeth removes the host veth (also removes the peer).
func DeleteVeth(veth *netlink.Veth) {
	if l, err := netlink.LinkByName(veth.LinkAttrs.Name); err == nil {
		netlink.LinkDel(l)
	}
}

// netnsChild is a stand-in for bwrap's child during tests.
type NetnsChild struct {
	Pid int
}

// SpawnNetnsChildForTest starts `sleep 300` in its own net namespace so a real
// netns exists to inject into. Test-only helper.
func SpawnNetnsChildForTest(t interface{ Fatalf(string, ...any) }) (*NetnsChild, func(), error) {
	cmd := exec.Command("sleep", "300")
	cmd.SysProcAttr = newNetnsSysProcAttr()
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return &NetnsChild{Pid: cmd.Process.Pid}, func() { cmd.Process.Kill(); cmd.Wait() }, nil
}
