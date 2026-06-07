package netmgr_test

import (
	"net"
	"testing"

	"github.com/gigmcp/gigmcp/internal/netmgr"
	"github.com/gigmcp/gigmcp/internal/sandbox"
)

func requireNet(t *testing.T) {
	t.Helper()
	if !sandbox.Available() {
		t.Skip("netmgr requires Linux + NET_ADMIN — run `make test`")
	}
}

func TestAllocatorHandsOutDistinctSubnets(t *testing.T) {
	a := netmgr.NewAllocator("10.88.0.0/16")
	s1, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := a.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if s1.HostIP.Equal(s2.HostIP) || s1.SandboxIP.Equal(s2.SandboxIP) {
		t.Fatalf("subnets overlap: %v %v", s1, s2)
	}
	// host and sandbox in same /30, distinct addresses
	if !s1.HostIP.Equal(net.ParseIP("10.88.0.1")) || !s1.SandboxIP.Equal(net.ParseIP("10.88.0.2")) {
		t.Fatalf("unexpected first /30: host=%v sb=%v", s1.HostIP, s1.SandboxIP)
	}
	a.Free(s1)
	s3, _ := a.Allocate()
	if !s3.HostIP.Equal(net.ParseIP("10.88.0.1")) {
		t.Fatalf("freed subnet not reused: %v", s3.HostIP)
	}
}

func TestCreateVethAndInject(t *testing.T) {
	requireNet(t)
	a := netmgr.NewAllocator("10.88.0.0/16")
	sub, _ := a.Allocate()
	// A long-lived child process in its OWN net namespace stands in for bwrap's child.
	child, cleanup, err := netmgr.SpawnNetnsChildForTest(t)
	if err != nil {
		t.Fatalf("spawn child: %v", err)
	}
	defer cleanup()

	link, err := netmgr.CreateVethToHost(sub)
	if err != nil {
		t.Fatalf("create veth: %v", err)
	}
	if err := netmgr.InjectPeer(link, child.Pid); err != nil {
		t.Fatalf("inject peer into pid %d: %v", child.Pid, err)
	}
	// Host side is up with the host IP; peer is now in the child netns.
	if err := netmgr.VerifyHostSide(sub); err != nil {
		t.Fatalf("host side not configured: %v", err)
	}
	netmgr.DeleteVeth(link) // cleanup
}
