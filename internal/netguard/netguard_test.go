package netguard

import (
	"net"
	"testing"
)

// TestIsBlockedIP covers the full rejection set (loopback, RFC1918 private,
// link-local, unspecified, CGNAT) plus confirmation that public addresses and a
// nil (unparseable) IP are handled correctly.
func TestIsBlockedIP(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true},       // loopback
		{"::1", true},             // loopback v6
		{"10.0.0.1", true},        // RFC1918 private
		{"172.16.0.1", true},      // RFC1918 private
		{"192.168.1.1", true},     // RFC1918 private
		{"169.254.169.254", true}, // link-local unicast (cloud metadata)
		{"224.0.0.1", true},       // link-local multicast
		{"0.0.0.0", true},         // unspecified
		{"100.64.0.0", true},      // CGNAT lower bound
		{"100.100.100.200", true}, // CGNAT (Alibaba metadata)
		{"100.127.255.255", true}, // CGNAT upper bound
		{"8.8.8.8", false},        // public
		{"1.1.1.1", false},        // public
		{"100.128.0.0", false},    // just outside CGNAT /10
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("test bug: unparseable IP %q", c.ip)
		}
		if got := IsBlockedIP(ip); got != c.blocked {
			t.Errorf("IsBlockedIP(%s) = %v, want %v", c.ip, got, c.blocked)
		}
	}
	if !IsBlockedIP(nil) {
		t.Error("IsBlockedIP(nil) must be true (unparseable address)")
	}
}
