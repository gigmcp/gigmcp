package proxy

import (
	"strings"
	"testing"
)

// TestEgressGuardRefusesBlockedIPs is a direct unit test of the production
// upstream-dial guard (guardDialControl). The Control callback runs on the
// CONCRETE resolved IP:port immediately before connect, so this is exactly the
// check that closes DNS rebinding: an allowlisted hostname that resolves to a
// private/metadata/loopback IP is refused at dial time. A public address is
// permitted.
func TestEgressGuardRefusesBlockedIPs(t *testing.T) {
	cases := []struct {
		address string
		blocked bool
	}{
		{"127.0.0.1:443", true},       // loopback
		{"169.254.169.254:443", true}, // link-local cloud metadata
		{"10.0.0.5:443", true},        // RFC1918 private
		{"100.100.100.200:443", true}, // CGNAT (Alibaba metadata)
		{"192.168.1.10:443", true},    // RFC1918 private
		{"0.0.0.0:443", true},         // unspecified
		{"8.8.8.8:443", false},        // public
		{"1.1.1.1:443", false},        // public
		{"not-an-ip:443", true},       // unparseable host → ParseIP nil → blocked
	}
	for _, c := range cases {
		err := guardDialControl("tcp", c.address, nil)
		if c.blocked {
			if err == nil {
				t.Errorf("guardDialControl(%q) = nil, want refusal", c.address)
				continue
			}
			if !strings.Contains(err.Error(), "ssrf guard") {
				t.Errorf("guardDialControl(%q) error %q should mention the ssrf guard", c.address, err)
			}
		} else if err != nil {
			t.Errorf("guardDialControl(%q) = %v, want permit", c.address, err)
		}
	}
}
