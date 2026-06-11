// Package netguard holds the shared SSRF connection-time predicate used by the
// OAuth broker (server-side token-endpoint requests) and the egress MITM proxy
// (upstream dials). Both must refuse the same set of dangerous destinations —
// loopback, RFC1918 private, link-local, unspecified, and CGNAT — so the guard
// lives in one leaf package and can never drift between the two boundaries.
package netguard

import "net"

// cgnatNet is the RFC 6598 shared address space (100.64.0.0/10) used for
// carrier-grade NAT. Some cloud metadata endpoints live here (e.g. Alibaba
// Cloud's 100.100.100.200), so the SSRF guard must reject it alongside
// loopback/private/link-local ranges.
var cgnatNet = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("100.64.0.0/10")
	return n
}()

// IsBlockedIP reports whether ip is a destination the SSRF guard must refuse:
// an unparseable address (nil), or one in the loopback, RFC1918 private,
// link-local (unicast or multicast), unspecified, or CGNAT (RFC 6598
// 100.64.0.0/10) ranges.
//
// It is intended to run on the CONCRETE resolved IP at connection time (e.g.
// from a net.Dialer Control callback), so it closes DNS rebinding: the IP
// checked is the IP actually connected to.
func IsBlockedIP(ip net.IP) bool {
	return ip == nil || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || cgnatNet.Contains(ip)
}
