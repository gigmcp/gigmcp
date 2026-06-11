package api

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateExternalHTTPSURL guards the admin-supplied BYO OAuth endpoint URLs
// (authorize_url / token_url) against being pointed at internal or
// cloud-metadata services. The gateway makes server-side requests to these URLs
// (authorization-code exchange + refresh-token grant), so an unvalidated URL is
// a server-side request forgery (SSRF) vector.
//
// It enforces: https scheme only, a non-empty host, the host is not "localhost"
// (case-insensitive), and — when the host is a literal IP — that the IP is not
// in a dangerous range (loopback, RFC1918 private, link-local incl. the
// 169.254.169.254 cloud-metadata address, or the unspecified address).
//
// NOTE: This is input-validation only. It blocks literal-IP and localhost SSRF
// but does NOT stop a hostname that DNS-resolves to a private IP
// (DNS-rebinding SSRF): the host could resolve to 169.254.169.254 at request
// time. The follow-up for full coverage is a dialer-level guard on the broker's
// HTTP client that re-checks the resolved IP at connection time and refuses to
// dial private/link-local/loopback addresses. That is intentionally out of
// scope for this input-validation layer.
func validateExternalHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme must be https, got %q", u.Scheme)
	}
	host := u.Hostname() // strips any :port and []-brackets around IPv6 literals
	if host == "" {
		return fmt.Errorf("URL must have a host")
	}
	if strings.EqualFold(host, "localhost") {
		return fmt.Errorf("host %q is not allowed", host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("host IP %q is in a disallowed (private/loopback/link-local) range", host)
		}
	}
	return nil
}
