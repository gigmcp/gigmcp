package proxy_test

import (
	"testing"

	"github.com/gigmcp/gigmcp/internal/proxy"
)

func TestHostAllowed(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		allowed []string
		want    bool
	}{
		// Wildcard matches exactly one label.
		{"wildcard single label", "api.github.com", []string{"*.github.com"}, true},
		{"wildcard case-insensitive", "API.GitHub.com", []string{"*.github.com"}, true},

		// Wildcard must NOT over-match multiple labels (the suffix-bypass bug).
		{"wildcard two labels rejected", "a.b.github.com", []string{"*.github.com"}, false},
		{"wildcard exfil host rejected", "evil.com.github.com", []string{"*.github.com"}, false},

		// Wildcard must NOT match the bare apex.
		{"wildcard apex rejected", "github.com", []string{"*.github.com"}, false},

		// Wildcard must NOT match a host that merely ends with the literal chars
		// but not on a label boundary.
		{"wildcard non-boundary rejected", "notgithub.com", []string{"*.github.com"}, false},

		// Exact entry matches the apex (any case), not subdomains.
		{"exact apex match", "github.com", []string{"github.com"}, true},
		{"exact apex case-insensitive", "GitHub.COM", []string{"github.com"}, true},
		{"exact does not match subdomain", "api.github.com", []string{"github.com"}, false},

		// Combined apex + wildcard (as real manifests do: slack.com + *.slack.com).
		{"combined matches apex", "slack.com", []string{"slack.com", "*.slack.com"}, true},
		{"combined matches subdomain", "api.slack.com", []string{"slack.com", "*.slack.com"}, true},
		{"combined rejects nested", "a.b.slack.com", []string{"slack.com", "*.slack.com"}, false},

		// Empty list never matches.
		{"empty list", "github.com", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := proxy.HostAllowed(tc.host, tc.allowed)
			if got != tc.want {
				t.Fatalf("HostAllowed(%q, %v) = %v, want %v", tc.host, tc.allowed, got, tc.want)
			}
		})
	}
}
