package api

import "testing"

func TestAllowedHostRe(t *testing.T) {
	accept := []string{
		"github.com",
		"*.github.com",
		"api.github.com",
		"a-b.example.com",
	}
	reject := []string{
		"*.*.example.com",
		"a..b.com",
		".example.com",
		"example.com.",
		"*.",
	}
	for _, h := range accept {
		if !allowedHostRe.MatchString(h) {
			t.Errorf("allowedHostRe should accept %q", h)
		}
	}
	for _, h := range reject {
		if allowedHostRe.MatchString(h) {
			t.Errorf("allowedHostRe should reject %q", h)
		}
	}
}
