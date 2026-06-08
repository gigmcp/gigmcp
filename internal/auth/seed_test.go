package auth

import "testing"

func TestManagedVendorSeedsHaveEndpoints(t *testing.T) {
	seeds := ManagedVendorSeeds()
	for _, want := range []string{"google", "microsoft", "slack"} {
		s, ok := seeds[want]
		if !ok {
			t.Fatalf("missing managed seed for %q", want)
		}
		if s.AuthorizeURL == "" || s.TokenURL == "" {
			t.Fatalf("seed %q missing endpoints: %+v", want, s)
		}
		if s.Mode != "managed" {
			t.Fatalf("seed %q must be mode=managed, got %q", want, s.Mode)
		}
	}
}
