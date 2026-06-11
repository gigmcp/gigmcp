package api

import "testing"

func TestValidateExternalHTTPSURL(t *testing.T) {
	accept := []string{
		"https://accounts.google.com/o/oauth2/auth",
		"https://oauth2.googleapis.com/token",
	}
	for _, u := range accept {
		if err := validateExternalHTTPSURL(u); err != nil {
			t.Errorf("expected %q to be accepted, got error: %v", u, err)
		}
	}

	reject := []string{
		"http://accounts.google.com/o/oauth2/auth",  // non-https
		"https://169.254.169.254/latest/meta-data/", // cloud metadata link-local
		"https://127.0.0.1/token",                   // loopback
		"https://localhost/token",                   // localhost hostname
		"https://10.0.0.5/token",                    // private 10/8
		"https://192.168.1.1/token",                 // private 192.168/16
		"https://[::1]/token",                       // IPv6 loopback
		"https://0.0.0.0/token",                     // unspecified
		"https://172.16.0.1/token",                  // private 172.16/12
		"https://",                                  // empty host
		"ht!tp://%zz",                               // malformed URL
	}
	for _, u := range reject {
		if err := validateExternalHTTPSURL(u); err == nil {
			t.Errorf("expected %q to be rejected, but it was accepted", u)
		}
	}
}
