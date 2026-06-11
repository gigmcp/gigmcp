package gateway

import "testing"

// TestMinimalSpawnEnvOmitsSecrets asserts the bwrap parent env passes through
// PATH (needed to locate the bwrap/iptables binaries) but never leaks the
// gateway's secrets — notably GIG_MASTER_KEY — which would otherwise be readable
// by a host-level attacker via /proc/<bwrap-pid>/environ.
func TestMinimalSpawnEnvOmitsSecrets(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/root",
		"LANG=en_US.UTF-8",
		"TMPDIR=/tmp",
		"GIG_MASTER_KEY=super-secret-master-key",
		"GIG_OIDC_CLIENT_SECRET=another-secret",
		"AWS_SECRET_ACCESS_KEY=cloud-secret",
		"MALFORMED_NO_EQUALS",
	}

	got := minimalSpawnEnv(environ)

	has := func(key string) bool {
		for _, kv := range got {
			if len(kv) > len(key) && kv[:len(key)+1] == key+"=" {
				return true
			}
		}
		return false
	}

	if !has("PATH") {
		t.Errorf("minimalSpawnEnv must pass through PATH; got %v", got)
	}
	for _, want := range []string{"HOME", "LANG", "TMPDIR"} {
		if !has(want) {
			t.Errorf("minimalSpawnEnv should pass through %s when present; got %v", want, got)
		}
	}
	for _, secret := range []string{"GIG_MASTER_KEY", "GIG_OIDC_CLIENT_SECRET", "AWS_SECRET_ACCESS_KEY"} {
		if has(secret) {
			t.Errorf("minimalSpawnEnv must NOT leak secret %s into the bwrap parent env; got %v", secret, got)
		}
	}
}

// TestMinimalSpawnEnvAbsentVarsNotInvented ensures we only emit allowlisted vars
// that were actually present in the source environment (no empty placeholders).
func TestMinimalSpawnEnvAbsentVarsNotInvented(t *testing.T) {
	got := minimalSpawnEnv([]string{"PATH=/bin"})
	if len(got) != 1 || got[0] != "PATH=/bin" {
		t.Errorf("expected only [PATH=/bin], got %v", got)
	}
}
