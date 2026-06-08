package config

import (
	"strings"
	"testing"
)

func TestFromEnvRegistryFields(t *testing.T) {
	t.Setenv("GIG_ECHO_BIN", "")
	t.Setenv("GIG_INSTALL", "echo@0.1.0, fetch")
	t.Setenv("GIG_REGISTRY_INDEX_URL", "file:///tmp/index.json")
	t.Setenv("GIG_REGISTRY_PUBKEY", "abcd")
	t.Setenv("GIG_DATA_DIR", "")
	cfg, err := FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if cfg.Install != "echo@0.1.0, fetch" || cfg.RegistryIndexURL != "file:///tmp/index.json" {
		t.Fatalf("bad cfg: %+v", cfg)
	}
	if cfg.DataDir != "/data" {
		t.Fatalf("DataDir default = %q, want /data", cfg.DataDir)
	}
}

func TestEchoBinNowOptional(t *testing.T) {
	t.Setenv("GIG_ECHO_BIN", "")
	t.Setenv("GIG_INSTALL", "")
	if _, err := FromEnv(); err != nil {
		t.Fatalf("GIG_ECHO_BIN must be optional now: %v", err)
	}
}

func TestInstallRequiresIndexURLAndKey(t *testing.T) {
	t.Setenv("GIG_INSTALL", "echo")
	t.Setenv("GIG_REGISTRY_INDEX_URL", "")
	t.Setenv("GIG_REGISTRY_PUBKEY", "")
	_, err := FromEnv()
	if err == nil || !strings.Contains(err.Error(), "GIG_REGISTRY") {
		t.Fatalf("GIG_INSTALL without index URL/pubkey must fail: %v", err)
	}
}
