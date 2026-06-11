package config_test

import (
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/config"
)

func TestParseMasterKey(t *testing.T) {
	valid := strings.Repeat("ab", 32) // 64 hex chars -> 32 bytes

	t.Run("valid 64-hex yields 32 bytes", func(t *testing.T) {
		key, err := config.ParseMasterKey(valid)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(key) != 32 {
			t.Fatalf("expected 32 bytes, got %d", len(key))
		}
	})

	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"too short (63 chars)", strings.Repeat("a", 63)},
		{"too long (65 chars)", strings.Repeat("a", 65)},
		{"non-hex of correct length", strings.Repeat("zz", 32)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.ParseMasterKey(tc.in)
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), "GIG_MASTER_KEY") {
				t.Fatalf("error should name GIG_MASTER_KEY, got: %v", err)
			}
			if !strings.Contains(err.Error(), "openssl rand -hex 32") {
				t.Fatalf("error should include actionable hint, got: %v", err)
			}
		})
	}
}
