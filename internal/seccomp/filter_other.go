//go:build !linux

// Package seccomp installs a scoped seccomp-BPF filter on Linux. On other
// platforms this is a no-op stub so the module still compiles on macOS.
package seccomp

// Install is a no-op on non-Linux (seccomp is Linux-only). The bootstrap that
// calls it is itself linux-only.
func Install() error { return nil }
