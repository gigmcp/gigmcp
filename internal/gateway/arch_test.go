package gateway

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gigmcp/gigmcp/internal/store"
)

// writeELF writes a minimal but parseable ELF64 binary whose e_machine field is
// `machine`, with no program/section headers. debug/elf only needs a valid
// header to report the machine, which is all checkBinaryArch reads.
func writeELF(t *testing.T, dir string, machine elf.Machine) string {
	t.Helper()
	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F'})
	hdr[4] = byte(elf.ELFCLASS64)
	hdr[5] = byte(elf.ELFDATA2LSB)
	hdr[6] = byte(elf.EV_CURRENT)
	le := binary.LittleEndian
	le.PutUint16(hdr[16:], uint16(elf.ET_EXEC)) // e_type
	le.PutUint16(hdr[18:], uint16(machine))     // e_machine
	le.PutUint32(hdr[20:], uint32(elf.EV_CURRENT))
	le.PutUint16(hdr[52:], 64) // e_ehsize
	// e_phentsize/e_phnum/e_shentsize/e_shnum/e_shstrndx remain 0.
	path := filepath.Join(dir, "server")
	if err := os.WriteFile(path, hdr, 0o555); err != nil {
		t.Fatal(err)
	}
	return path
}

// foreignMachine returns an ELF machine that is NOT the host's, plus its
// expected GOARCH name, so the test is host-agnostic (passes on amd64 and arm64
// CI/dev machines alike).
func foreignMachine() (elf.Machine, string) {
	if runtime.GOARCH == "amd64" {
		return elf.EM_AARCH64, "arm64"
	}
	return elf.EM_X86_64, "amd64"
}

func hostMachine(t *testing.T) elf.Machine {
	t.Helper()
	switch runtime.GOARCH {
	case "amd64":
		return elf.EM_X86_64
	case "arm64":
		return elf.EM_AARCH64
	case "386":
		return elf.EM_386
	case "arm":
		return elf.EM_ARM
	default:
		t.Skipf("no ELF machine mapping for host GOARCH %q", runtime.GOARCH)
		return 0
	}
}

func TestCheckBinaryArchMismatch(t *testing.T) {
	mach, wantArch := foreignMachine()
	bin := writeELF(t, t.TempDir(), mach)

	err := checkBinaryArch(store.Server{Name: "hackernews", Binary: bin})
	if err == nil {
		t.Fatal("foreign-arch binary must be rejected, got nil")
	}
	var archErr *ArchMismatchError
	if !errors.As(err, &archErr) {
		t.Fatalf("want *ArchMismatchError, got %T: %v", err, err)
	}
	if archErr.Server != "hackernews" || archErr.ImageArch != wantArch || archErr.HostArch != runtime.GOARCH {
		t.Fatalf("unexpected fields: %+v", archErr)
	}
	if !strings.Contains(archErr.Error(), "is incompatible with host") ||
		!strings.Contains(archErr.Error(), "multi-arch image is required") {
		t.Fatalf("error string not actionable: %q", archErr.Error())
	}
}

func TestCheckBinaryArchMatchingHost(t *testing.T) {
	bin := writeELF(t, t.TempDir(), hostMachine(t))
	if err := checkBinaryArch(store.Server{Name: "ok", Binary: bin}); err != nil {
		t.Fatalf("host-arch binary must pass, got %v", err)
	}
}

func TestCheckBinaryArchNonELFIsAllowed(t *testing.T) {
	dir := t.TempDir()
	// A non-ELF file (e.g. the legacy gig-echo stub / host-native test binary)
	// and a missing file must both be permitted — we only block POSITIVE
	// mismatches, never uncertainty.
	stub := filepath.Join(dir, "server")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho hi\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	if err := checkBinaryArch(store.Server{Name: "echo", Binary: stub}); err != nil {
		t.Fatalf("non-ELF binary must pass, got %v", err)
	}
	if err := checkBinaryArch(store.Server{Name: "missing", Binary: filepath.Join(dir, "nope")}); err != nil {
		t.Fatalf("missing binary must not block spawn, got %v", err)
	}
}

// TestSpawnEgressBackendRejectsArchMismatch proves the mismatch is caught at the
// top of the spawn path — returning the typed error BEFORE any sandbox/MCP work,
// i.e. the opaque "calling initialize: EOF" can no longer occur for this cause.
// nil alloc/reg are safe: the guard returns before they are touched.
func TestSpawnEgressBackendRejectsArchMismatch(t *testing.T) {
	mach, wantArch := foreignMachine()
	bin := writeELF(t, t.TempDir(), mach)

	_, err := SpawnEgressBackend(
		context.Background(),
		store.Server{Name: "hackernews", Binary: bin},
		nil, nil, 0, "", "", "news", "",
	)
	var archErr *ArchMismatchError
	if !errors.As(err, &archErr) {
		t.Fatalf("want *ArchMismatchError, got %T: %v", err, err)
	}
	if archErr.ImageArch != wantArch {
		t.Fatalf("ImageArch = %q, want %q", archErr.ImageArch, wantArch)
	}
}
