package gateway

import (
	"debug/elf"
	"fmt"
	"path"
	"path/filepath"
	"runtime"

	"github.com/gigmcp/gigmcp/internal/store"
)

// ArchMismatchError reports that an installed server's binary is built for a
// CPU architecture the host cannot execute. The egress sandbox carries no QEMU
// (or any) interpreter, so a foreign-arch binary fails to exec inside bwrap and
// previously surfaced only as an opaque MCP "calling initialize: EOF" → the
// dashboard's generic "backend unavailable". Detecting the mismatch up front
// turns that into an actionable, typed error that the spawn/serve path can
// recognise (errors.As) and present verbatim.
type ArchMismatchError struct {
	Server    string // installed server name
	ImageArch string // architecture the extracted binary targets (OCI/GOARCH naming)
	HostArch  string // runtime.GOARCH of the gateway host
}

func (e *ArchMismatchError) Error() string {
	return fmt.Sprintf(
		"server %q: image architecture %s is incompatible with host %s (no emulation in sandbox); a multi-arch image is required",
		e.Server, e.ImageArch, e.HostArch)
}

// elfMachineToGOARCH maps an ELF machine field to Go's GOARCH naming, which is
// also the OCI image-config architecture naming (amd64/arm64/...). Only the
// architectures we can positively identify are listed; anything absent is
// treated as "unknown" and does not trip the guard.
var elfMachineToGOARCH = map[elf.Machine]string{
	elf.EM_X86_64:  "amd64",
	elf.EM_386:     "386",
	elf.EM_AARCH64: "arm64",
	elf.EM_ARM:     "arm",
	elf.EM_PPC64:   "ppc64",
	elf.EM_S390:    "s390x",
	elf.EM_RISCV:   "riscv64",
	elf.EM_MIPS:    "mips",
}

// checkBinaryArch inspects the extracted server binary's ELF header and returns
// an *ArchMismatchError when its architecture differs from the host's, so the
// spawn fails fast with a clear message instead of forking a sandbox whose exec
// silently dies (the opaque EOF chain).
//
// It reads the on-disk pulled artifact — no network round-trip, no schema
// change — so it also works for already-installed servers. A multi-arch (OCI
// index) image resolves to the host platform at pull time, so its extracted
// binary is host-native and never trips this.
//
// The check is deliberately permissive about uncertainty: a non-ELF file (the
// legacy gig-echo demo binary, or a host-native test stub), an unreadable file,
// or an ELF whose machine we do not recognise all return nil. Only a
// POSITIVELY identified foreign architecture is rejected, so the normal
// matching-arch path is never weakened.
func checkBinaryArch(srv store.Server) error {
	// For a toolpack bundle, srv.Binary is the IN-IMAGE entrypoint path (e.g.
	// /app/server) which does not exist on the host; the host artifact is the
	// same-named file inside the staging dir. For single-file servers srv.Binary
	// is already the host path.
	binPath := srv.Binary
	if srv.BundleDir != "" {
		binPath = filepath.Join(srv.BundleDir, path.Base(srv.Binary))
	}
	f, err := elf.Open(binPath)
	if err != nil {
		// Not an ELF, or unreadable: cannot determine arch — do not block.
		return nil
	}
	defer f.Close()

	goarch, known := elfMachineToGOARCH[f.Machine]
	if !known {
		return nil
	}
	if goarch != runtime.GOARCH {
		return &ArchMismatchError{Server: srv.Name, ImageArch: goarch, HostArch: runtime.GOARCH}
	}
	return nil
}
