//go:build linux

// Package seccomp installs a scoped seccomp-BPF filter that denies the
// namespace-creation and privilege-escalation syscalls an untrusted MCP
// server must never need. It closes the nested-user-namespace escape
// (unshare/clone3 CLONE_NEWUSER → regain capabilities) that uid 65534 +
// capability-dropping alone do NOT prevent. Installed by cmd/bootstrap after
// the capability/uid drop and before execve; PR_SET_NO_NEW_PRIVS is already
// set by then, so no CAP_SYS_ADMIN is required.
package seccomp

import (
	"syscall"

	seccomp "github.com/elastic/go-seccomp-bpf"
)

// cloneNewuser is the CLONE_NEWUSER flag (clone(2) arg0). clone3 cannot be
// arg-filtered (its arg0 is a pointer BPF cannot dereference; the flags are
// in a struct, not a register). clone3 is therefore handled separately — see
// the actionErrnoENOSYS group below.
const cloneNewuser = 0x10000000

// actionErrnoENOSYS is seccomp.ActionErrno with errno=ENOSYS (38) ORed in.
//
// The go-seccomp-bpf assembler's Ret() defaults ActionErrno to EPERM; to
// specify a different errno we pre-OR the value into the Action constant
// before passing it to the SyscallGroup, which bypasses the EPERM default
// (Ret checks action == ActionErrno exactly, and our value has extra bits).
// This is the same technique the library uses internally for its x32-ABI
// filter: `uint32(ActionErrno) | uint32(errnoENOSYS)` (filter.go line 241).
var actionErrnoENOSYS = seccomp.ActionErrno | seccomp.Action(syscall.ENOSYS)

// Install loads the scoped seccomp filter onto the calling thread. It must be
// called AFTER PR_SET_NO_NEW_PRIVS is set and on the same (locked) OS thread
// that will execve the untrusted server.
//
// Filter strategy (default action = ALLOW; only escape/escalation vectors are
// denied):
//
//   - unshare, setns, mount-family, ptrace, keyctl, bpf, kexec, modules:
//     KILL_PROCESS — no legitimate use for an MCP server.
//   - clone(CLONE_NEWUSER): KILL_PROCESS — arg-filtered via BitsSet on arg0;
//     this is the primary nested-userns escape vector.
//   - clone3: ENOSYS — NOT kill. glibc ≥2.34 uses clone3 for pthread_create
//     and falls back to clone only on ENOSYS; a KILL would SIGSYS-kill
//     Rust/C/glibc servers on thread creation. Returning ENOSYS triggers the
//     glibc fallback to plain clone, which is arg-filtered above (CLONE_NEWUSER
//     → KILL_PROCESS). The escape stays closed; only thread compat improves.
//
// API note: SyscallGroup.NamesWithCondtions is spelled with a missing 'i' —
// this is a known typo in github.com/elastic/go-seccomp-bpf v1.6.0 (the
// struct tag uses "names_with_args"). We match the library spelling exactly.
func Install() error {
	policy := seccomp.Policy{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			// Hard-kill: namespace-creation, mount, ptrace, key, BPF, module syscalls.
			// None of these have any legitimate use inside the MCP server sandbox.
			{
				Action: seccomp.ActionKillProcess,
				Names: []string{
					"unshare", "setns",
					"mount", "umount2", "pivot_root", "chroot",
					"open_tree", "move_mount", "fsopen", "mount_setattr",
					"ptrace", "process_vm_readv", "process_vm_writev",
					"keyctl", "add_key", "request_key",
					"bpf", "perf_event_open",
					"kexec_load", "init_module", "finit_module", "delete_module",
				},
			},
			// ENOSYS for clone3: allows glibc pthread_create to fall back to
			// clone (which is arg-filtered below). Do NOT use KILL_PROCESS here —
			// that would SIGSYS-kill glibc-threaded servers before they can fall back.
			{
				Action: actionErrnoENOSYS,
				Names:  []string{"clone3"},
			},
			// Arg-filtered kill: clone(CLONE_NEWUSER) → KILL_PROCESS.
			// This closes the nested-user-namespace escape. Plain clone without
			// CLONE_NEWUSER is allowed (Go runtime thread creation uses it).
			{
				Action: seccomp.ActionKillProcess,
				// NamesWithCondtions: library field name has a typo (missing 'i').
				NamesWithCondtions: []seccomp.NameWithConditions{{
					Name: "clone",
					Conditions: seccomp.ArgumentConditions{{
						Argument:  0,
						Operation: seccomp.BitsSet,
						Value:     cloneNewuser,
					}},
				}},
			},
		},
	}
	// NoNewPrivs:false — the bootstrap already set PR_SET_NO_NEW_PRIVS; setting
	// it again via the library would be redundant. Flag is zero (no TSYNC) —
	// installed single-threaded on the locked thread right before execve.
	return seccomp.LoadFilter(seccomp.Filter{
		NoNewPrivs: false,
		Policy:     policy,
	})
}
