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
	seccomp "github.com/elastic/go-seccomp-bpf"
)

// cloneNewuser is the CLONE_NEWUSER flag (clone(2) arg0). clone3 cannot be
// arg-filtered (its arg0 is a pointer BPF cannot dereference), so clone3 is
// blanket-denied — safe because the Go runtime uses clone, not clone3, for
// OS threads.
const cloneNewuser = 0x10000000

// Install loads the scoped seccomp filter onto the calling thread. It must be
// called AFTER PR_SET_NO_NEW_PRIVS is set and on the same (locked) OS thread
// that will execve the untrusted server.
//
// API note: SyscallGroup.NamesWithCondtions is spelled with a missing 'i' —
// this is a known typo in github.com/elastic/go-seccomp-bpf v1.6.0 (the
// struct tag uses "names_with_args"). We match the library spelling exactly.
func Install() error {
	policy := seccomp.Policy{
		DefaultAction: seccomp.ActionAllow,
		Syscalls: []seccomp.SyscallGroup{
			{
				Action: seccomp.ActionKillProcess,
				Names: []string{
					"unshare", "setns", "clone3",
					"mount", "umount2", "pivot_root", "chroot",
					"open_tree", "move_mount", "fsopen", "mount_setattr",
					"ptrace", "process_vm_readv", "process_vm_writev",
					"keyctl", "add_key", "request_key",
					"bpf", "perf_event_open",
					"kexec_load", "init_module", "finit_module", "delete_module",
				},
			},
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
