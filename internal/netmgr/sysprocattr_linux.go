//go:build linux

package netmgr

import "syscall"

func newNetnsSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWUSER}
}
