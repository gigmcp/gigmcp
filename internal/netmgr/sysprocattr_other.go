//go:build !linux

package netmgr

import "syscall"

func newNetnsSysProcAttr() *syscall.SysProcAttr {
	return nil
}
