//go:build windows

package codex

import "syscall"

// newSysProcAttr returns SysProcAttr for Windows (no Setsid equivalent).
func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
