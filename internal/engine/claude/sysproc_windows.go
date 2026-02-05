//go:build windows

package claude

import "syscall"

// newSysProcAttr returns SysProcAttr for Windows (no Setsid equivalent).
func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}
