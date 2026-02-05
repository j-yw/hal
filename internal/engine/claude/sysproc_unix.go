//go:build !windows

package claude

import "syscall"

// newSysProcAttr returns SysProcAttr that creates a new session to detach
// from the controlling TTY, suppressing interactive UI hints.
func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}
