//go:build windows

package claude

import (
	"os/exec"
	"syscall"
)

// newSysProcAttr returns SysProcAttr for Windows (no Setsid equivalent).
func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

// setupProcessCleanup is a no-op on Windows. Windows does not support POSIX
// process groups; the default cmd.Cancel (os.Process.Kill) is used instead.
func setupProcessCleanup(cmd *exec.Cmd) {}
