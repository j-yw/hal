//go:build !windows

package codex

import (
	"os/exec"
	"syscall"
	"time"
)

// newSysProcAttr returns SysProcAttr that creates a new session to detach
// from the controlling TTY, suppressing interactive UI hints.
func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}

// setupProcessCleanup configures cmd to kill the entire process group on
// context cancellation, preventing orphaned child processes (e.g., hung curl).
func setupProcessCleanup(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	cmd.WaitDelay = 5 * time.Second
}
