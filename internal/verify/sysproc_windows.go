//go:build windows

package verify

import (
	"os/exec"
	"syscall"
	"time"
)

func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

func setupProcessCleanup(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// taskkill /T terminates descendants that cmd.exe would otherwise leave behind.
		return killWindowsProcessTree(cmd.Process.Pid, cmd.Process.Kill, nil)
	}
	cmd.WaitDelay = 5 * time.Second
}
