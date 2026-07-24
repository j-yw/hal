//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package rootlesspodman

import (
	"os/exec"
	"syscall"
	"time"
)

const (
	execProcessGroupGracePeriod = 2 * time.Second
	execProcessGroupForcePeriod = 2 * time.Second
)

func configureExecProcessGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateExecProcessGroup(cmd *exec.Cmd, waitCh <-chan error) error {
	if cmd == nil || cmd.Process == nil {
		return <-waitCh
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(execProcessGroupGracePeriod)
	defer timer.Stop()
	select {
	case err := <-waitCh:
		return err
	case <-timer.C:
	}

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	forceTimer := time.NewTimer(execProcessGroupForcePeriod)
	defer forceTimer.Stop()
	select {
	case err := <-waitCh:
		return err
	case <-forceTimer.C:
		return syscall.ETIMEDOUT
	}
}
