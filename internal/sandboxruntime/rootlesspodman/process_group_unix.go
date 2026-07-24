//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package rootlesspodman

import (
	"os/exec"
	"syscall"
	"time"
)

const (
	execProcessGroupGracePeriod = 2 * time.Second
)

func configureExecProcessGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func terminateExecProcessGroup(cmd *exec.Cmd, waitCh <-chan error) error {
	return terminateExecProcessGroupAfter(cmd, waitCh, execProcessGroupGracePeriod)
}

func terminateExecProcessGroupAfter(cmd *exec.Cmd, waitCh <-chan error, gracePeriod time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return <-waitCh
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(gracePeriod)
	defer timer.Stop()
	select {
	case err := <-waitCh:
		return err
	case <-timer.C:
	}

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	// cmd.Wait owns the caller-provided output writers. Do not return while it
	// can still append logs or retain execution resources.
	return <-waitCh
}
