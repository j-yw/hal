//go:build linux

package rootlesspodman

import (
	"errors"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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

func observeExecProcess(cmd *exec.Cmd) <-chan error {
	return observeExecProcessWith(cmd, waitForExecProcessExit)
}

func observeExecProcessWith(cmd *exec.Cmd, observe func(int) error) <-chan error {
	completionCh := make(chan error, 1)
	if cmd == nil || cmd.Process == nil || observe == nil {
		completionCh <- errors.New("exec process observation is unavailable")
		return completionCh
	}
	go func() {
		completionCh <- observe(cmd.Process.Pid)
	}()
	return completionCh
}

func waitForExecProcessExit(pid int) error {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}

func waitExecProcess(cmd *exec.Cmd, observationErr error) error {
	if cmd == nil {
		return observationErr
	}
	if observationErr != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	return errors.Join(observationErr, cmd.Wait())
}

func terminateExecProcessGroup(cmd *exec.Cmd, completionCh <-chan error) error {
	return terminateExecProcessGroupAfter(cmd, completionCh, execProcessGroupGracePeriod)
}

func terminateExecProcessGroupAfter(cmd *exec.Cmd, completionCh <-chan error, gracePeriod time.Duration) error {
	if cmd == nil || cmd.Process == nil {
		return waitExecProcess(cmd, <-completionCh)
	}
	// waitid(WNOWAIT) keeps the leader unreaped until cancellation has either
	// observed completion or finished signaling. The process-group ID cannot
	// be recycled while it is used below.
	select {
	case observationErr := <-completionCh:
		return waitExecProcess(cmd, observationErr)
	default:
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(gracePeriod)
	defer timer.Stop()
	select {
	case observationErr := <-completionCh:
		return waitExecProcess(cmd, observationErr)
	case <-timer.C:
	}

	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	return waitExecProcess(cmd, <-completionCh)
}
