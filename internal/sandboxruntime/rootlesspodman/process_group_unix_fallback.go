//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package rootlesspodman

import (
	"os/exec"
	"syscall"
	"time"
)

const execProcessGroupGracePeriod = 2 * time.Second

func configureExecProcessGroup(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func observeExecProcess(cmd *exec.Cmd) <-chan error {
	completionCh := make(chan error, 1)
	go func() {
		completionCh <- cmd.Wait()
	}()
	return completionCh
}

func waitExecProcess(_ *exec.Cmd, observationErr error) error {
	return observationErr
}

func terminateExecProcessGroup(cmd *exec.Cmd, completionCh <-chan error) error {
	select {
	case err := <-completionCh:
		return err
	default:
	}
	// These platforms do not provide the Linux non-reaping wait used to pin a
	// process-group ID. Signal only the tracked os.Process handle so a delayed
	// Wait notification cannot target a recycled negative PGID.
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		timer := time.NewTimer(execProcessGroupGracePeriod)
		defer timer.Stop()
		select {
		case err := <-completionCh:
			return err
		case <-timer.C:
		}
		_ = cmd.Process.Kill()
	}
	return <-completionCh
}
