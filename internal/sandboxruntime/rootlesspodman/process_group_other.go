//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package rootlesspodman

import "os/exec"

func configureExecProcessGroup(*exec.Cmd) {}

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
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	return <-completionCh
}
