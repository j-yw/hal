//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package rootlesspodman

import "os/exec"

func configureExecProcessGroup(*exec.Cmd) {}

func terminateExecProcessGroup(cmd *exec.Cmd, waitCh <-chan error) error {
	select {
	case err := <-waitCh:
		return err
	default:
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	return <-waitCh
}
