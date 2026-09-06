//go:build !linux

package rootlesspodman

import (
	"context"
	"os/exec"
)

func runExecProcess(ctx context.Context, cmd *exec.Cmd) (cancelled bool, err error) {
	if err := cmd.Start(); err != nil {
		return false, err
	}
	completionCh := observeExecProcess(cmd)
	select {
	case observationErr := <-completionCh:
		return false, waitExecProcess(cmd, observationErr)
	case <-ctx.Done():
		return true, terminateExecProcessGroup(cmd, completionCh)
	}
}
