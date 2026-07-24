//go:build !windows

package sandboxworkspace

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
)

func gitRunSafeWithVerifiedPayload(ctx context.Context, dir, operation string, payload *os.File, args ...string) error {
	if err := rewindSafeApplyPayload(payload); err != nil {
		return fmt.Errorf("%s failed: verified payload is unavailable", operation)
	}
	cmdArgs := append([]string{"-C", dir}, args...)
	cmdArgs = append(cmdArgs, "/dev/fd/3")
	cmd := exec.CommandContext(ctx, "git", cmdArgs...)
	cmd.ExtraFiles = []*os.File{payload}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return gitSafeCommandError(operation, stderr.String(), err)
	}
	return nil
}
