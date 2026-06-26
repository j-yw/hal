package sandbox

import (
	"context"
	"strings"
	"time"
)

const nonInteractiveSSHCommandTimeout = 30 * time.Second

func nonInteractiveSSHOptions() []string {
	return []string{
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "NumberOfPasswordPrompts=0",
	}
}

func nonInteractiveSSHOptionsWithConnectTimeout(timeout string) []string {
	options := nonInteractiveSSHOptions()
	return append(options, "-o", "ConnectTimeout="+timeout)
}

func nonInteractiveSSHContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(ctx, nonInteractiveSSHCommandTimeout)
}

func sshRemoteCommand(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, sshShellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func appendSSHRemoteCommand(cmdArgs []string, args []string) []string {
	if len(args) == 0 {
		return cmdArgs
	}
	return append(cmdArgs, sshRemoteCommand(args))
}

func sshShellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
