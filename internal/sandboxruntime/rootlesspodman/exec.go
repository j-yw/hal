package rootlesspodman

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var (
	ErrExecRunnerRequired = errors.New("rootless Podman exec runner is required")
	ErrExecArgsRequired   = errors.New("rootless Podman exec args are required")
)

const (
	execStateDirectoryPrefix = "/tmp/.hal-exec-"
	execWrapperScript        = `state_dir=$1
token=$2
shift
shift
umask 077
if ! mkdir "$state_dir"; then
	exit 125
fi
if ! mkfifo -m 600 "$state_dir/cancel"; then
	rmdir "$state_dir" 2>/dev/null || true
	exit 125
fi
cleanup() {
	rm -f "$state_dir/cancel"
	rmdir "$state_dir" 2>/dev/null || true
}
trap cleanup EXIT
setsid --wait sh -c '
cancel_fifo=$1
token=$2
shift
shift
(
	IFS= read -r received <"$cancel_fifo" || exit 125
	if [ "$received" != "$token" ]; then
		exit 125
	fi
	kill -KILL 0
) &
watcher=$!
status=0
"$@" || status=$?
kill "$watcher" 2>/dev/null || true
wait "$watcher" 2>/dev/null || true
exit "$status"
' hal-exec-child "$state_dir/cancel" "$token" "$@"`
	execCancellationScript = `state_dir=$1
token=$2
cancel_fifo=$state_dir/cancel
attempt=0
while [ ! -p "$cancel_fifo" ]; do
	if [ "$attempt" -ge 300 ]; then
		exit 124
	fi
	attempt=$((attempt + 1))
	sleep 0.02
done
if ! printf "%s\n" "$token" >"$cancel_fifo"; then
	exit 125
fi
attempt=0
while [ -e "$state_dir" ]; do
	if [ "$attempt" -ge 100 ]; then
		exit 124
	fi
	attempt=$((attempt + 1))
	sleep 0.02
done`
)

func (d *Driver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	commandArgs := cloneStringSlice(req.Args)
	if len(commandArgs) == 0 {
		return nil, operationError(OperationExec, CommandResult{}, ErrExecArgsRequired)
	}
	ref, err := containerRef(req.Target)
	if err != nil {
		return nil, operationError(OperationExec, CommandResult{}, err)
	}
	commandRequest := CommandRequest{
		Operation: OperationExec,
		Args:      d.execArgs(ref, commandArgs, req.Env, req.WorkDir, req.Stdin != nil),
		Env:       cloneStringMap(req.Env),
		Stdin:     req.Stdin,
		Stdout:    req.Stdout,
		Stderr:    req.Stderr,
	}
	if req.RequireProcessGroupCancellationProof {
		stateDir, token, err := newExecCancellationIdentity()
		if err != nil {
			return nil, operationError(OperationExec, CommandResult{}, err)
		}
		commandRequest.Args = d.execArgs(
			ref,
			scopedExecCommandArgs(stateDir, token, commandArgs),
			req.Env,
			req.WorkDir,
			req.Stdin != nil,
		)
		commandRequest.CancellationArgs = d.execCancellationArgs(ref, stateDir, token)
	}

	result, err := d.runExecCommand(ctx, commandRequest)
	execResult := &sandboxruntime.ExecResult{ExitCode: result.ExitCode}
	if result.CancellationProcessGroupTerminated && ctx != nil && ctx.Err() != nil {
		execResult.Cancellation = &sandboxruntime.ExecCancellationResult{ProcessGroupTerminated: true}
	}
	if err != nil {
		return execResult, err
	}
	return execResult, nil
}

func (d *Driver) runExecCommand(ctx context.Context, req CommandRequest) (CommandResult, error) {
	runner, err := d.execRunnerFor(req.Operation)
	if err != nil {
		return CommandResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return CommandResult{ExitCode: -1}, operationError(req.Operation, CommandResult{ExitCode: -1}, err)
	}

	result, err := runner.RunExecCommand(ctx, req)
	if err != nil || result.ExitCode != 0 {
		return result, operationError(req.Operation, result, err)
	}
	return result, nil
}

func (d *Driver) execRunnerFor(operation string) (ExecCommandRunner, error) {
	if d == nil || d.execRunner == nil {
		return nil, operationError(operation, CommandResult{}, ErrExecRunnerRequired)
	}
	return d.execRunner, nil
}

func (d *Driver) execArgs(ref string, commandArgs []string, env map[string]string, workDir string, interactive bool) []string {
	args := []string{d.podmanPath, "exec"}
	if interactive {
		args = append(args, "--interactive")
	}
	if trimmedWorkDir := strings.TrimSpace(workDir); trimmedWorkDir != "" {
		args = append(args, "--workdir", trimmedWorkDir)
	}
	for _, key := range sortedMapKeys(env) {
		args = append(args, "--env", key)
	}
	args = append(args, ref)
	args = append(args, commandArgs...)
	return args
}

func scopedExecCommandArgs(stateDir, token string, commandArgs []string) []string {
	args := []string{"sh", "-c", execWrapperScript, "hal-exec", stateDir, token}
	return append(args, commandArgs...)
}

func (d *Driver) execCancellationArgs(ref, stateDir, token string) []string {
	return []string{d.podmanPath, "exec", ref, "sh", "-c", execCancellationScript, "hal-exec-cancel", stateDir, token}
}

func newExecCancellationIdentity() (string, string, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", "", fmt.Errorf("allocate rootless Podman exec identity: %w", err)
	}
	return execStateDirectoryPrefix + hex.EncodeToString(random[:16]), hex.EncodeToString(random[16:]), nil
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func sortedMapKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
