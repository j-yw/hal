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
shift
umask 077
if ! mkdir "$state_dir"; then
	exit 125
fi
cleanup() {
	rm -f "$state_dir/pid"
	rmdir "$state_dir" 2>/dev/null || true
}
trap cleanup EXIT
setsid --wait sh -c '
pid_file=$1
shift
if ! printf "%s\n" "$$" >"$pid_file"; then
	exit 125
fi
exec "$@"
' hal-exec-child "$state_dir/pid" "$@" <&0 &
launcher=$!
status=0
wait "$launcher" || status=$?
exit "$status"`
	execCancellationScript = `state_dir=$1
pid_file=$state_dir/pid
attempt=0
while [ ! -r "$pid_file" ]; do
	if [ "$attempt" -ge 300 ]; then
		exit 124
	fi
	attempt=$((attempt + 1))
	sleep 0.02
done
IFS= read -r child <"$pid_file" || exit 0
case "$child" in
	""|*[!0-9]*|0|1) exit 125 ;;
esac
if ! kill -KILL "-$child" 2>/dev/null; then
	exit 125
fi
attempt=0
while kill -0 "-$child" 2>/dev/null; do
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
	if req.RequireCancellationProof {
		stateDir, err := newExecStateDirectory()
		if err != nil {
			return nil, operationError(OperationExec, CommandResult{}, err)
		}
		commandRequest.Args = d.execArgs(
			ref,
			scopedExecCommandArgs(stateDir, commandArgs),
			req.Env,
			req.WorkDir,
			req.Stdin != nil,
		)
		commandRequest.CancellationArgs = d.execCancellationArgs(ref, stateDir)
	}

	result, err := d.runExecCommand(ctx, commandRequest)
	execResult := &sandboxruntime.ExecResult{ExitCode: result.ExitCode}
	if result.CancellationTerminated && ctx != nil && ctx.Err() != nil {
		execResult.Cancellation = &sandboxruntime.ExecCancellationResult{Terminated: true}
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

func scopedExecCommandArgs(stateDir string, commandArgs []string) []string {
	args := []string{"sh", "-c", execWrapperScript, "hal-exec", stateDir}
	return append(args, commandArgs...)
}

func (d *Driver) execCancellationArgs(ref, stateDir string) []string {
	return []string{d.podmanPath, "exec", ref, "sh", "-c", execCancellationScript, "hal-exec-cancel", stateDir}
}

func newExecStateDirectory() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", fmt.Errorf("allocate rootless Podman exec identity: %w", err)
	}
	return execStateDirectoryPrefix + hex.EncodeToString(random), nil
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
