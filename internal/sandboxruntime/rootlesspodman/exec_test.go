package rootlesspodman_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
)

var _ sandboxruntime.ExecDriver = (*rootlesspodman.Driver)(nil)

func TestExecUsesFakeRunnerAndStreamsIO(t *testing.T) {
	stdin := bytes.NewBufferString("stdin payload")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	env := map[string]string{"HAL_B": "hal-env-value-b", "HAL_A": "hal-env-value-a"}
	runner := &streamingExecRunner{
		stdout: "stdout stream\n",
		stderr: "stderr stream\n",
	}
	driver := rootlesspodman.New(rootlesspodman.Options{ExecRunner: runner})
	target := sandboxruntime.Target{
		ID:   "container-id",
		Name: "hal-dev",
		Runtime: sandboxruntime.RuntimeState{
			RuntimeID: "runtime-id",
		},
	}

	result, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target:  target,
		Args:    []string{"sh", "-lc", "printf ok"},
		Env:     env,
		WorkDir: "/workspace/project",
		Stdin:   stdin,
		Stdout:  stdout,
		Stderr:  stderr,
	})
	if err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("Exec() result = %#v, want exit code 0", result)
	}
	if got := runner.stdin; got != "stdin payload" {
		t.Fatalf("runner stdin = %q, want forwarded stdin payload", got)
	}
	if got := stdout.String(); got != "stdout stream\n" {
		t.Fatalf("stdout = %q, want streamed stdout", got)
	}
	if got := stderr.String(); got != "stderr stream\n" {
		t.Fatalf("stderr = %q, want streamed stderr", got)
	}

	if len(runner.requests) != 1 {
		t.Fatalf("exec requests = %d, want 1", len(runner.requests))
	}
	request := runner.requests[0]
	wantPrefix := []string{
		"podman", "exec",
		"--interactive",
		"--workdir", "/workspace/project",
		"--env", "HAL_A",
		"--env", "HAL_B",
		"runtime-id",
	}
	assertDirectExecRequest(t, request, wantPrefix, []string{"sh", "-lc", "printf ok"})
	if request.Operation != rootlesspodman.OperationExec {
		t.Fatalf("operation = %q, want %q", request.Operation, rootlesspodman.OperationExec)
	}
	if !reflect.DeepEqual(request.Env, env) {
		t.Fatalf("env = %#v, want %#v", request.Env, env)
	}
	if request.WorkDir != "" {
		t.Fatalf("host workdir = %q, want empty because --workdir is a container path", request.WorkDir)
	}
	if request.Stdin != stdin {
		t.Fatalf("stdin reader was not forwarded")
	}
	if request.Stdout != stdout {
		t.Fatalf("stdout writer was not forwarded")
	}
	if request.Stderr != stderr {
		t.Fatalf("stderr writer was not forwarded")
	}
	argv := strings.Join(request.Args, "\x00")
	for _, value := range env {
		if strings.Contains(argv, value) {
			t.Fatalf("exec args contain environment value %q: %#v", value, request.Args)
		}
	}

	env["HAL_A"] = "mutated"
	if request.Env["HAL_A"] != "hal-env-value-a" {
		t.Fatalf("env was not cloned before forwarding: %#v", request.Env)
	}
}

func TestExecKeepsSecretEnvironmentValuesOutOfPodmanArgs(t *testing.T) {
	const secret = "sentinel-secret-that-must-not-enter-argv"
	runner := &streamingExecRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{ExecRunner: runner})

	if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: sandboxruntime.Target{Name: "hal-dev"},
		Args:   []string{"sh", "-c", "test -n \"$GITHUB_TOKEN\""},
		Env:    map[string]string{"GITHUB_TOKEN": secret},
	}); err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	request := runner.requests[0]
	if got := request.Env["GITHUB_TOKEN"]; got != secret {
		t.Fatalf("runner environment value = %q, want sentinel value", got)
	}
	if got := strings.Join(request.Args, "\x00"); strings.Contains(got, secret) {
		t.Fatalf("exec args contain secret value: %#v", request.Args)
	}
	assertDirectExecRequest(
		t,
		request,
		[]string{"podman", "exec", "--env", "GITHUB_TOKEN", "hal-dev"},
		[]string{"sh", "-c", "test -n \"$GITHUB_TOKEN\""},
	)
}

func TestExecOmitsOptionalPodmanArgsWhenUnset(t *testing.T) {
	runner := &streamingExecRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{ExecRunner: runner})

	if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: sandboxruntime.Target{Name: "hal-dev"},
		Args:   []string{"echo", "ok"},
	}); err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	assertDirectExecRequest(
		t,
		runner.requests[0],
		[]string{"podman", "exec", "hal-dev"},
		[]string{"echo", "ok"},
	)
}

func TestExecCancellationProofUsesScopedWrapper(t *testing.T) {
	runner := &streamingExecRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{ExecRunner: runner})

	if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target:                               sandboxruntime.Target{Name: "hal-dev"},
		Args:                                 []string{"echo", "ok"},
		RequireProcessGroupCancellationProof: true,
	}); err != nil {
		t.Fatalf("Exec() unexpected error: %v", err)
	}

	assertScopedExecRequest(
		t,
		runner.requests[0],
		[]string{
			"podman", "exec",
			"--env", "HAL_INTERNAL_EXEC_CANCEL_STATE",
			"--env", "HAL_INTERNAL_EXEC_CANCEL_TOKEN",
			"hal-dev",
		},
		[]string{"echo", "ok"},
	)
}

func TestExecFailuresWrapOperationWithSanitizedOutput(t *testing.T) {
	runnerErr := errors.New("podman exec failed password=raw-secret from /Users/alice/worktree")
	runner := &fakeCommandRunner{
		resultByOperation: map[string]rootlesspodman.CommandResult{
			rootlesspodman.OperationExec: {
				ExitCode: 126,
				Stdout:   "using /Users/alice/project\n",
				Stderr:   "refusing /var/run/docker.sock token=abcd1234\n",
			},
		},
		errByOperation: map[string]error{
			rootlesspodman.OperationExec: runnerErr,
		},
	}
	driver := rootlesspodman.New(rootlesspodman.Options{ExecRunner: runner})

	result, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: sandboxruntime.Target{Name: "hal-dev"},
		Args:   []string{"hal", "status"},
	})
	if err == nil {
		t.Fatal("Exec() expected error, got nil")
	}
	if result == nil || result.ExitCode != 126 {
		t.Fatalf("Exec() result = %#v, want exit code 126", result)
	}
	if !errors.Is(err, runnerErr) {
		t.Fatalf("errors.Is(%v, runnerErr) = false, want true", err)
	}
	var opErr *rootlesspodman.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("errors.As(%T) = false, want true", opErr)
	}
	if opErr.Driver != sandboxruntime.DriverRootlessPodman || opErr.Operation != rootlesspodman.OperationExec || opErr.ExitCode != 126 {
		t.Fatalf("OperationError = %#v, want rootless exec exit 126", opErr)
	}
	message := err.Error()
	for _, unsafe := range []string{"/Users/alice", "/var/run/docker.sock", "raw-secret", "abcd1234"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("error message %q contains unsafe detail %q", message, unsafe)
		}
	}
	for _, want := range []string{sandboxruntime.DriverRootlessPodman, rootlesspodman.OperationExec, "[redacted-path]", "[redacted-docker-socket]", "token=[redacted]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("error message %q does not include sanitized detail %q", message, want)
		}
	}
}

func TestExecContextCancellationRemainsObservable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &streamingExecRunner{}
	driver := rootlesspodman.New(rootlesspodman.Options{ExecRunner: runner})

	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: sandboxruntime.Target{Name: "hal-dev"},
		Args:   []string{"hal", "status"},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Exec() error = %v, want errors.Is context.Canceled", err)
	}
	if result == nil || result.ExitCode != -1 {
		t.Fatalf("Exec() result = %#v, want exit code -1", result)
	}
	if len(runner.requests) != 0 {
		t.Fatalf("runner was called after context cancellation: %#v", runner.requests)
	}
}

func TestExecRejectsMissingRunnerTargetAndArgs(t *testing.T) {
	driver := rootlesspodman.New(rootlesspodman.Options{})
	if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: sandboxruntime.Target{Name: "hal-dev"},
		Args:   []string{"hal", "status"},
	}); !errors.Is(err, rootlesspodman.ErrExecRunnerRequired) {
		t.Fatalf("Exec() error = %v, want ErrExecRunnerRequired", err)
	}

	driver = rootlesspodman.New(rootlesspodman.Options{ExecRunner: &fakeCommandRunner{}})
	for _, tt := range []struct {
		name string
		req  sandboxruntime.ExecRequest
		want error
	}{
		{
			name: "missing args",
			req: sandboxruntime.ExecRequest{
				Target: sandboxruntime.Target{Name: "hal-dev"},
			},
			want: rootlesspodman.ErrExecArgsRequired,
		},
		{
			name: "missing target reference",
			req: sandboxruntime.ExecRequest{
				Args: []string{"hal", "status"},
			},
			want: rootlesspodman.ErrTargetRefRequired,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := driver.Exec(context.Background(), tt.req); !errors.Is(err, tt.want) {
				t.Fatalf("Exec() error = %v, want %v", err, tt.want)
			}
		})
	}
}

type streamingExecRunner struct {
	requests []rootlesspodman.CommandRequest
	stdin    string
	stdout   string
	stderr   string
}

func assertDirectExecRequest(t *testing.T, request rootlesspodman.CommandRequest, wantPrefix, wantCommand []string) {
	t.Helper()
	want := append(append([]string(nil), wantPrefix...), wantCommand...)
	if !reflect.DeepEqual(request.Args, want) {
		t.Fatalf("exec args = %#v, want direct command %#v", request.Args, want)
	}
	if len(request.CancellationArgs) != 0 {
		t.Fatalf("exec cancellation args = %#v, want no guest helper for ordinary exec", request.CancellationArgs)
	}
}

func assertScopedExecRequest(t *testing.T, request rootlesspodman.CommandRequest, wantPrefix, wantCommand []string) {
	t.Helper()
	const wrapperFieldCount = 4
	if len(request.Args) != len(wantPrefix)+wrapperFieldCount+len(wantCommand) {
		t.Fatalf("exec args = %#v, want prefix %#v plus scoped wrapper and command %#v", request.Args, wantPrefix, wantCommand)
	}
	if got := request.Args[:len(wantPrefix)]; !reflect.DeepEqual(got, wantPrefix) {
		t.Fatalf("exec args prefix = %#v, want %#v", got, wantPrefix)
	}
	wrapper := request.Args[len(wantPrefix) : len(wantPrefix)+wrapperFieldCount]
	if wrapper[0] != "sh" || wrapper[1] != "-c" || wrapper[3] != "hal-exec" {
		t.Fatalf("exec wrapper args = %#v, want job-scoped shell wrapper", wrapper)
	}
	if !strings.Contains(wrapper[2], "setsid") || !strings.Contains(wrapper[2], `"$state_dir/cancel"`) {
		t.Fatalf("exec wrapper does not own a scoped process group: %q", wrapper[2])
	}
	stateDir := request.Env["HAL_INTERNAL_EXEC_CANCEL_STATE"]
	token := request.Env["HAL_INTERNAL_EXEC_CANCEL_TOKEN"]
	if !strings.HasPrefix(stateDir, "/tmp/.hal-exec-") || len(strings.TrimPrefix(stateDir, "/tmp/.hal-exec-")) != 32 {
		t.Fatalf("exec state directory = %q, want random private container path", stateDir)
	}
	if len(token) != 32 {
		t.Fatalf("exec cancellation token length = %d, want random opaque token", len(token))
	}
	if got := request.Args[len(wantPrefix)+wrapperFieldCount:]; !reflect.DeepEqual(got, wantCommand) {
		t.Fatalf("exec command args = %#v, want %#v", got, wantCommand)
	}
	wantCancellationPrefix := []string{"podman", "exec", "--env", "HAL_INTERNAL_EXEC_CANCEL_TOKEN=" + token, wantPrefix[len(wantPrefix)-1], "sh", "-c"}
	if len(request.CancellationArgs) != len(wantCancellationPrefix)+3 ||
		!reflect.DeepEqual(request.CancellationArgs[:len(wantCancellationPrefix)], wantCancellationPrefix) {
		t.Fatalf("exec cancellation args = %#v, want prefix %#v", request.CancellationArgs, wantCancellationPrefix)
	}
	if request.CancellationArgs[len(wantCancellationPrefix)+1] != "hal-exec-cancel" ||
		request.CancellationArgs[len(wantCancellationPrefix)+2] != stateDir {
		t.Fatalf("exec cancellation args = %#v, want matching scoped state %q", request.CancellationArgs, stateDir)
	}
	cancellationScript := request.CancellationArgs[len(wantCancellationPrefix)]
	if !strings.Contains(cancellationScript, `printf "%s\n" "$token" >"$cancel_fifo"`) ||
		!strings.Contains(wrapper[2], "kill -KILL 0") {
		t.Fatalf("exec cancellation script does not terminate the scoped process group: %q", cancellationScript)
	}
	for _, arg := range request.CancellationArgs {
		if arg == "stop" {
			t.Fatalf("exec cancellation used container-wide stop: %#v", request.CancellationArgs)
		}
	}
}

func (r *streamingExecRunner) RunExecCommand(ctx context.Context, req rootlesspodman.CommandRequest) (rootlesspodman.CommandResult, error) {
	if err := ctx.Err(); err != nil {
		return rootlesspodman.CommandResult{ExitCode: -1}, err
	}
	r.requests = append(r.requests, req)
	if req.Stdin != nil {
		content, err := io.ReadAll(req.Stdin)
		if err != nil {
			return rootlesspodman.CommandResult{ExitCode: -1}, err
		}
		r.stdin = string(content)
	}
	if req.Stdout != nil {
		if _, err := req.Stdout.Write([]byte(r.stdout)); err != nil {
			return rootlesspodman.CommandResult{ExitCode: -1}, err
		}
	}
	if req.Stderr != nil {
		if _, err := req.Stderr.Write([]byte(r.stderr)); err != nil {
			return rootlesspodman.CommandResult{ExitCode: -1}, err
		}
	}
	return rootlesspodman.CommandResult{ExitCode: 0}, nil
}
