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
	env := map[string]string{"HAL_B": "2", "HAL_A": "1"}
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
	wantArgs := []string{
		"podman", "exec",
		"--interactive",
		"--workdir", "/workspace/project",
		"--env", "HAL_A=1",
		"--env", "HAL_B=2",
		"runtime-id",
		"sh", "-lc", "printf ok",
	}
	if !reflect.DeepEqual(request.Args, wantArgs) {
		t.Fatalf("exec args = %#v, want %#v", request.Args, wantArgs)
	}
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

	env["HAL_A"] = "mutated"
	if request.Env["HAL_A"] != "1" {
		t.Fatalf("env was not cloned before forwarding: %#v", request.Env)
	}
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

	wantArgs := []string{"podman", "exec", "hal-dev", "echo", "ok"}
	if !reflect.DeepEqual(runner.requests[0].Args, wantArgs) {
		t.Fatalf("exec args = %#v, want %#v", runner.requests[0].Args, wantArgs)
	}
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
