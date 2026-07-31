package rootlesspodman

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDefaultCommandRunnerBoundsLifecycleOutputBeforeCapture(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error: %v", err)
	}

	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			request := CommandRequest{
				Operation: OperationInspect,
				Args:      []string{executable, "-test.run=^TestDefaultCommandRunnerOutputHelper$"},
				Env:       map[string]string{"HAL_ROOTLESS_PODMAN_OUTPUT_HELPER": stream},
			}
			if stream == "stdout" {
				request.MaxStdoutBytes = 1024
			} else {
				request.MaxStderrBytes = 1024
			}

			result, err := (DefaultCommandRunner{}).RunLifecycleCommand(ctx, request)
			if !errors.Is(err, ErrCommandOutputLimitExceeded) {
				t.Fatalf("RunLifecycleCommand() error = %v, want output-limit sentinel", err)
			}
			if len(result.Stdout) > 1024 || len(result.Stderr) > 1024 {
				t.Fatalf("captured output lengths = stdout:%d stderr:%d, want both bounded", len(result.Stdout), len(result.Stderr))
			}
			if strings.Contains(err.Error(), "private-output-canary") {
				t.Fatalf("output-limit error leaked command output: %v", err)
			}
		})
	}
}

func TestDefaultCommandRunnerZeroOutputLimitsPreserveCapture(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error: %v", err)
	}
	result, err := (DefaultCommandRunner{}).RunLifecycleCommand(context.Background(), CommandRequest{
		Operation: OperationInspect,
		Args:      []string{executable, "-test.run=^TestDefaultCommandRunnerOutputHelper$"},
		Env:       map[string]string{"HAL_ROOTLESS_PODMAN_OUTPUT_HELPER": "compatible"},
	})
	if err != nil {
		t.Fatalf("RunLifecycleCommand() error: %v", err)
	}
	if result.ExitCode != 0 || result.Stdout != "compatible-stdout" || result.Stderr != "compatible-stderr" {
		t.Fatalf("RunLifecycleCommand() result = %#v, want unchanged zero-limit capture", result)
	}
}

func TestDefaultCommandRunnerOutputHelper(t *testing.T) {
	switch os.Getenv("HAL_ROOTLESS_PODMAN_OUTPUT_HELPER") {
	case "stdout":
		_, _ = os.Stdout.Write([]byte(strings.Repeat("private-output-canary", 1<<16)))
	case "stderr":
		_, _ = os.Stderr.Write([]byte(strings.Repeat("private-output-canary", 1<<16)))
	case "compatible":
		_, _ = os.Stdout.Write([]byte("compatible-stdout"))
		_, _ = os.Stderr.Write([]byte("compatible-stderr"))
	default:
		return
	}
	os.Exit(0)
}

func TestCancellationProofRequiresExecutedSuccessfulHelper(t *testing.T) {
	helperArgs := []string{"podman", "exec", "target", "cancel"}
	tests := []struct {
		name      string
		attempted bool
		args      []string
		err       error
		want      bool
	}{
		{name: "successful helper", attempted: true, args: helperArgs, want: true},
		{name: "natural completion race", args: helperArgs},
		{name: "missing helper", attempted: true},
		{name: "failed helper", attempted: true, args: helperArgs, err: errors.New("failed")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := cancellationProcessGroupTerminationProven(test.attempted, test.args, test.err); got != test.want {
				t.Fatalf("cancellationProcessGroupTerminationProven() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestCancellationHelperProvesObservedProcessGroupDisappeared(t *testing.T) {
	for _, required := range []string{
		"ps -eo pgid=,args=",
		"matching_pgids",
		"observed_pgid",
		"ps -eo pgid=",
	} {
		if !strings.Contains(execCancellationScript, required) {
			t.Fatalf("exec cancellation helper lacks process-group proof marker %q", required)
		}
	}
	if strings.Contains(execCancellationScript, `token=$2`) {
		t.Fatal("exec cancellation helper accepts its proof token through observable argv")
	}
}
