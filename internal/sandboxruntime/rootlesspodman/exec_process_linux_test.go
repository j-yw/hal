//go:build linux

package rootlesspodman

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecProcessOutputPreservesCaptureStreamingAndExitStatus(t *testing.T) {
	for _, exitCode := range []int{0, 7} {
		for _, streaming := range []bool{false, true} {
			t.Run(strconv.Itoa(exitCode)+"/streaming="+strconv.FormatBool(streaming), func(t *testing.T) {
				var stdout, stderr bytes.Buffer
				request := CommandRequest{
					Args:  []string{"sh", "-c", `cat; printf stdout; printf stderr >&2; exit "$1"`, "output", strconv.Itoa(exitCode)},
					Stdin: strings.NewReader("stdin-"),
				}
				if streaming {
					request.Stdout, request.Stderr = &stdout, &stderr
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				result, err := runDefaultExecCommand(ctx, request)
				if (err != nil) != (exitCode != 0) || result.ExitCode != exitCode {
					t.Fatalf("result = %#v, %v, want exit %d", result, err, exitCode)
				}
				if result.CancellationProcessGroupTerminated {
					t.Fatal("normal completion claimed cancellation proof")
				}
				if streaming {
					if stdout.String() != "stdin-stdout" || stderr.String() != "stderr" || result.Stdout != "" || result.Stderr != "" {
						t.Fatalf("streamed stdout=%q stderr=%q, captured=%#v", stdout.String(), stderr.String(), result)
					}
				} else if result.Stdout != "stdin-stdout" || result.Stderr != "stderr" {
					t.Fatalf("captured result = %#v", result)
				}
			})
		}
	}
}

func TestExecProcessDrainsDescendantOutputAfterLeaderExit(t *testing.T) {
	dir := t.TempDir()
	leaderPath, childPath, releasePath := dir+"/leader.pid", dir+"/child.pid", dir+"/release"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resultCh := make(chan error, 1)
	var result CommandResult
	go func() {
		var err error
		result, err = runDefaultExecCommand(ctx, CommandRequest{
			Args: []string{"sh", "-c", `printf '%s' "$$" > "$LEADER"; sh -c 'printf "%s" "$$" > "$CHILD"; while [ ! -e "$RELEASE" ]; do sleep 0.01; done; printf delayed-stdout; printf delayed-stderr >&2' & exit 7`},
			Env:  map[string]string{"LEADER": leaderPath, "CHILD": childPath, "RELEASE": releasePath},
		})
		resultCh <- err
	}()
	childPID := waitForL2PIDFile(t, childPath)
	t.Cleanup(func() { _ = syscall.Kill(childPID, syscall.SIGKILL) })
	leaderPID := waitForL2PIDFile(t, leaderPath)
	deadline := time.Now().Add(time.Second)
	for l2ProcessAlive(leaderPID) {
		if time.Now().After(deadline) {
			t.Fatal("leader did not exit before descendant output was released")
		}
		time.Sleep(time.Millisecond)
	}
	assertL2LeaderUnreaped(t, leaderPID)
	select {
	case err := <-resultCh:
		t.Fatalf("exec returned before descendant output drained: %v", err)
	default:
	}
	if !l2ProcessAlive(childPID) {
		t.Fatal("normal leader exit terminated its descendant")
	}
	if err := os.WriteFile(releasePath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-resultCh:
		if err == nil || errors.Is(err, context.DeadlineExceeded) || result.ExitCode != 7 {
			t.Fatalf("result = %#v, %v, want leader exit 7", result, err)
		}
		if result.Stdout != "delayed-stdout" || result.Stderr != "delayed-stderr" {
			t.Fatalf("descendant output was lost: %#v", result)
		}
		if result.CancellationProcessGroupTerminated {
			t.Fatal("normal output drain claimed cancellation proof")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec did not complete after descendant output drained")
	}
}

func TestExecProcessStartFailureClosesOutputPipes(t *testing.T) {
	// Initialize the runtime's poller before counting descriptors.
	if _, err := runDefaultExecCommand(context.Background(), CommandRequest{Args: []string{"sh", "-c", "exit 0"}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	missing := t.TempDir() + "/missing-executable"
	for range 20 {
		result, err := runDefaultExecCommand(context.Background(), CommandRequest{Args: []string{missing}})
		if !errors.Is(err, os.ErrNotExist) || result.ExitCode != -1 {
			t.Fatalf("start failure = %#v, %v", result, err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("start failures leaked descriptors: before=%d after=%d", len(before), len(after))
	}
}

func TestExecProcessPreservesOutputLimitErrors(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			result, err := runDefaultExecCommand(ctx, CommandRequest{
				Args:           []string{executable, "-test.run=^TestLifecycleCommandOutputHelper$"},
				Env:            map[string]string{"HAL_ROOTLESS_PODMAN_OUTPUT_HELPER": stream},
				MaxStdoutBytes: 1024,
				MaxStderrBytes: 1024,
			})
			if !errors.Is(err, ErrCommandOutputLimitExceeded) {
				t.Fatalf("output error = %v, want output-limit sentinel", err)
			}
			if len(result.Stdout) > 1024 || len(result.Stderr) > 1024 {
				t.Fatalf("captured output exceeded its bound: stdout=%d stderr=%d", len(result.Stdout), len(result.Stderr))
			}
		})
	}
}

func TestExecProcessPreservesWriterErrors(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			request := CommandRequest{Args: []string{"sh", "-c", "printf stdout; printf stderr >&2"}}
			if stream == "stdout" {
				request.Stdout = execFailingWriter{}
			} else {
				request.Stderr = execFailingWriter{}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := runDefaultExecCommand(ctx, request); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("writer error = %v, want io.ErrClosedPipe", err)
			}
		})
	}
}

type execFailingWriter struct{}

func (execFailingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
