//go:build linux

package rootlesspodman

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestL2DefaultExecCancellationTerminatesDescendantProcessGroup(t *testing.T) {
	for _, test := range []struct {
		name, script string
	}{
		{"leader ignores term", `trap '' TERM; sleep 30 & child=$!; printf '%s' "$child" > "$L2_PID_FILE"; wait "$child"`},
		{"leader exits before descendant", `trap 'exit 0' TERM; sh -c 'trap "" TERM; printf "%s" "$$" > "$L2_PID_FILE"; exec sleep 30' & wait "$!"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			testL2ExecCancellationDescendant(t, test.script)
		})
	}
}

func testL2ExecCancellationDescendant(t *testing.T, script string) {
	t.Helper()
	pidPath := t.TempDir() + "/descendant.pid"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan error, 1)
	go func() {
		_, err := (DefaultCommandRunner{}).RunExecCommand(ctx, CommandRequest{
			Operation: OperationExec,
			Args: []string{
				"sh",
				"-c",
				script,
			},
			Env: map[string]string{"L2_PID_FILE": pidPath},
		})
		resultCh <- err
	}()

	descendantPID := waitForL2PIDFile(t, pidPath)
	t.Cleanup(func() {
		_ = syscall.Kill(descendantPID, syscall.SIGKILL)
	})

	cancel()
	select {
	case err := <-resultCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("RunExecCommand() error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunExecCommand() did not return after cancellation")
	}

	// SIGKILL delivery to a descendant need not complete before the leader is
	// reaped. Observe the result within a bound rather than racing the scheduler.
	deadline := time.Now().Add(time.Second)
	for l2ProcessAlive(descendantPID) {
		if time.Now().After(deadline) {
			t.Fatalf("descendant process %d remained alive after daemon-owned exec cancellation", descendantPID)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestL2DefaultExecStreamingDoesNotDuplicateOutputCapture(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result, err := (DefaultCommandRunner{}).RunExecCommand(context.Background(), CommandRequest{
		Operation: OperationExec,
		Args:      []string{"sh", "-c", `printf stdout; printf stderr >&2`},
		Stdout:    &stdout,
		Stderr:    &stderr,
	})
	if err != nil {
		t.Fatalf("RunExecCommand() error = %v", err)
	}
	if stdout.String() != "stdout" || stderr.String() != "stderr" {
		t.Fatalf("streamed output = stdout %q stderr %q", stdout.String(), stderr.String())
	}
	if result.Stdout != "" || result.Stderr != "" {
		t.Fatalf("captured result = stdout %q stderr %q, want no duplicate streaming capture", result.Stdout, result.Stderr)
	}
}

func TestL2DefaultExecCancellationAfterLeaderExitWithDescendantOutput(t *testing.T) {
	for _, helper := range []string{"absent", "success", "failure"} {
		t.Run(helper, func(t *testing.T) {
			testL2ExecLateCancellation(t, helper)
		})
	}
}

func testL2ExecLateCancellation(t *testing.T, helper string) {
	t.Helper()
	dir := t.TempDir()
	pidPath, leaderPath := dir+"/descendant.pid", dir+"/leader.pid"
	helperPath := dir + "/cleanup-called"
	var cancellationArgs []string
	if helper != "absent" {
		exitCode := "0"
		if helper == "failure" {
			exitCode = "1"
		}
		cancellationArgs = []string{"sh", "-c", `printf called >> "$1"; exit "$2"`, "cleanup", helperPath, exitCode}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan error, 1)
	var result CommandResult
	go func() {
		var err error
		result, err = (DefaultCommandRunner{}).RunExecCommand(ctx, CommandRequest{
			Operation:        OperationExec,
			Args:             []string{"sh", "-c", `printf '%s' "$$" > "$L2_LEADER_PID_FILE"; sh -c 'trap "" TERM; printf "%s" "$$" > "$L2_PID_FILE"; exec sleep 30' & exit 0`},
			Env:              map[string]string{"L2_PID_FILE": pidPath, "L2_LEADER_PID_FILE": leaderPath},
			CancellationArgs: cancellationArgs,
		})
		resultCh <- err
	}()
	descendantPID := waitForL2PIDFile(t, pidPath)
	t.Cleanup(func() { _ = syscall.Kill(descendantPID, syscall.SIGKILL) })
	leaderPID := waitForL2PIDFile(t, leaderPath)
	deadline := time.Now().Add(time.Second)
	for l2ProcessAlive(leaderPID) {
		if time.Now().After(deadline) {
			t.Fatal("fixture leader did not exit independently of cancellation")
		}
		time.Sleep(time.Millisecond)
	}
	if !l2ProcessAlive(descendantPID) {
		t.Fatal("fixture descendant exited before cancellation")
	}
	assertL2LeaderUnreaped(t, leaderPID)
	select {
	case err := <-resultCh:
		t.Fatalf("exec returned before descendant output completed: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-resultCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("late cancellation = %v, want context.Canceled", err)
		}
		if helper == "failure" && !strings.Contains(err.Error(), "cleanup failed") {
			t.Fatalf("failed cancellation helper error was lost: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("late cancellation was ignored while descendant retained stdout")
	}
	if result.CancellationProcessGroupTerminated != (helper == "success") {
		t.Fatalf("cancellation proof = %v for %s helper", result.CancellationProcessGroupTerminated, helper)
	}
	if helper != "absent" {
		data, err := os.ReadFile(helperPath)
		if err != nil || string(data) != "called" {
			t.Fatalf("cancellation helper execution = %q, %v, want exactly once", data, err)
		}
	}
	var info unix.Siginfo
	if err := unix.Waitid(unix.P_PID, leaderPID, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil); !errors.Is(err, unix.ECHILD) {
		t.Fatalf("leader was not reaped after cancellation: %v", err)
	}
	deadline = time.Now().Add(time.Second)
	for l2ProcessAlive(descendantPID) {
		if time.Now().After(deadline) {
			t.Fatal("late cancellation left descendant alive")
		}
		time.Sleep(time.Millisecond)
	}
}

func assertL2LeaderUnreaped(t *testing.T, pid int) {
	t.Helper()
	var info unix.Siginfo
	if err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil); err != nil {
		t.Fatalf("leader was reaped before output drained, losing the process-group identity anchor: %v", err)
	}
}

func waitForL2PIDFile(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(data)) != "" {
			pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
			if err != nil {
				t.Fatalf("parse descendant PID: %v", err)
			}
			return pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("descendant PID file was not created")
	return 0
}

func l2ProcessAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	stat, readErr := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if readErr == nil {
		fields := strings.Fields(string(stat))
		if len(fields) > 2 && fields[2] == "Z" {
			return false
		}
	}
	return true
}
