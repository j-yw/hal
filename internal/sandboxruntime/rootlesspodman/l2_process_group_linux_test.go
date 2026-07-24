//go:build linux

package rootlesspodman

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestL2DefaultExecCancellationTerminatesDescendantProcessGroup(t *testing.T) {
	pidPath := t.TempDir() + "/descendant.pid"
	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan error, 1)
	go func() {
		_, err := (DefaultCommandRunner{}).RunExecCommand(ctx, CommandRequest{
			Operation: OperationExec,
			Args: []string{
				"sh",
				"-c",
				`trap '' TERM; sleep 30 & child=$!; printf '%s' "$child" > "$L2_PID_FILE"; wait "$child"`,
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

	if l2ProcessAlive(descendantPID) {
		t.Fatalf("descendant process %d remained alive after daemon-owned exec cancellation", descendantPID)
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
	return err == nil || errors.Is(err, syscall.EPERM)
}
