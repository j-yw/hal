//go:build linux

package rootlesspodman

import (
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestTerminateExecProcessGroupKeepsExitedLeaderUnreapedUntilObserved(t *testing.T) {
	cmd := exec.Command("sh", "-c", "exit 0")
	configureExecProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}

	exitObserved := make(chan struct{})
	releaseObservation := make(chan struct{})
	completion := observeExecProcessWith(cmd, func(pid int) error {
		err := waitForExecProcessExit(pid)
		close(exitObserved)
		<-releaseObservation
		return err
	})
	select {
	case <-exitObserved:
	case <-time.After(time.Second):
		t.Fatal("process exit was not observed")
	}
	if cmd.ProcessState != nil {
		t.Fatal("process was reaped before cancellation decided whether to signal its group")
	}

	result := make(chan error, 1)
	go func() {
		result <- terminateExecProcessGroupAfter(cmd, completion, 5*time.Millisecond)
	}()
	select {
	case err := <-result:
		t.Fatalf("termination returned before observation was published: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	if cmd.ProcessState != nil {
		t.Fatal("process was reaped while its process-group ID was still in use")
	}

	close(releaseObservation)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("termination error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("termination did not finish after observation was published")
	}
	if cmd.ProcessState == nil {
		t.Fatal("process was not reaped after process-group signaling finished")
	}
}

func TestExecProcessObservationFailureKillsAndReapsWithoutGroupSignal(t *testing.T) {
	cmd := exec.Command("sh", "-c", "sleep 30")
	configureExecProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start command: %v", err)
	}
	observationErr := errors.New("observation failed")
	if err := waitExecProcess(cmd, observationErr); !errors.Is(err, observationErr) {
		t.Fatalf("waitExecProcess() error = %v, want observation failure", err)
	}
	if cmd.ProcessState == nil {
		t.Fatal("process was not reaped after observation failure")
	}
}
