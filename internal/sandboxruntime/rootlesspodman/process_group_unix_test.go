//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package rootlesspodman

import (
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestTerminateExecProcessGroupWaitsForCommandWaitAfterKill(t *testing.T) {
	waitCh := make(chan error, 1)
	resultCh := make(chan error, 1)
	cmd := &exec.Cmd{Process: &os.Process{Pid: (1 << 30) - 1}}
	go func() {
		resultCh <- terminateExecProcessGroupAfter(cmd, waitCh, 5*time.Millisecond)
	}()

	select {
	case err := <-resultCh:
		t.Fatalf("termination returned before cmd.Wait completed: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	waitErr := errors.New("wait completed")
	waitCh <- waitErr
	select {
	case err := <-resultCh:
		if !errors.Is(err, waitErr) {
			t.Fatalf("termination error = %v, want cmd.Wait result", err)
		}
	case <-time.After(time.Second):
		t.Fatal("termination did not return after cmd.Wait completed")
	}
}
