//go:build linux

package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestL5GuestInitSupervisesAgentProcessGroupAndReapsAllChildren(t *testing.T) {
	source, err := os.ReadFile("main_linux.go")
	if err != nil {
		t.Fatalf("ReadFile(main_linux.go) error = %v", err)
	}
	for _, marker := range []string{
		"os.Getpid() != 1",
		"Setpgid: true",
		"syscall.SIGCHLD",
		"unix.Wait4(-1",
		"unix.Kill(-childPID",
		"terminationGrace",
		"unix.SIGKILL",
		"waitForKilledChildren(reapContext, childPID, unix.Wait4)",
	} {
		if !strings.Contains(string(source), marker) {
			t.Errorf("guest PID1 supervisor missing %q", marker)
		}
	}
}

func TestL7GuestInitReapsKilledProcessTreeWithoutSignalNotification(t *testing.T) {
	const mainPID = 101
	const descendantPID = 202
	wantStatus := unix.WaitStatus(unix.SIGKILL)
	waitCalls := 0
	status, exited := waitForKilledChildren(context.Background(), mainPID, func(pid int, status *unix.WaitStatus, options int, _ *unix.Rusage) (int, error) {
		waitCalls++
		if pid != -1 {
			t.Fatalf("Wait4 pid = %d, want all children", pid)
		}
		if options != unix.WNOHANG {
			t.Fatalf("Wait4 options = %d, want nonblocking reap", options)
		}
		switch waitCalls {
		case 1:
			return -1, unix.EINTR
		case 2:
			*status = wantStatus
			return mainPID, nil
		case 3:
			*status = wantStatus
			return descendantPID, nil
		default:
			return -1, unix.ECHILD
		}
	})
	if !exited || status != wantStatus {
		t.Fatalf("waitForKilledChildren() = %v, %t, want killed main child status", status, exited)
	}
	if waitCalls != 4 {
		t.Fatalf("Wait4 calls = %d, want EINTR retry, main, descendant, and ECHILD", waitCalls)
	}
}

func TestL7GuestInitRetainsKilledMainStatusWhenDrainProofRacesDeadline(t *testing.T) {
	const mainPID = 303
	wantStatus := unix.WaitStatus(unix.SIGKILL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waitCalls := 0
	status, exited := waitForKilledChildren(ctx, mainPID, func(_ int, status *unix.WaitStatus, _ int, _ *unix.Rusage) (int, error) {
		waitCalls++
		if waitCalls == 1 {
			*status = wantStatus
			return mainPID, nil
		}
		cancel()
		return -1, unix.ECHILD
	})
	if !exited || status != wantStatus {
		t.Fatalf("waitForKilledChildren() = %v, %t, want killed main child after complete drain proof", status, exited)
	}
	if waitCalls != 2 {
		t.Fatalf("Wait4 calls = %d, want main and ECHILD", waitCalls)
	}
}

func TestL7GuestInitKilledProcessTreeReapHonorsFinalDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waitCalls := 0
	status, exited := waitForKilledChildren(ctx, 303, func(int, *unix.WaitStatus, int, *unix.Rusage) (int, error) {
		waitCalls++
		return 0, nil
	})
	if exited || status != 0 {
		t.Fatalf("waitForKilledChildren() = %v, %t, want bounded failure", status, exited)
	}
	if waitCalls != 1 {
		t.Fatalf("Wait4 calls = %d, want one nonblocking attempt before deadline", waitCalls)
	}
}

func TestL7GuestInitUnsupportedPlatformStubFailsClosed(t *testing.T) {
	source, err := os.ReadFile("main_other.go")
	if err != nil {
		t.Fatalf("ReadFile(main_other.go) error = %v", err)
	}
	if !strings.Contains(string(source), "os.Exit(127)") {
		t.Fatal("unsupported guest-init platform does not fail closed")
	}
}
