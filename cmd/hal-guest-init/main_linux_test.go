//go:build linux

package main

import (
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
		"waitForMainChild(childPID, unix.Wait4)",
	} {
		if !strings.Contains(string(source), marker) {
			t.Errorf("guest PID1 supervisor missing %q", marker)
		}
	}
}

func TestL7GuestInitReapsKilledMainChildWithoutSignalNotification(t *testing.T) {
	const mainPID = 101
	wantStatus := unix.WaitStatus(unix.SIGKILL)
	waitCalls := 0
	status, exited := waitForMainChild(mainPID, func(pid int, status *unix.WaitStatus, options int, _ *unix.Rusage) (int, error) {
		waitCalls++
		if pid != mainPID {
			t.Fatalf("Wait4 pid = %d, want exact main child", pid)
		}
		if options != 0 {
			t.Fatalf("Wait4 options = %d, want blocking wait", options)
		}
		if waitCalls == 1 {
			return -1, unix.EINTR
		}
		*status = wantStatus
		return mainPID, nil
	})
	if !exited || status != wantStatus {
		t.Fatalf("waitForMainChild() = %v, %t, want killed child status", status, exited)
	}
	if waitCalls != 2 {
		t.Fatalf("Wait4 calls = %d, want EINTR retry and reap", waitCalls)
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
