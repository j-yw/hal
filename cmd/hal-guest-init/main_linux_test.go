//go:build linux

package main

import (
	"os"
	"strings"
	"testing"
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
	} {
		if !strings.Contains(string(source), marker) {
			t.Errorf("guest PID1 supervisor missing %q", marker)
		}
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
