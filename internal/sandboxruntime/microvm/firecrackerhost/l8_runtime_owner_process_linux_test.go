//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestL8RuntimeOwnerProcessIdentityIncludesExactParentAndStart(t *testing.T) {
	fields := []string{"S", "77"}
	for index := 0; index < 17; index++ {
		fields = append(fields, strconv.Itoa(index+1))
	}
	fields = append(fields, "424242")
	payload := []byte("123 (firecracker ) helper) " + strings.Join(fields, " ") + "\n")
	parent, start, state, err := parseL8RuntimeOwnerProcIdentity(payload, 123)
	if err != nil || parent != 77 || start != 424242 || state != 'S' {
		t.Fatalf("process identity = parent %d start %d state %q, %v", parent, start, state, err)
	}
	for _, malformed := range [][]byte{
		[]byte("123 (firecracker) S 0 1 2\n"),
		[]byte("123 (firecracker) S bad " + strings.Repeat("1 ", 20)),
		[]byte("124 (firecracker) " + strings.Join(fields, " ") + "\n"),
	} {
		if _, _, _, err := parseL8RuntimeOwnerProcIdentity(malformed, 123); !errors.Is(err, errL8RuntimeOwnerInvalid) {
			t.Fatalf("malformed process identity = %v", err)
		}
	}
}

func TestL8RuntimeOwnerPidfdSignalTerminalAndProcAbsenceAreDistinct(t *testing.T) {
	path, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep executable unavailable")
	}
	command := exec.Command(path, "30")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	reaped := false
	defer func() {
		if !reaped {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()
	observation, err := inspectL8RuntimeOwnerProcess(uint32(command.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer observation.Close()
	if observation.ParentPID != uint32(syscall.Getpid()) || observation.state == 'Z' {
		t.Fatalf("child observation = %#v", observation)
	}
	if err := signalL8RuntimeOwnerProcess(observation, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := waitL8RuntimeOwnerProcessTerminal(ctx, observation); err != nil {
		t.Fatal(err)
	}
	if absent, err := inspectL8RuntimeOwnerProcessAbsent(observation.PID); err != nil || absent {
		t.Fatalf("unreaped child absence = %t, %v", absent, err)
	}
	if err := command.Wait(); err == nil {
		t.Fatal("SIGKILL child unexpectedly exited successfully")
	}
	reaped = true
	if absent, err := inspectL8RuntimeOwnerProcessAbsent(observation.PID); err != nil || !absent {
		t.Fatalf("reaped child absence = %t, %v", absent, err)
	}
}
