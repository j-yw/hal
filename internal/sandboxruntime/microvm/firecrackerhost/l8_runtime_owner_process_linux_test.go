//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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

func TestL8RuntimeOwnerReplacementClosesEveryOwnedPidfdOnFailure(t *testing.T) {
	seed := l8RuntimeOwnerTestSeed()
	record := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "running", "unclaimed", 2
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	fd := int(reader.Fd())
	observation := l8RuntimeOwnerProcessObservation{PID: record.FirecrackerPID, ParentPID: 1, StartTime: record.FirecrackerStartTime, state: 'S', pidfd: fd, pidfdOwned: true}
	_, gotErr := containL8RuntimeOwnerReplacement(record, l8RuntimeOwnerReplacementOps{
		CurrentBootID: func() (string, error) { return record.HostBootID, nil },
		InspectSupervisor: func(uint32) (l8RuntimeOwnerProcessObservation, bool, error) {
			return l8RuntimeOwnerProcessObservation{}, false, nil
		},
		InspectChild:       func(uint32) (l8RuntimeOwnerProcessObservation, bool, error) { return observation, true, nil },
		SignalKill:         func(l8RuntimeOwnerProcessObservation) error { return errors.New("private signal path") },
		WaitTerminal:       func(context.Context, l8RuntimeOwnerProcessObservation) error { return errors.New("private wait path") },
		ProcessAbsent:      func(uint32) (bool, error) { return false, nil },
		AcquisitionBarrier: func() error { return nil },
		RecordAbsent:       func(l8RuntimeOwnerAbsenceObservation) (uint64, error) { return 0, errors.New("must not record absent") },
		RecordUncertain:    func() (uint64, error) { return 3, nil },
		Now:                func() time.Time { return time.Unix(1, 0) },
	})
	if !errors.Is(gotErr, errL8RuntimeOwnerInvalid) {
		t.Fatalf("replacement = %v", gotErr)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("pidfd still open: %v", err)
	}
	_ = reader.Close()
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
