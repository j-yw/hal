//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// Uses the actual dispatcher/admission and real descriptor closure, injecting
// only a reported close failure after that close has actually been attempted.
func runMinimalControlCloseFixture(t *testing.T, f *minimalControlAdmissionFixture, mode string, failClose int, consume func(*minimalControlSupervisorAdmission) error) (int, [8]int, int) {
	t.Helper()
	imports := map[int]int{}
	var closes [8]int
	legacy := 0
	open := func(number uintptr, role string) (int, error) {
		if number < 3 || number > 10 || role != minimalControlTestRoles[number-3] {
			t.Fatal("wrong role")
		}
		fd := int(f.files[number-3].Fd())
		imports[fd] = int(number) - 3
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		return fd, nil
	}
	closeFD := func(fd int) error {
		i, ok := imports[fd]
		if !ok {
			t.Fatal("unowned/repeated descriptor close")
		}
		delete(imports, fd)
		closes[i]++
		err := f.files[i].Close()
		if i+3 == failClose {
			return unix.EIO
		}
		return err
	}
	code := runPrivateL8RuntimeOwnerExecutableWithOps([]string{mode}, l8RuntimeOwnerExecutableOps{
		OpenFD: open, CloseFD: closeFD,
		RunSupervisor: func([6]int) error { legacy++; return nil },
		RunChildGate:  func([6]int) error { legacy++; return nil },
		SelectSupervisor: func(fds [6]int) (bool, error) {
			return withMinimalControlSupervisorAdmission(fds, open, closeFD, uint32(os.Geteuid()), consume)
		},
	})
	if len(imports) != 0 {
		t.Fatal("import closure was skipped")
	}
	return code, closes, legacy
}

func TestMinimalControlConfigEverySelectedCloseErrorFails(t *testing.T) {
	for role := 3; role <= 10; role++ {
		t.Run(strconv.Itoa(role), func(t *testing.T) {
			requireMinimalControlAdmission(t)
			f := newMinimalControlAdmissionFixture(t)
			admitted := 0
			var key []byte
			code, closes, legacy := runMinimalControlCloseFixture(t, f, "supervise", role, func(a *minimalControlSupervisorAdmission) error {
				admitted++
				key = a.controllerKey
				return nil
			})
			wantAdmitted := 1
			if role == 10 {
				wantAdmitted = 0
			}
			if code != 127 || legacy != 0 || admitted != wantAdmitted {
				t.Fatalf("close failure exit=%d legacy=%d admitted=%d", code, legacy, admitted)
			}
			if closes != ([8]int{1, 1, 1, 1, 1, 1, 1, 1}) {
				t.Fatalf("not all closes attempted: %v", closes)
			}
			if key != nil && !bytes.Equal(key, make([]byte, ed25519.PrivateKeySize)) {
				t.Fatal("key survived failed final close")
			}
		})
	}
}

func TestMinimalControlConfigObserverFailureWipesAndCloses(t *testing.T) {
	for _, outcome := range []string{"error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			requireMinimalControlAdmission(t)
			f := newMinimalControlAdmissionFixture(t)
			var key []byte
			code, closes, legacy := runMinimalControlCloseFixture(t, f, "supervise", 0, func(a *minimalControlSupervisorAdmission) error {
				key = a.controllerKey
				// Reassign the field too: the original key backing storage must
				// still be cleared, rather than whichever slice an observer leaves.
				a.controllerKey = nil
				if outcome == "panic" {
					panic("public fixture panic")
				}
				return unix.EIO
			})
			if code != 127 || legacy != 0 || closes != ([8]int{1, 1, 1, 1, 1, 1, 1, 1}) {
				t.Fatal("observer failure escaped selected cleanup")
			}
			if len(key) != ed25519.PrivateKeySize || !bytes.Equal(key, make([]byte, len(key))) {
				t.Fatal("observer failure retained signing key")
			}
		})
	}
}

func TestMinimalControlConfigLegacyCloseErrorBehaviorUnchanged(t *testing.T) {
	for _, mode := range []string{"six", "seven", "child-gate"} {
		t.Run(mode, func(t *testing.T) {
			f := newMinimalControlAdmissionFixture(t)
			argument := "supervise"
			switch mode {
			case "six":
				payload, _ := encodeL8RuntimeOwnerSupervisorConfig(l8RuntimeOwnerTestSupervisorConfig())
				f.reseal(payload)
			case "seven":
				payload, _ := json.Marshal(jailerRecoveryTestSupervisorConfig(t))
				f.reseal(payload)
			case "child-gate":
				argument = mode
			}
			code, closes, legacy := runMinimalControlCloseFixture(t, f, argument, 5, func(*minimalControlSupervisorAdmission) error { t.Fatal("legacy selected minimal"); return nil })
			if code != 0 || legacy != 1 || closes != ([8]int{1, 1, 1, 1, 1, 1, 0, 0}) {
				t.Fatal("legacy close semantics changed")
			}
		})
	}
}

func TestMinimalControlConfigProductionConsumerNeverLaunches(t *testing.T) {
	requireMinimalControlAdmission(t)
	f := newMinimalControlAdmissionFixture(t)
	var imported []int
	code := runPrivateL8RuntimeOwnerExecutable([]string{"supervise"}, func(number uintptr, role string) *os.File {
		if number < 3 || number > 10 || role != minimalControlTestRoles[number-3] {
			t.Fatal("unexpected inherited role")
		}
		file := f.files[number-3]
		imported = append(imported, int(file.Fd()))
		return file
	})
	if code != 127 || len(imported) != 8 {
		t.Fatal("actual production wrapper did not admit-and-reject all eight roles")
	}
	for _, fd := range imported {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != unix.EBADF {
			t.Fatal("production import retained after unavailable result")
		}
	}
}
