package firecrackerhost

import (
	"errors"
	"reflect"
	"testing"
)

// The selected gate is a role of the existing owner executable, not a second
// executable or a padded use of the legacy six-descriptor child ABI.
func TestJailerRecoveryGateUsesExactTwoDescriptorRole(t *testing.T) {
	for _, failure := range []string{"", "first open", "second open", "gate"} {
		t.Run("failure="+failure, func(t *testing.T) {
			var opened []uintptr
			var roles []string
			var closed []int
			called := false
			ops := l8RuntimeOwnerExecutableOps{
				OpenFD: func(fd uintptr, role string) (int, error) {
					opened, roles = append(opened, fd), append(roles, role)
					if failure == "first open" && fd == 3 || failure == "second open" && fd == 4 {
						return -1, errors.New("fixture open")
					}
					return int(fd), nil
				},
				CloseFD: func(fd int) error { closed = append(closed, fd); return nil },
				RunSupervisor: func([6]int) error {
					t.Fatal("selected gate routed into supervisor")
					return nil
				},
				RunChildGate: func([6]int) error {
					t.Fatal("selected gate routed into legacy child")
					return nil
				},
				RunJailerGate: func(fds [2]int) error {
					called = true
					if fds != [2]int{3, 4} {
						t.Fatalf("gate descriptors=%v", fds)
					}
					if failure == "gate" {
						return errors.New("fixture gate")
					}
					return nil
				},
			}
			code := runPrivateL8RuntimeOwnerExecutableWithOps([]string{"jailer-child-gate-v1"}, ops)
			wantCode, wantCalled := 127, false
			wantOpened, wantRoles, wantClosed := []uintptr{3, 4}, []string{"control-socket", "jailer-gate-config"}, []int{4, 3}
			switch failure {
			case "":
				wantCode, wantCalled = 0, true
			case "gate":
				wantCalled = true
			case "first open":
				wantOpened, wantRoles, wantClosed = []uintptr{3}, []string{"control-socket"}, nil
			case "second open":
				wantClosed = []int{3}
			}
			if code != wantCode || called != wantCalled || !reflect.DeepEqual(opened, wantOpened) || !reflect.DeepEqual(roles, wantRoles) || !reflect.DeepEqual(closed, wantClosed) {
				t.Fatalf("gate dispatch code=%d called=%t opened=%v roles=%v closed=%v", code, called, opened, roles, closed)
			}
		})
	}
}
