//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestJailerRecoveryCleanBootstrapFailureAuthenticatesAndFinalizes(t *testing.T) {
	for _, postPID := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_pid", true: "published_pid"}[postPID], func(t *testing.T) {
			f := newJailerRecoveryBootstrapWireFixture(t, func(owned *l8RuntimeOwnerLinuxRuntime) {
				if postPID {
					if err := unix.Shutdown(int(owned.selected.starter.gate.Fd()), unix.SHUT_WR); err != nil {
						t.Fatal(err)
					}
				} else {
					owned.selected.coordinator.deps.lifecycle.(*coordinatorFakeLifecycle).startErr = errors.New("fake start refused")
				}
			})
			store := f.owned.store.selected
			if !store.terminal || store.reservation == nil || !store.reservation.idleCommitted || !store.reservation.released || f.owned.selected.coordinator.generation != nil {
				t.Fatal("fixture did not finish exact resource cleanup")
			}
			if err := f.owned.quarantineJailerBootstrap(); err != nil {
				t.Fatalf("completed owned cleanup cannot expose authenticated retry: %v", err)
			}
			client := f.fresh(t)
			if err := client.stopAndCommit(context.Background()); err != nil {
				t.Fatalf("fresh terminal finalization: %v", err)
			}
			f.waitConnection()
			if !store.retired || !f.owned.selected.terminal || f.owned.selected.coordinator.generation != nil {
				t.Fatal("terminal owner not retired")
			}
		})
	}
}
