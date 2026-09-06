//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"slices"
	"strings"
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

func TestJailerRecoveryCleanBootstrapFinalizationDoesNotTouchSuccessor(t *testing.T) {
	f := newJailerRecoveryBootstrapWireFixture(t, func(owned *l8RuntimeOwnerLinuxRuntime) {
		owned.selected.coordinator.deps.lifecycle.(*coordinatorFakeLifecycle).startErr = errors.New("fake start refused")
	})
	authority := f.owned.selected.coordinator.deps.identity
	successor, err := authority.reserve(context.Background(), "next-runtime", strings.Repeat("b", 64), authority.slot.uid, authority.slot.gid)
	if err != nil {
		t.Fatal(err)
	}
	defer successor.close()
	store := successor.fs.(*fakeJailerIdentityFilesystem).store
	before := store.snapshot()
	if err := f.owned.quarantineJailerBootstrap(); err != nil {
		t.Fatal(err)
	}
	client := f.fresh(t)
	if err := client.stopAndCommit(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.waitConnection()
	if !slices.Equal(before, store.snapshot()) || successor.verify(context.Background()) != nil {
		t.Fatal("old finalization affected successor slot")
	}
}

func TestJailerRecoveryCleanBootstrapRequiresExactTerminalEvidence(t *testing.T) {
	for _, name := range []string{"checkpoint", "reservation", "busy", "idle", "released", "closed", "lease_poisoned", "lease_close_error", "store_poisoned", "record_changed", "descriptor_close"} {
		t.Run(name, func(t *testing.T) {
			f := newJailerRecoveryBootstrapWireFixture(t, func(owned *l8RuntimeOwnerLinuxRuntime) {
				owned.selected.coordinator.deps.lifecycle.(*coordinatorFakeLifecycle).startErr = errors.New("fake start refused")
			})
			s := f.owned.store.selected
			originalLease := s.reservation
			if originalLease == nil || !s.terminal || !originalLease.released {
				t.Fatal("terminal fixture invalid")
			}
			switch name {
			case "checkpoint":
				s.terminal = false
			case "reservation":
				s.reservation = nil
			case "busy":
				changed := *s.busy
				changed.Nonce = l8RuntimeOwnerTestToken(99)
				s.busy = &changed
			case "idle":
				originalLease.idleCommitted = false
			case "released":
				originalLease.released = false
			case "closed":
				originalLease.closed = false
			case "lease_poisoned":
				originalLease.poisoned = true
			case "lease_close_error":
				originalLease.closeErr = errors.New("old close uncertain")
			case "store_poisoned":
				s.poisoned = true
			case "record_changed":
				if _, err := s.file.WriteAt([]byte("!"), 0); err != nil {
					t.Fatal(err)
				}
			case "descriptor_close":
				if err := f.owned.selected.starter.gate.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before := slices.Clone(originalLease.fs.(*fakeJailerIdentityFilesystem).store.snapshot())
			if err := f.owned.quarantineJailerBootstrap(); err == nil || f.owned.selected.terminal {
				t.Fatal("incomplete proof became terminal recovery")
			}
			after := originalLease.fs.(*fakeJailerIdentityFilesystem).store.snapshot()
			if !slices.Equal(before, after) {
				t.Fatal("old terminal check touched identity journal")
			}
		})
	}
}
