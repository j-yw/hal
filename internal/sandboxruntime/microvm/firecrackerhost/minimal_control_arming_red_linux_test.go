//go:build linux

package firecrackerhost

import (
	"context"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This wrapper uses the existing fake process/cgroup starter, then the exact
// selected production receive. It does not launch a process, enter a namespace,
// signal the observed self PID, or claim supervisor-created child authority.
type minimalArmingFixtureStarter struct {
	tracked *minimalReleaseFakeStarter
	entered chan minimalArmingFixtureObservation
}

type minimalArmingFixtureObservation struct {
	task     string
	identity *strictJailerIdentityLease
}

func (s *minimalArmingFixtureStarter) startStrictJailerNamespaceProcess(ctx context.Context, request strictJailerNamespaceProcessStartRequest) (HostProcess, error) {
	process, err := s.tracked.startStrictJailerNamespaceProcess(ctx, request)
	if err != nil {
		return process, err
	}
	starter := s.tracked.ownerStarter
	starter.mu.Lock()
	defer starter.mu.Unlock()
	// Capture the retained identity on its owning task. The coordinator later
	// republishes generation, so another task must not read that field unlocked.
	s.entered <- minimalArmingFixtureObservation{task: minimalGateIOCurrentTask(), identity: s.tracked.selected.coordinator.generation.identity}
	// The actual runner's original P/stage context is passed unchanged. Return
	// the exact fake process on failure so its real runner owns fake Kill/Wait.
	return process, starter.awaitMinimalGateArmedLocked(ctx)
}

func minimalArmingUseFixture(f *minimalPreparationFixture) <-chan minimalArmingFixtureObservation {
	s := &minimalArmingFixtureStarter{tracked: f.tracked, entered: make(chan minimalArmingFixtureObservation, 1)}
	f.tracked.lifecycle.runner.starter = s
	return s.entered
}

func TestMinimalArmingReceiveActualBootstrapControl(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		entered := minimalArmingUseFixture(f)
		done, joined := f.start(t), false
		defer func() {
			if !joined {
				_ = unix.Shutdown(f.gatePeer, unix.SHUT_WR)
				_ = minimalPreparationJoin(t, done)
			}
		}()
		observation := minimalArmingWaitActualReceive(t, entered)
		minimalArmingRequireGenesisAndOuterLocks(t, f, observation)
		if sendL8RuntimeOwnerSeqpacket(f.gatePeer, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildArmed}, nil) != nil {
			t.Fatal("real ChildArmed packet send")
		}
		if err := minimalPreparationJoin(t, done); err != nil {
			t.Fatal("actual arming/release/bootstrap control", err)
		}
		joined = true
		for index, fd := range []int{f.gatePeer, f.peer} {
			packet, err := minimalReleaseReceive(t, fd)
			closeL8RuntimeOwnerFiles(packet.Files)
			want := []uint16{l8RuntimeOwnerOpcodeChildRelease, l8RuntimeOwnerOpcodeBootstrapPublished}[index]
			if err != nil || packet.Packet.Opcode != want {
				t.Fatal("actual gate release/revision-2 reply missing", err)
			}
		}
		record, err := f.owned.store.Load(context.Background())
		if err != nil || record.Revision != 2 || record.State != "running" || !f.owned.selected.starter.released || f.tracked.calls != 1 {
			t.Fatal("successful actual arming did not retain original bootstrap ordering", err)
		}
	})
}

func TestMinimalArmingReceiveObservedLossInterrupts(t *testing.T) {
	for _, loss := range []string{"original_eof", "original_p", "starter_close", "preparation_close", "owned_close"} {
		t.Run(loss, func(t *testing.T) {
			deadline := time.Now().Add(time.Minute)
			if loss == "original_p" {
				deadline = time.Now().Add(3 * time.Second)
			}
			withMinimalPreparationFixture(t, deadline, func(f *minimalPreparationFixture) {
				entered := minimalArmingUseFixture(f)
				done, joined := f.start(t), false
				var closeDone chan error
				closeJoined := false
				defer func() {
					if !joined || closeDone != nil && !closeJoined {
						_ = unix.Shutdown(f.gatePeer, unix.SHUT_WR)
						if !joined {
							_ = minimalPreparationJoin(t, done)
						}
						if closeDone != nil && !closeJoined {
							_ = minimalPreparationJoin(t, closeDone)
						}
					}
				}()
				observation := minimalArmingWaitActualReceive(t, entered)
				minimalArmingRequireGenesisAndOuterLocks(t, f, observation)
				if loss == "original_p" && time.Until(deadline) < time.Second {
					t.Fatal("P fixture reached receive too late for cancellation proof")
				}
				starter, prep := f.owned.selected.starter, f.owned.minimalPreparation
				if starter.mu.TryLock() {
					starter.mu.Unlock()
				} else {
					t.Error("starter bookkeeping mutex held over actual blocked arming receive")
				}
				switch loss {
				case "original_eof":
					if unix.Shutdown(f.peer, unix.SHUT_WR) != nil {
						t.Fatal("original-channel EOF input")
					}
					waitMinimalPreparationSignal(t, prep.monitorDone, "actual original monitor revocation")
				case "original_p":
					waitMinimalPreparationSignal(t, prep.observerDone, "original sealed-P observer")
				default:
					closeDone = make(chan error, 1)
					go func() {
						switch loss {
						case "starter_close":
							closeDone <- starter.close()
						case "preparation_close":
							closeDone <- f.owned.shutdownMinimalControlPreparation()
						case "owned_close":
							f.owned.close()
							closeDone <- nil
						}
					}()
				}
				waitMinimalPreparationSignal(t, prep.ctx.Done(), "same preparation cancellation before outer joins")
				if !prep.canceled.Load() {
					t.Fatal("context loss did not publish the same cancellation latch")
				}
				var result error
				select {
				case result = <-done:
					joined = true
				case <-time.After(750 * time.Millisecond):
					t.Error("observed cancellation did not interrupt actual arming receive before legacy timeout")
				}
				if closeDone != nil {
					select {
					case err := <-closeDone:
						closeJoined = true
						if err != nil {
							t.Error("owned close could not join local cleanup", err)
						}
					case <-time.After(250 * time.Millisecond):
						t.Error("actual close remained behind blocked arming/outer locks")
					}
				}
				if !joined {
					// Rescue only follows recorded failure and is not cancellation
					// evidence. EOF lets the unchanged real receive return and join.
					if unix.Shutdown(f.gatePeer, unix.SHUT_WR) != nil {
						t.Fatal("owned peer rescue failed")
					}
					result = minimalPreparationJoin(t, done)
					joined = true
				}
				if closeDone != nil && !closeJoined {
					if err := minimalPreparationJoin(t, closeDone); err != nil {
						t.Error("close failed after joined failure rescue", err)
					}
					closeJoined = true
				}
				if result == nil || starter.released || prep.canceled.releaseAdmitted() {
					t.Error("failed arming acquired release/bootstrap authority")
				}
				f.tracked.process.mu.Lock()
				killed, waited, terminal := f.tracked.process.killCalls, f.tracked.process.waitCalls, f.tracked.process.closed
				f.tracked.process.mu.Unlock()
				if killed != 1 || waited != 1 || !terminal {
					t.Error("original runner did not own exact fake child cleanup", killed, waited, terminal)
				}
				for _, fd := range []int{f.gatePeer, f.peer} {
					buffer := make([]byte, l8RuntimeOwnerPacketLimit)
					n, _, _, _, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
					if err == nil && n > 0 {
						t.Error("failed arming sent a release or successful bootstrap packet")
					}
				}
			})
		})
	}
}

func minimalArmingRequireGenesisAndOuterLocks(t *testing.T, f *minimalPreparationFixture, observation minimalArmingFixtureObservation) {
	t.Helper()
	record, err := f.owned.store.Load(context.Background())
	if err != nil || record.Revision != 0 || record.State != "starting" || record.FirecrackerPID != 0 {
		t.Fatal("arming did not occur under actual durable genesis", err)
	}
	for _, item := range []struct {
		name string
		mu   *sync.Mutex
	}{
		{"owner", &f.owner.mu}, {"selected", &f.owned.selected.mu},
		{"coordinator", &f.owned.selected.coordinator.mu}, {"identity", &observation.identity.mu},
		{"runner", &f.tracked.lifecycle.runner.mu},
	} {
		if item.mu.TryLock() {
			item.mu.Unlock()
			t.Fatal("expected actual outer lock was not held during arming", item.name)
		}
	}
}

func minimalArmingWaitActualReceive(t *testing.T, entered <-chan minimalArmingFixtureObservation) minimalArmingFixtureObservation {
	t.Helper()
	var observation minimalArmingFixtureObservation
	select {
	case observation = <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("original runner never entered selected arming extraction")
	}
	deadline := time.Now().Add(3 * time.Second)
	buffer := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.HasPrefix(stack, observation.task) && strings.Contains(stack, "[syscall]") &&
				strings.Contains(stack, "firecrackerhost.(*l8RuntimeOwnerLinuxRuntime).serveMinimalControlPreparation") &&
				strings.Contains(stack, "firecrackerhost.(*l8RuntimeOwnerSupervisor).HandleBootstrap") &&
				strings.Contains(stack, "firecrackerhost.(*jailerRecoveryStarter).awaitMinimalGateArmedLocked") &&
				strings.Contains(stack, "golang.org/x/sys/unix.Recvmsg") {
				return observation
			}
		}
		runtime.Gosched()
	}
	t.Fatal("exact selected bootstrap task did not block in actual arming recvmsg")
	return minimalArmingFixtureObservation{}
}
