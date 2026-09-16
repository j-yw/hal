//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalArmingPacketsRejectAndCloseRights(t *testing.T) {
	for _, fault := range []string{"wrong_role", "short", "extra", "truncated", "rights", "truncated_rights", "eof"} {
		t.Run(fault, func(t *testing.T) {
			canary, err := os.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer canary.Close()
			withMinimalArmingBlocked(t, nil, func(f *minimalPreparationFixture, op *minimalControlGateOperation, join func() error) {
				wire, err := encodeL8RuntimeOwnerPacket(l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildArmed})
				if err != nil {
					t.Fatal(err)
				}
				var rights []byte
				switch fault {
				case "wrong_role":
					wire, err = encodeL8RuntimeOwnerPacket(l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildRelease})
				case "short":
					wire = wire[:len(wire)-1]
				case "extra":
					wire = append(wire, 0)
				case "truncated":
					wire = bytes.Repeat([]byte{'X'}, l8RuntimeOwnerPacketLimit+1)
				case "rights":
					rights = unix.UnixRights(int(canary.Fd()))
				case "truncated_rights":
					fds := make([]int, 8)
					for i := range fds {
						fds[i] = int(canary.Fd())
					}
					rights = unix.UnixRights(fds...)
				}
				if err != nil {
					t.Fatal(err)
				}
				if fault == "eof" {
					err = unix.Shutdown(f.gatePeer, unix.SHUT_WR)
				} else {
					_, err = unix.SendmsgN(f.gatePeer, wire, rights, nil, unix.MSG_NOSIGNAL)
				}
				if err != nil {
					t.Fatal("actual malformed packet input", err)
				}
				if join() == nil || f.owned.selected.starter.released {
					t.Fatal("invalid arming packet allowed release")
				}
				if minimalArmingMatchingFDs(t, canary) != 1 {
					t.Fatal("rejected packet leaked received rights")
				}
			})
		})
	}
}

func TestMinimalArmingConcurrentAttemptsAndClose(t *testing.T) {
	withMinimalArmingBlocked(t, nil, func(f *minimalPreparationFixture, op *minimalControlGateOperation, join func() error) {
		starter, prep := f.owned.selected.starter, f.owned.minimalPreparation
		results := make(chan error, 8)
		var tasks sync.WaitGroup
		for range 8 {
			tasks.Add(1)
			go func() {
				defer tasks.Done()
				starter.mu.Lock()
				err := starter.awaitMinimalGateArmedLocked(prep.preparationCtx)
				starter.mu.Unlock()
				results <- err
			}()
		}
		tasks.Wait()
		for range 8 {
			if <-results == nil {
				t.Error("concurrent arming entered original operation")
			}
		}
		// No actual Release closure exists before StartChild returns. This raw
		// call checks that boundary, not the later admitted operation-slot guard.
		if starter.release() == nil {
			t.Fatal("pre-closure raw release acquired authority")
		}
		starter.mu.Lock()
		unchanged := starter.minimalGate.operation == op && !starter.minimalGate.attempted && prep.current()
		starter.mu.Unlock()
		if !unchanged {
			t.Fatal("losing attempts poisoned original arming")
		}
		for range 8 {
			tasks.Add(1)
			go func() { defer tasks.Done(); results <- starter.close() }()
		}
		tasks.Wait()
		for range 8 {
			if err := <-results; err != nil {
				t.Error("concurrent Close", err)
			}
		}
		if join() == nil {
			t.Fatal("closed arming succeeded")
		}
	})
}

func TestMinimalArmingOriginalReleaseUsesOnlyJoinedSlot(t *testing.T) {
	for _, unfinished := range []bool{false, true} {
		name := "joined_arming_then_release"
		if unfinished {
			name = "unfinished_retained_slot_rejects_admitted_release"
		}
		t.Run(name, func(t *testing.T) {
			var revisionOne <-chan struct{}
			var unblock func()
			captured := make(chan func() error, 1)
			withMinimalArmingBlocked(t, func(f *minimalPreparationFixture) {
				start := f.owner.opts.StartChild
				f.owner.opts.StartChild = func() (l8RuntimeOwnerStartedChild, error) {
					child, err := start()
					if err == nil {
						captured <- child.Release
					}
					return child, err
				}
				revisionOne, unblock = minimalReleasePauseAtRevisionOne(f)
			}, func(f *minimalPreparationFixture, arm *minimalControlGateOperation, join func() error) {
				defer unblock()
				if sendL8RuntimeOwnerSeqpacket(f.gatePeer, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildArmed}, nil) != nil {
					t.Fatal("ChildArmed send")
				}
				waitMinimalPreparationSignal(t, revisionOne, "actual post-arming revision 1")
				minimalReleaseRequireRevisionOne(t, f, f.tracked)
				waitMinimalPreparationSignal(t, arm.done, "original arming completion")
				waitMinimalPreparationSignal(t, arm.watcherDone, "original arming watcher")
				starter, prep := f.owned.selected.starter, f.owned.minimalPreparation
				starter.mu.Lock()
				if starter.awaitMinimalGateArmedLocked(prep.preparationCtx) == nil {
					starter.mu.Unlock()
					t.Fatal("completed arming became repeatable")
				}
				if starter.minimalGate.attempted || starter.minimalGate.operation != arm {
					starter.mu.Unlock()
					t.Fatal("arming consumed release attempt")
				}
				var retained *minimalControlGateOperation
				var finishRetained func()
				if unfinished {
					// The original physical arming already joined. This test-owned
					// retained-slot mismatch, not claimed concurrent real arming,
					// reaches the slot guard after the actual revision-1 CAS.
					retained = &minimalControlGateOperation{done: make(chan struct{})}
					starter.minimalGate.operation = retained
					finishRetained = sync.OnceFunc(func() {
						close(retained.done)
						starter.mu.Lock()
						starter.minimalGate.operation = arm
						starter.mu.Unlock()
					})
					defer finishRetained()
				}
				starter.mu.Unlock()
				if unfinished {
					// Invoke the same real returned callback while its FSM is
					// paused, then finish only this test-owned slot before normal
					// containment. No reconstructed release snapshot or authority.
					var release func() error
					select {
					case release = <-captured:
					default:
						t.Fatal("original callback not captured")
					}
					gate := starter.minimalGate
					if release() == nil {
						t.Fatal("admitted release overwrote unfinished slot")
					}
					starter.mu.Lock()
					kept := gate.operation == retained && !gate.attempted && prep.canceled.releaseAdmitted() && !gate.window.startedAt.IsZero()
					starter.mu.Unlock()
					if !kept {
						t.Fatal("unfinished retained operation was replaced or consumed")
					}
					finishRetained()
				}
				unblock()
				err := join()
				if unfinished {
					if err == nil || starter.released {
						t.Fatal("consumed rejected admission became retryable")
					}
					return
				}
				if err != nil || !starter.released {
					t.Fatal("original arming to release failed", err)
				}
				starter.mu.Lock()
				release := starter.minimalGate.operation
				window := starter.minimalGate.window
				starter.mu.Unlock()
				if release == arm || release == nil || window.startedAt.IsZero() || !prep.canceled.releaseAdmitted() {
					t.Fatal("original release did not retain own admitted operation")
				}
				waitMinimalPreparationSignal(t, release.done, "original release completion")
				packet, err := minimalReleaseReceive(t, f.gatePeer)
				closeL8RuntimeOwnerFiles(packet.Files)
				if err != nil || packet.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease {
					t.Fatal("actual release packet", err)
				}
			})
		})
	}
}

func TestMinimalArmingPostReceiveLossCannotRebase(t *testing.T) {
	for _, loss := range []string{"cancel", "shorter_stage", "original_p"} {
		t.Run(loss, func(t *testing.T) {
			deadline := time.Now().Add(time.Minute)
			if loss == "original_p" {
				deadline = time.Now().Add(time.Second)
			}
			withMinimalArmingBlockedDeadline(t, deadline, func(f *minimalPreparationFixture) {
				if loss == "shorter_stage" {
					// A real shorter derived stage is lower-operation evidence;
					// it does not claim the fixed actual 30-second stage elapsed.
					base := f.tracked.lifecycle.runner.starter.(*minimalArmingFixtureStarter)
					f.tracked.lifecycle.runner.starter = &minimalArmingShortStage{base: base, duration: 250 * time.Millisecond}
				}
			}, func(f *minimalPreparationFixture, op *minimalControlGateOperation, join func() error) {
				starter := f.owned.selected.starter
				starter.mu.Lock()
				locked := true
				defer func() {
					if locked {
						starter.mu.Unlock()
					}
				}()
				if sendL8RuntimeOwnerSeqpacket(f.gatePeer, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildArmed}, nil) != nil {
					t.Fatal("real packet input")
				}
				waitMinimalPreparationSignal(t, op.stopWatcher, "actual receive completion before lock reentry")
				waitMinimalPreparationSignal(t, op.watcherDone, "watcher join without starter lock")
				if loss == "cancel" {
					f.owned.minimalPreparation.revoke()
				} else if loss == "original_p" {
					waitMinimalPreparationSignal(t, f.owned.minimalPreparation.ctx.Done(), "original P while starter lock delays completion")
				} else {
					<-time.After(300 * time.Millisecond)
				}
				starter.mu.Unlock()
				locked = false
				if join() == nil || starter.released {
					t.Fatal("post-receive loss was ignored/rebased")
				}
				// Failure must come from arming before lifecycle publication,
				// not merely a later canceled store transition after false success.
				f.tracked.process.mu.Lock()
				killed, waited := f.tracked.process.killCalls, f.tracked.process.waitCalls
				f.tracked.process.mu.Unlock()
				if killed != 1 || waited != 1 {
					t.Fatal("post-receive loss escaped original runner start-failure containment", killed, waited)
				}
			})
		})
	}
}

func TestMinimalArmingShorterStageInterruptsActualReceive(t *testing.T) {
	withMinimalArmingBlocked(t, func(f *minimalPreparationFixture) {
		base := f.tracked.lifecycle.runner.starter.(*minimalArmingFixtureStarter)
		f.tracked.lifecycle.runner.starter = &minimalArmingShortStage{base: base, duration: 250 * time.Millisecond}
	}, func(f *minimalPreparationFixture, op *minimalControlGateOperation, join func() error) {
		// The lower derived context genuinely expires; original P stays long.
		// Its socket bound must not be the old independently rebased five seconds.
		var bound time.Duration
		raw, err := op.file.SyscallConn()
		if err == nil {
			err = raw.Control(func(fd uintptr) {
				value, readErr := unix.GetsockoptTimeval(int(fd), unix.SOL_SOCKET, unix.SO_RCVTIMEO)
				if readErr == nil {
					bound = time.Duration(value.Nano())
				}
			})
		}
		if err != nil || bound <= 0 || bound > 251*time.Millisecond {
			t.Fatal("arming socket escaped original shorter stage bound", bound, err)
		}
		before := time.Now()
		if join() == nil || time.Since(before) > 750*time.Millisecond || f.owned.selected.starter.released {
			t.Fatal("shorter stage did not interrupt and join actual receive")
		}
	})
}

func TestMinimalArmingDescriptorSuccessorsSurviveJoinedClose(t *testing.T) {
	canary, err := os.CreateTemp(t.TempDir(), "arming-successor-")
	if err != nil {
		t.Fatal(err)
	}
	defer canary.Close()
	if _, err := canary.WriteString("retained successor canary"); err != nil {
		t.Fatal(err)
	}
	withMinimalArmingBlocked(t, nil, func(f *minimalPreparationFixture, op *minimalControlGateOperation, join func() error) {
		starter := f.owned.selected.starter
		starter.mu.Lock()
		originalFD := int(starter.gate.Fd())
		aliasFD, err := unix.FcntlInt(uintptr(originalFD), unix.F_DUPFD_CLOEXEC, 10)
		var identity unix.Stat_t
		statErr := unix.Fstat(originalFD, &identity)
		starter.mu.Unlock()
		if err != nil || statErr != nil {
			t.Fatal("owned socket alias prerequisite", err, statErr)
		}
		alias := os.NewFile(uintptr(aliasFD), "arming-retained-alias")
		defer alias.Close()
		var operationFD int
		raw, err := op.file.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		if raw.Control(func(fd uintptr) { operationFD = int(fd) }) != nil {
			t.Fatal("operation descriptor observation")
		}
		closed := make(chan error, 1)
		go func() { closed <- starter.close() }()
		if join() == nil {
			t.Fatal("closed arming succeeded")
		}
		if err := minimalPreparationJoin(t, closed); err != nil {
			t.Fatal("joined starter close", err)
		}
		if f.owned.shutdownMinimalControlPreparation() != nil {
			t.Fatal("joined preparation close")
		}
		var retained unix.Stat_t
		if unix.Fstat(aliasFD, &retained) != nil || identity.Dev != retained.Dev || identity.Ino != retained.Ino {
			t.Fatal("arming cleanup closed retained socket alias")
		}
		// Allocate only the now-free operation number; never overwrite a busy FD.
		fd, err := unix.FcntlInt(canary.Fd(), unix.F_DUPFD_CLOEXEC, operationFD)
		if err != nil {
			t.Fatal(err)
		}
		successor := os.NewFile(uintptr(fd), "arming-operation-successor")
		defer successor.Close()
		if fd != operationFD {
			t.Fatal("operation number unavailable after all joins")
		}
		minimalGateIOCheckSuccessor(t, f, canary, originalFD)
		if starter.close() != nil {
			t.Fatal("repeated selected close")
		}
		content := make([]byte, len("retained successor canary"))
		n, err := successor.ReadAt(content, 0)
		if err != nil || n != len(content) || string(content) != "retained successor canary" {
			t.Fatal("late arming cleanup consumed operation FD successor", err)
		}
	})
}

type minimalArmingShortStage struct {
	base     *minimalArmingFixtureStarter
	duration time.Duration
}

func (s *minimalArmingShortStage) startStrictJailerNamespaceProcess(ctx context.Context, request strictJailerNamespaceProcessStartRequest) (HostProcess, error) {
	ctx, cancel := context.WithTimeout(ctx, s.duration)
	defer cancel()
	return s.base.startStrictJailerNamespaceProcess(ctx, request)
}

func withMinimalArmingBlocked(t *testing.T, configure func(*minimalPreparationFixture), use func(*minimalPreparationFixture, *minimalControlGateOperation, func() error)) {
	t.Helper()
	withMinimalArmingBlockedDeadline(t, time.Now().Add(time.Minute), configure, use)
}

func withMinimalArmingBlockedDeadline(t *testing.T, deadline time.Time, configure func(*minimalPreparationFixture), use func(*minimalPreparationFixture, *minimalControlGateOperation, func() error)) {
	t.Helper()
	withMinimalPreparationFixture(t, deadline, func(f *minimalPreparationFixture) {
		entered := minimalArmingUseFixture(f)
		if configure != nil {
			configure(f)
		}
		done, joined := f.start(t), false
		defer func() {
			if !joined {
				_ = unix.Shutdown(f.gatePeer, unix.SHUT_WR)
				_ = minimalPreparationJoin(t, done)
			}
		}()
		observation := minimalArmingWaitActualReceive(t, entered)
		minimalArmingRequireGenesisAndOuterLocks(t, f, observation)
		starter := f.owned.selected.starter
		starter.mu.Lock()
		op := starter.minimalGate.operation
		valid := op != nil && op.file != nil && !starter.minimalGate.attempted
		if valid {
			var original, duplicate unix.Stat_t
			raw, err := op.file.SyscallConn()
			valid = err == nil
			if valid {
				err = raw.Control(func(fd uintptr) {
					flags, flagErr := unix.FcntlInt(fd, unix.F_GETFD, 0)
					valid = flagErr == nil && flags&unix.FD_CLOEXEC != 0 && fd != starter.gate.Fd() &&
						unix.Fstat(int(fd), &duplicate) == nil && unix.Fstat(int(starter.gate.Fd()), &original) == nil &&
						duplicate.Dev == original.Dev && duplicate.Ino == original.Ino
				})
				valid = valid && err == nil
			}
		}
		starter.mu.Unlock()
		if !valid {
			t.Fatal("arming lacks exact owned CLOEXEC operation duplicate")
		}
		use(f, op, func() error { err := minimalPreparationJoin(t, done); joined = true; return err })
		if !joined {
			t.Fatal("arming test did not join actual bootstrap")
		}
		waitMinimalPreparationSignal(t, op.done, "arming operation completion")
		waitMinimalPreparationSignal(t, op.watcherDone, "arming watcher completion")
		if op.file.Fd() != ^uintptr(0) {
			t.Fatal("arming duplicate survived its joined operation")
		}
	})
}

func minimalArmingMatchingFDs(t *testing.T, file *os.File) int {
	t.Helper()
	var want unix.Stat_t
	if unix.Fstat(int(file.Fd()), &want) != nil {
		t.Fatal("retained rights canary identity")
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		var got unix.Stat_t
		if err == nil && unix.Fstat(fd, &got) == nil && got.Dev == want.Dev && got.Ino == want.Ino {
			count++
		}
	}
	return count
}
