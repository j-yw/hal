//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Pure single-word ordering coverage complements (does not replace) the actual
// selected callback, revision-1, blocked-send and post-CAS tests below.
func TestMinimalReleaseAdmissionLatchOrdering(t *testing.T) {
	for range 256 {
		var latch minimalControlPreparationLatch
		start, admitted, canceled := make(chan struct{}), make(chan bool, 1), make(chan struct{})
		go func() { <-start; admitted <- latch.admitRelease() }()
		go func() { <-start; latch.cancel(); close(canceled) }()
		close(start)
		won := <-admitted
		<-canceled
		if !latch.Load() || latch.releaseAdmitted() != won || latch.admitRelease() {
			t.Fatal("cancellation/admission ordering was lost or reset")
		}
	}
}

func TestMinimalReleaseAdmissionConcurrentFirstAttempts(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		// Call the actual selected constructor, without the older fixture's
		// sequential-only order-recording slice wrapper. Its tests are unchanged.
		start := f.owned.selected.startMinimalControlChild
		results := make(chan int, 1)
		f.owner.opts.StartChild = func() (l8RuntimeOwnerStartedChild, error) {
			child, err := start()
			if err != nil {
				return child, err
			}
			release := child.Release
			child.Release = func() error {
				ready, done := make(chan struct{}), make(chan error, 16)
				for range 16 {
					go func() { <-ready; done <- release() }()
				}
				close(ready)
				wins := 0
				for range 16 {
					if <-done == nil {
						wins++
					}
				}
				results <- wins // Every contender joins before the actual FSM continues.
				if wins != 1 {
					return errL8RuntimeOwnerInvalid
				}
				return nil
			}
			return child, nil
		}
		if err := minimalPreparationJoin(t, f.start(t)); err != nil {
			t.Fatal("concurrent actual returned releases did not yield one success", err)
		}
		if <-results != 1 || !f.owned.minimalPreparation.canceled.releaseAdmitted() || !f.owned.minimalPreparation.current() {
			t.Fatal("losing contenders altered the admitted original lifetime")
		}
		packet, err := minimalReleaseReceive(t, f.gatePeer)
		if err != nil || packet.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease {
			t.Fatal("one actual release packet missing", err)
		}
		minimalGateIOCheckQueuedPackets(t, f.gatePeer, nil, 0)
		minimalAdmissionRequireRevision(t, f, 2)
	})
}

func TestMinimalReleaseAdmissionContendersCannotPoisonBlockedWinner(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		capture, task := make(chan func() error, 1), make(chan string, 1)
		start := f.owned.selected.startMinimalControlChild
		f.owner.opts.StartChild = func() (l8RuntimeOwnerStartedChild, error) {
			child, err := start()
			if err == nil {
				capture <- child.Release
				task <- minimalGateIOCurrentTask()
			}
			return child, err
		}
		entered, unblock := minimalReleasePauseAtRevisionOne(f)
		done, joined := f.start(t), false
		defer func() {
			unblock()
			if !joined {
				f.owned.minimalPreparation.revoke()
				_ = minimalPreparationJoin(t, done)
			}
		}()
		waitMinimalPreparationSignal(t, entered, "actual revision-1 pause")
		minimalReleaseRequireRevisionOne(t, f, f.tracked)
		starter, prep := f.owned.selected.starter, f.owned.minimalPreparation
		fill, count := minimalGateIOFillQueue(t, int(starter.gate.Fd()))
		unblock()
		minimalGateIOWaitActualSend(t, <-task)
		original, ok := starter.minimalGate.releaseWindow()
		if !ok || !prep.canceled.releaseAdmitted() {
			t.Fatal("blocked original has not won admission")
		}
		// The existing fake identity hook observes successful real currentness
		// traversals, never supplies bytes or admission/clock observations.
		fs := minimalAdmissionIdentityFilesystem(t, f)
		var reads atomic.Int32
		fs.store.mu.Lock()
		fs.store.hook = func(op string) {
			if op == "read" {
				reads.Add(1)
			}
		}
		fs.store.mu.Unlock()
		release, attempts := <-capture, make(chan error, 16)
		for range 16 {
			go func() { attempts <- release() }()
		}
		for range 16 {
			if err := minimalPreparationJoin(t, attempts); err == nil {
				t.Error("contender entered an already admitted release")
			}
		}
		if reads.Load() != 3*16 || !prep.current() {
			t.Fatal("contenders did not pass all final resource checks or poisoned the winner", reads.Load())
		}
		if after, retained := starter.minimalGate.releaseWindow(); !retained || after != original {
			t.Fatal("losing admission reset original R/D")
		}
		// Drain only the known ordinary queue fillers, permitting the original
		// blocked syscall to complete. No packet injection or retry is involved.
		buffer := make([]byte, len(fill))
		for range count {
			n, _, flags, _, err := unix.Recvmsg(f.gatePeer, buffer, nil, 0)
			if err != nil || flags != 0 || n != len(fill) || !bytes.Equal(buffer, fill) {
				t.Fatal("exact queue filler changed", err)
			}
		}
		if err := minimalPreparationJoin(t, done); err != nil {
			joined = true
			t.Fatal("losers prevented the original successful send", err)
		}
		joined = true
		packet, err := minimalReleaseReceive(t, f.gatePeer)
		if err != nil || packet.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease {
			t.Fatal("original winning packet missing", err)
		}
		minimalGateIOCheckQueuedPackets(t, f.gatePeer, nil, 0)
		minimalAdmissionRequireRevision(t, f, 2)
	})
}

func TestMinimalReleaseAdmissionPostCASLockDelay(t *testing.T) {
	for _, mode := range []string{"delay", "cancel", "original_P"} {
		t.Run(mode, func(t *testing.T) {
			deadline := time.Now().Add(time.Minute)
			if mode == "original_P" {
				deadline = time.Now().Add(3 * time.Second)
			}
			withMinimalPreparationFixture(t, deadline, func(f *minimalPreparationFixture) {
				entered, unblock := minimalReleasePauseAtRevisionOne(f)
				done, joined := f.start(t), false
				starter, prep := f.owned.selected.starter, f.owned.minimalPreparation
				locked, unlock := make(chan struct{}), false
				defer func() {
					if unlock {
						starter.mu.Unlock()
					}
					unblock()
					if !joined {
						prep.revoke()
						_ = minimalPreparationJoin(t, done)
					}
				}()
				waitMinimalPreparationSignal(t, entered, "actual revision-1 pause")
				minimalReleaseRequireRevisionOne(t, f, f.tracked)
				fs := minimalAdmissionIdentityFilesystem(t, f)
				verifies := 0
				fs.store.mu.Lock()
				fs.store.hook = func(op string) {
					if op == "verify" {
						verifies++
						if verifies == 6 {
							// Existing fake filesystem hook, at the final successful
							// identity check AFTER the actual armed process readback.
							starter.mu.Lock()
							close(locked)
						}
					}
				}
				fs.store.mu.Unlock()
				before := time.Now()
				unblock()
				waitMinimalPreparationSignal(t, locked, "final resource check locks starter")
				unlock = true
				minimalAdmissionWaitCAS(t, prep)
				afterCAS := time.Now()
				if f.owner.mu.TryLock() {
					f.owner.mu.Unlock()
					t.Fatal("actual bootstrap FSM no longer owns its lock")
				}
				if gate := starter.minimalGate; !gate.window.startedAt.IsZero() || gate.attempted || gate.operation != nil {
					t.Fatal("publication or I/O escaped the locked post-CAS boundary")
				}
				switch mode {
				case "delay":
					<-time.After(25 * time.Millisecond)
				case "cancel":
					// Revoke must not wait for starter, owner, or preparation.mu.
					prep.mu.Lock()
					revoked := make(chan struct{})
					go func() { prep.revoke(); close(revoked) }()
					select {
					case <-revoked:
						prep.mu.Unlock()
					case <-time.After(time.Second):
						prep.mu.Unlock()
						starter.mu.Unlock()
						unlock = false
						waitMinimalPreparationSignal(t, revoked, "failed revoke rescue join")
						t.Fatal("cancellation waited for a bookkeeping lock")
					}
				case "original_P":
					if time.Until(prep.deadline) < time.Second {
						t.Fatal("original P budget prerequisite not reached")
					}
					waitMinimalPreparationSignal(t, prep.ctx.Done(), "unchanged original P expiration")
				}
				starter.mu.Unlock()
				unlock = false
				err := minimalPreparationJoin(t, done)
				joined = true
				window, ok := starter.minimalGate.releaseWindow()
				if !ok {
					t.Fatal("consumed admission lost its original window")
				}
				minimalReleaseAdmissionRequireWindow(t, window, before, afterCAS, prep.deadline)
				if prep.deadline.UnixNano() != deadline.UnixNano() || !prep.canceled.releaseAdmitted() {
					t.Fatal("original P/admission was reset")
				}
				if mode == "delay" {
					packet, packetErr := minimalReleaseReceive(t, f.gatePeer)
					if err != nil || packetErr != nil || packet.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease || !prep.current() {
						t.Fatal("delayed original release failed", err, packetErr)
					}
					minimalAdmissionRequireRevision(t, f, 2)
				} else {
					if err == nil || !prep.canceled.Load() || starter.released || starter.minimalGate.attempted || starter.minimalGate.operation != nil || starter.release() == nil {
						t.Fatal("post-CAS loss admitted send or retry")
					}
					minimalAdmissionRequireRevision(t, f, 1)
				}
				minimalGateIOCheckQueuedPackets(t, f.gatePeer, nil, 0)
			})
		})
	}
}

func minimalAdmissionIdentityFilesystem(t *testing.T, f *minimalPreparationFixture) *fakeJailerIdentityFilesystem {
	t.Helper()
	fs, ok := f.owned.selected.coordinator.generation.identity.fs.(*fakeJailerIdentityFilesystem)
	if !ok {
		t.Fatal("expected existing fake identity filesystem")
	}
	return fs
}

func minimalAdmissionWaitCAS(t *testing.T, prep *minimalControlPreparation) {
	t.Helper()
	deadline, tick := time.NewTimer(time.Second), time.NewTicker(time.Millisecond)
	defer deadline.Stop()
	defer tick.Stop()
	for !prep.canceled.releaseAdmitted() {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("actual selected CAS admission not reached")
		}
	}
}

func minimalAdmissionRequireRevision(t *testing.T, f *minimalPreparationFixture, want uint64) {
	t.Helper()
	record, err := f.owned.store.Load(context.Background())
	if err != nil || record.Revision != want {
		t.Fatal("actual canonical record revision", record.Revision, err)
	}
}
