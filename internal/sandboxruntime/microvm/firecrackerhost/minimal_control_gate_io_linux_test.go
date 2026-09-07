//go:build linux

package firecrackerhost

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalGateIOSelectedClosureRejectsBindingReplacement(t *testing.T) {
	for _, change := range []string{"missing", "foreign_starter", "foreign_preparation", "copied_binding"} {
		t.Run(change, func(t *testing.T) {
			withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
				capture := make(chan func() error, 1)
				start := f.owner.opts.StartChild
				f.owner.opts.StartChild = func() (l8RuntimeOwnerStartedChild, error) {
					child, err := start()
					if err == nil {
						capture <- child.Release
					}
					return child, err
				}
				entered, unblock := minimalReleasePauseAtRevisionOne(f)
				done, joined := f.start(t), false
				starter := f.owned.selected.starter
				original := starter.minimalGate
				defer func() {
					starter.minimalGate = original
					unblock()
					if !joined {
						_ = minimalPreparationJoin(t, done)
					}
				}()
				waitMinimalPreparationSignal(t, entered, "actual revision-1 pause")
				minimalReleaseRequireRevisionOne(t, f, f.tracked)
				var release func() error
				select {
				case release = <-capture:
				default:
					t.Fatal("actual selected callback not captured")
				}
				switch change {
				case "missing":
					starter.minimalGate = nil
				case "foreign_starter":
					starter.minimalGate = &minimalControlGateIO{starter: &jailerRecoveryStarter{}, prep: original.prep}
				case "foreign_preparation":
					starter.minimalGate = &minimalControlGateIO{starter: starter, prep: &minimalControlPreparation{}}
				case "copied_binding":
					starter.minimalGate = &minimalControlGateIO{starter: starter, prep: original.prep}
				}
				// The real owner is paused and no I/O is active. Invoke its captured
				// callback, then restore before the actual FSM resumes/cleans up.
				if release() == nil || starter.released || original.attempted || original.operation != nil {
					t.Fatal("changed selected binding reached legacy/send or consumed original operation")
				}
				starter.minimalGate = original
				unblock()
				if err := minimalPreparationJoin(t, done); err != nil {
					t.Fatal("exact original binding did not retain its valid release", err)
				}
				joined = true
				packet, err := minimalReleaseReceive(t, f.gatePeer)
				if err != nil || packet.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease {
					t.Fatal("exact original release control", err)
				}
			})
		})
	}
}

func TestMinimalGateIOBindingRejectsUsedOrForeignLifetime(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		for _, state := range []string{"missing_starter", "missing_preparation", "started", "released", "closed", "already_bound"} {
			t.Run(state, func(t *testing.T) {
				starter, prep := &jailerRecoveryStarter{}, f.owned.minimalPreparation
				switch state {
				case "missing_starter":
					starter = nil
				case "missing_preparation":
					prep = nil
				case "started":
					starter.started = true
				case "released":
					starter.released = true
				case "closed":
					starter.closed = true
				case "already_bound":
					starter = f.owned.selected.starter
				}
				if bindMinimalControlGateIO(starter, prep) == nil {
					t.Fatal("late/missing/duplicate lifetime accepted")
				}
			})
		}
		if !f.owned.minimalPreparation.current() || f.owned.selected.starter.minimalGate.attempted {
			t.Fatal("rejected binding affected original lifetime")
		}
	})
}

func TestMinimalGateIOConcurrentOperationAndCloseOwnership(t *testing.T) {
	for _, stop := range []string{"owner_cancel", "concurrent_close", "concurrent_release", "peer_error"} {
		t.Run(stop, func(t *testing.T) {
			withMinimalGateIOBlockedOperation(t, func(f *minimalPreparationFixture, join func() error) {
				starter := f.owned.selected.starter
				if !starter.mu.TryLock() {
					t.Fatal("starter bookkeeping mutex held over actual blocked send")
				}
				gate := starter.minimalGate
				op := gate.operation
				if op == nil || op.file == nil || !gate.attempted {
					starter.mu.Unlock()
					t.Fatal("actual send lacks registered owned operation")
				}
				var original, duplicate unix.Stat_t
				originalFD := starter.gate.Fd()
				observed := false
				// SyscallConn retains the operation FD for this test observation.
				// Fd() could race a timeout/error Close despite a prior blocked stack.
				raw, err := op.file.SyscallConn()
				if err == nil {
					err = raw.Control(func(fd uintptr) {
						flags, flagErr := unix.FcntlInt(fd, unix.F_GETFD, 0)
						observed = flagErr == nil && flags&unix.FD_CLOEXEC != 0 && fd != originalFD &&
							unix.Fstat(int(fd), &duplicate) == nil && unix.Fstat(int(originalFD), &original) == nil &&
							original.Dev == duplicate.Dev && original.Ino == duplicate.Ino
					})
				}
				starter.mu.Unlock()
				if err != nil || !observed {
					t.Fatal("gate operation did not retain an exact CLOEXEC duplicate")
				}
				results := make(chan error, 8)
				pending := 0
				defer func() {
					if pending != 0 {
						if !t.Failed() {
							t.Error("concurrent operations left unjoined")
						}
						_ = unix.Shutdown(f.gatePeer, unix.SHUT_RD)
						for pending > 0 {
							_ = minimalPreparationJoin(t, results)
							pending--
						}
					}
				}()
				switch stop {
				case "concurrent_close":
					pending = 8
					for range 8 {
						go func() { results <- starter.close() }()
					}
					for range 8 {
						err := minimalPreparationJoin(t, results)
						pending--
						if err != nil {
							t.Error("concurrent Close did not join exact local cleanup", err)
						}
					}
				case "concurrent_release":
					pending = 8
					for range 8 {
						go func() { results <- starter.release() }()
					}
					for range 8 {
						err := minimalPreparationJoin(t, results)
						pending--
						if err == nil {
							t.Error("another release attempt entered active gate operation")
						}
					}
					if !f.owned.minimalPreparation.current() {
						t.Fatal("rejected extra release revoked original owner's lifetime")
					}
					f.owned.minimalPreparation.revoke()
				case "owner_cancel":
					f.owned.minimalPreparation.revoke()
				case "peer_error":
					if unix.Shutdown(f.gatePeer, unix.SHUT_RD) != nil {
						t.Fatal("owned peer-error input")
					}
				}
				if err := join(); err == nil {
					t.Fatal("canceled/failed release became successful bootstrap")
				}
				waitMinimalPreparationSignal(t, op.done, "registered release operation")
				waitMinimalPreparationSignal(t, op.watcherDone, "owned gate watcher")
				if op.file.Fd() != ^uintptr(0) || !gate.attempted || starter.released || gate.operation != op || starter.release() == nil {
					t.Fatal("operation ownership escaped or failed attempt became reusable")
				}
				if starter.close() != nil || starter.close() != nil {
					t.Fatal("completed selected Close was not idempotent")
				}
			})
		})
	}
}

// Actual revision-1/store/returned Release; only host resources/process are the
// existing fake fixture. This helper joins every task even after Fatal. The
// callback joins through the supplied fixture closure; rescue follows failure.
func withMinimalGateIOBlockedOperation(t *testing.T, use func(*minimalPreparationFixture, func() error)) {
	t.Helper()
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		task := make(chan string, 1)
		start := f.owner.opts.StartChild
		f.owner.opts.StartChild = func() (l8RuntimeOwnerStartedChild, error) {
			task <- minimalGateIOCurrentTask()
			return start()
		}
		entered, unblock := minimalReleasePauseAtRevisionOne(f)
		done := f.start(t)
		joined := false
		defer func() {
			unblock()
			if !joined {
				_ = unix.Shutdown(f.gatePeer, unix.SHUT_RD)
				_ = minimalPreparationJoin(t, done)
			}
		}()
		waitMinimalPreparationSignal(t, entered, "actual revision-1 pause")
		minimalReleaseRequireRevisionOne(t, f, f.tracked)
		fill, count := minimalGateIOFillQueue(t, int(f.owned.selected.starter.gate.Fd()))
		unblock()
		select {
		case id := <-task:
			minimalGateIOWaitActualSend(t, id)
		default:
			t.Fatal("actual blocked operation task missing")
		}
		use(f, func() error {
			err := minimalPreparationJoin(t, done)
			joined = true
			return err
		})
		if !joined {
			t.Fatal("blocked-operation callback did not join bootstrap")
		}
		minimalGateIOCheckQueuedPackets(t, f.gatePeer, fill, count)
		record, err := f.owned.store.Load(context.Background())
		if err != nil || record.Revision != 1 || record.State != "starting" || record.ControllerState != "none" {
			t.Fatal("failed release promoted canonical revision 1", err)
		}
	})
}

func TestMinimalGateIOClosedDescriptorErrorIsRetained(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		starter := f.owned.selected.starter
		// No process/operation has started; close this fixture-owned endpoint to
		// reproduce a genuine close error without recycling a descriptor under I/O.
		if starter.gate.Close() != nil {
			t.Fatal("unused descriptor-close input")
		}
		first, second := starter.close(), starter.close()
		if first == nil || second != first || !starter.closed || f.owned.minimalPreparation.current() || starter.released {
			t.Fatal("descriptor-close uncertainty was hidden or revived")
		}
		select {
		case <-starter.minimalGate.closeDone:
		default:
			t.Fatal("local failed Close did not finish its handle ownership")
		}
		if _, err := unix.FcntlInt(uintptr(f.admission.borrowed[0]), unix.F_GETFD, 0); err != nil {
			t.Fatal("gate cleanup consumed borrowed original endpoint", err)
		}
	})
}

func TestMinimalGateIOClosePublishesCancellationBeforeStarterLock(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		starter := f.owned.selected.starter
		starter.mu.Lock()
		locked, joined := true, false
		done := make(chan error, 1)
		go func() { done <- starter.close() }()
		defer func() {
			if locked {
				starter.mu.Unlock()
			}
			if !joined {
				_ = minimalPreparationJoin(t, done)
			}
		}()
		waitMinimalPreparationSignal(t, f.owned.minimalPreparation.ctx.Done(), "Close cancellation while starter mutex is held")
		if !f.owned.minimalPreparation.canceled.Load() {
			t.Fatal("Close did not publish through the original cancellation latch")
		}
		starter.mu.Unlock()
		locked = false
		if err := minimalPreparationJoin(t, done); err != nil {
			t.Fatal("Close after mutex release", err)
		}
		joined = true
	})
}

func TestMinimalGateIOReleaseRechecksCancellationAfterStarterLock(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		entered, unblock := minimalReleasePauseAtRevisionOne(f)
		done, joined := f.start(t), false
		starter := f.owned.selected.starter
		locked := false
		var releaseDone <-chan error
		releaseJoined := false
		defer func() {
			if locked {
				starter.mu.Unlock()
			}
			if releaseDone != nil && !releaseJoined {
				_ = minimalPreparationJoin(t, releaseDone)
			}
			unblock()
			if !joined {
				_ = minimalPreparationJoin(t, done)
			}
		}()
		waitMinimalPreparationSignal(t, entered, "actual revision-1 pause")
		minimalReleaseRequireRevisionOne(t, f, f.tracked)
		starter.mu.Lock()
		locked = true
		released := make(chan error, 1)
		taskID := make(chan string, 1)
		releaseDone = released
		go func() {
			taskID <- minimalGateIOCurrentTask()
			released <- starter.release()
		}()
		select {
		case id := <-taskID:
			minimalGateIOWaitReleaseLock(t, id)
		case <-time.After(3 * time.Second):
			t.Fatal("gate entry task did not start")
		}
		f.owned.minimalPreparation.revoke()
		starter.mu.Unlock()
		locked = false
		if err := minimalPreparationJoin(t, releaseDone); err == nil {
			t.Fatal("post-mutex cancellation reached gate send")
		}
		releaseJoined = true
		if starter.minimalGate.attempted || starter.minimalGate.operation != nil || starter.released {
			t.Fatal("canceled gate entry consumed an operation/descriptor")
		}
		unblock()
		if err := minimalPreparationJoin(t, done); err == nil {
			t.Fatal("canceled actual bootstrap succeeded")
		}
		joined = true
		minimalGateIOCheckQueuedPackets(t, f.gatePeer, nil, 0)
	})
}

func minimalGateIOWaitReleaseLock(t *testing.T, task string) {
	t.Helper()
	if task == "" {
		t.Fatal("gate entry task identity missing")
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	buffer := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buffer, true)
		for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
			if strings.HasPrefix(stack, task) && strings.Contains(stack, "firecrackerhost.(*jailerRecoveryStarter).beginMinimalGateRelease") &&
				strings.Contains(stack, "sync.(*Mutex).lockSlow") {
				return
			}
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("actual selected gate entry did not wait for starter mutex")
		}
	}
}
