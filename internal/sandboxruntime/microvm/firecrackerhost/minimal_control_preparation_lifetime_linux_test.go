//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalPreparationCurrentRequiresInitializedLifetimeAndAbsoluteP(t *testing.T) {
	for _, mode := range []string{"nil", "zero", "expired_live_context"} {
		t.Run(mode, func(t *testing.T) {
			var prep *minimalControlPreparation
			if mode == "zero" {
				prep = &minimalControlPreparation{}
			} else if mode == "expired_live_context" {
				// Pure admission check only: a not-yet-canceled context cannot
				// stand in for synchronous comparison with immutable P.
				prep = &minimalControlPreparation{ctx: context.Background(), deadline: time.Now().Add(-time.Second)}
			}
			if prep.current() {
				t.Fatal("uninitialized or expired preparation considered current")
			}
		})
	}
}

func waitMinimalPreparationSignal(t *testing.T, done <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fixture failed to join " + label)
	}
}

func waitMinimalPreparationOperation(t *testing.T, prep *minimalControlPreparation) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(3 * time.Second)
	defer timeout.Stop()
	for {
		prep.mu.Lock()
		started := prep.operation != nil
		prep.mu.Unlock()
		if started {
			return
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("fixture never entered original receive operation")
		}
	}
}

func TestMinimalPreparationOriginalMonitorAfterReply(t *testing.T) {
	for _, mode := range []string{"eof", "packet", "malformed", "rights", "oversized_rights"} {
		t.Run(mode, func(t *testing.T) {
			withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
				if err := minimalPreparationJoin(t, f.start(t)); err != nil {
					t.Fatal("actual bootstrap prerequisite", err)
				}
				prep := f.owned.minimalPreparation
				if prep.monitorDone == nil || prep.ctx.Err() != nil {
					t.Fatal("sole original monitor was not retained after reply")
				}
				before := minimalNamespaceTestHandleCount(t, f.files)
				wire, err := encodeL8RuntimeOwnerPacket(l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildRelease})
				if err != nil {
					t.Fatal(err)
				}
				var control []byte
				switch mode {
				case "eof":
					err = unix.Shutdown(f.peer, unix.SHUT_RDWR)
				case "malformed":
					wire = []byte{1}
				case "rights", "oversized_rights":
					control = unix.UnixRights(int(f.files[0].Fd()), int(f.files[1].Fd()))
					if mode == "oversized_rights" {
						wire = bytes.Repeat([]byte{1}, l8RuntimeOwnerPacketLimit+1)
					}
				}
				if mode != "eof" {
					err = unix.Sendmsg(f.peer, wire, control, nil, 0)
				}
				if err != nil {
					t.Fatal("actual original loss input prerequisite", err)
				}
				waitMinimalPreparationSignal(t, prep.ctx.Done(), "original-channel cancellation")
				waitMinimalPreparationSignal(t, prep.monitorDone, "original monitor")
				if !prep.canceled.Load() || minimalNamespaceTestHandleCount(t, f.files) != before {
					t.Fatal("original loss did not latch or leaked received rights")
				}
				if f.owned.shutdownMinimalControlPreparation() != nil {
					t.Fatal("joined original monitor shutdown")
				}
			})
		})
	}
}

func TestMinimalPreparationDeadlineObserverSurvivesReply(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(2*time.Second), func(f *minimalPreparationFixture) {
		if err := minimalPreparationJoin(t, f.start(t)); err != nil {
			t.Fatal("actual bootstrap prerequisite", err)
		}
		prep := f.owned.minimalPreparation
		if !prep.current() || prep.deadline.UnixNano() != f.admission.config.Control.PreparationDeadlineUnixNano {
			t.Fatal("fixture did not reach post-reply admission before original P")
		}
		waitMinimalPreparationSignal(t, prep.ctx.Done(), "original P observer")
		if time.Now().Before(prep.deadline) || !prep.canceled.Load() {
			t.Fatal("deadline observer rebased or failed to latch cancellation")
		}
		waitMinimalPreparationSignal(t, prep.observerDone, "P observer")
		waitMinimalPreparationSignal(t, prep.monitorDone, "deadline-interrupted monitor")
	})
}

func TestMinimalPreparationInitialReceiveCancellationAndClose(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			deadline := time.Now().Add(time.Minute)
			if mode == "deadline" {
				deadline = time.Now().Add(2 * time.Second)
			}
			withMinimalPreparationFixture(t, deadline, func(f *minimalPreparationFixture) {
				prep := f.owned.minimalPreparation
				done := make(chan error, 1)
				go func() { done <- f.owned.serveMinimalControlPreparation(f.owner, f.admission.borrowed[0], f.admission) }()
				waitMinimalPreparationOperation(t, prep)
				if mode == "cancel" {
					prep.revoke()
				}
				if mode == "close" {
					closed := make(chan error, 1)
					go func() { closed <- f.owned.shutdownMinimalControlPreparation() }()
					if err := minimalPreparationJoin(t, closed); err != nil {
						t.Fatal("outside-lock shutdown failed", err)
					}
				}
				if err := minimalPreparationJoin(t, done); err == nil || f.owned.selected.attempted || f.owned.store.selected.file != nil {
					t.Fatal("initial receive cancellation reached genesis/launch", err)
				}
				var wg sync.WaitGroup
				errors := make(chan error, 6)
				for range 6 {
					wg.Add(1)
					go func() { defer wg.Done(); errors <- f.owned.shutdownMinimalControlPreparation() }()
				}
				wg.Wait()
				close(errors)
				for err := range errors {
					if err != nil {
						t.Error("repeated shutdown changed terminal local result", err)
					}
				}
				if _, err := unix.FcntlInt(uintptr(f.admission.borrowed[0]), unix.F_GETFD, 0); err != nil {
					t.Fatal("shutdown closed borrowed original FD")
				}
			})
		})
	}
}

func TestMinimalPreparationRejectsChangedServeBinding(t *testing.T) {
	for _, mode := range []string{"correlation", "deadline", "replacement_fd"} {
		t.Run(mode, func(t *testing.T) {
			withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
				prep := f.owned.minimalPreparation
				switch mode {
				case "correlation":
					original := f.admission.configDigest
					defer func() { f.admission.configDigest = original }()
					f.admission.configDigest[0] ^= 1
				case "deadline":
					original := f.admission.config.Control.PreparationDeadlineUnixNano
					defer func() { f.admission.config.Control.PreparationDeadlineUnixNano = original }()
					f.admission.config.Control.PreparationDeadlineUnixNano++ // Caller metadata, not retained P.
				case "replacement_fd":
					pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
					if err != nil {
						t.Fatal(err)
					}
					defer unix.Close(pair[0])
					defer unix.Close(pair[1])
					if unix.Dup3(pair[0], prep.borrowedFD, unix.O_CLOEXEC) != nil {
						t.Fatal("replace only unused task-owned borrowed alias")
					}
					defer func() {
						if unix.Dup3(int(prep.original.Fd()), prep.borrowedFD, unix.O_CLOEXEC) != nil {
							t.Error("restore exact fixture alias before admission cleanup")
						}
					}()
				}
				if err := f.owned.serveMinimalControlPreparation(f.owner, f.admission.borrowed[0], f.admission); err == nil || prep.used || f.owned.selected.attempted {
					t.Fatal("changed caller binding selected a replacement owner/endpoint")
				}
				if _, err := prep.original.Stat(); err != nil {
					t.Fatal("rejection discarded retained original endpoint", err)
				}
			})
		})
	}
}

func TestMinimalPreparationInitialReceiveRejectsUntrustedPackets(t *testing.T) {
	for _, mode := range []string{"eof", "malformed_rights", "oversized_rights", "excess_rights"} {
		t.Run(mode, func(t *testing.T) {
			withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
				before := minimalNamespaceTestHandleCount(t, f.files)
				wire, err := encodeL8RuntimeOwnerPacket(f.packet)
				if err != nil {
					t.Fatal(err)
				}
				fds := []int{int(f.files[0].Fd()), int(f.files[1].Fd())}
				switch mode {
				case "eof":
					err = unix.Shutdown(f.peer, unix.SHUT_RDWR)
				case "malformed_rights":
					wire = []byte{1}
				case "oversized_rights":
					wire = bytes.Repeat([]byte{1}, l8RuntimeOwnerPacketLimit+1)
				case "excess_rights":
					fds = append(fds, fds...)
				}
				if mode != "eof" {
					err = unix.Sendmsg(f.peer, wire, unix.UnixRights(fds...), nil, 0)
				}
				if err != nil {
					t.Fatal("actual initial invalid input prerequisite", err)
				}
				err = f.owned.serveMinimalControlPreparation(f.owner, f.admission.borrowed[0], f.admission)
				prep := f.owned.minimalPreparation
				if err == nil || f.owned.selected.attempted || f.owned.store.selected.file != nil || prep.monitorDone != nil || !prep.canceled.Load() {
					t.Fatal("invalid initial packet reached monitor/genesis/launch or failed to cancel", err)
				}
				if minimalNamespaceTestHandleCount(t, f.files) != before {
					t.Fatal("rejected initial packet leaked received rights")
				}
			})
		})
	}
}

func TestMinimalPreparationTransferredMonitorRetainsOriginalEndpoint(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		if err := minimalPreparationJoin(t, f.start(t)); err != nil {
			t.Fatal("actual bootstrap prerequisite", err)
		}
		prep := f.owned.minimalPreparation
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(pair[0])
		defer unix.Close(pair[1])
		if unix.Dup3(pair[0], prep.borrowedFD, unix.O_CLOEXEC) != nil {
			t.Fatal("replace only caller's task-owned alias after receive transfer")
		}
		defer func() {
			if unix.Dup3(int(prep.original.Fd()), prep.borrowedFD, unix.O_CLOEXEC) != nil {
				t.Error("restore exact borrowed alias before joined fixture cleanup")
			}
		}()
		// Original peer loss must still reach the existing monitor. The newly
		// installed successor endpoint must neither receive nor be shut down.
		if unix.Shutdown(f.peer, unix.SHUT_RDWR) != nil {
			t.Fatal("original peer EOF prerequisite")
		}
		waitMinimalPreparationSignal(t, prep.monitorDone, "retained original monitor")
		waitMinimalPreparationSignal(t, prep.ioDone, "retained original I/O interrupter")
		if !prep.canceled.Load() {
			t.Fatal("original EOF no longer canceled selected lifetime")
		}
		if unix.Sendmsg(pair[1], []byte{7}, nil, nil, unix.MSG_DONTWAIT) != nil {
			t.Fatal("cancellation affected successor socket")
		}
		payload := make([]byte, 1)
		if n, _, err := unix.Recvfrom(pair[0], payload, unix.MSG_DONTWAIT); err != nil || n != 1 || payload[0] != 7 {
			t.Fatal("successor bytes were consumed or endpoint was shut down", err)
		}
	})
}
