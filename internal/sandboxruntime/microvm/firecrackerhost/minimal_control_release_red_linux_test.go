//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/binary"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalReleaseRevisionOneLossPreventsGateSend(t *testing.T) {
	for _, loss := range []string{"original_EOF", "original_P"} {
		t.Run(loss, func(t *testing.T) {
			deadline := time.Now().Add(time.Minute)
			if loss == "original_P" {
				deadline = time.Now().Add(5 * time.Second)
			}
			withMinimalPreparationFixture(t, deadline, func(f *minimalPreparationFixture) {
				starter := minimalReleaseUseTrackedFixture(t, f)
				entered, unblock := minimalReleasePauseAtRevisionOne(f)
				done := f.start(t)
				joined := false
				defer func() {
					unblock()
					if !joined {
						_ = minimalPreparationJoin(t, done)
					}
				}()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("actual revision-1 release boundary not reached")
				}
				minimalReleaseRequireRevisionOne(t, f, starter)
				prep := f.owned.minimalPreparation
				if !prep.current() || prep.deadline.UnixNano() != deadline.UnixNano() {
					t.Fatal("fixture lacks original current, unchanged admitted P")
				}
				if loss == "original_EOF" && unix.Shutdown(f.peer, unix.SHUT_RDWR) != nil {
					t.Fatal("original peer EOF prerequisite")
				}
				// P expires naturally. Nothing mutates/reseals admission or directly
				// cancels preparation. Join the actual observer and sole reader.
				for _, ended := range []<-chan struct{}{prep.ctx.Done(), prep.observerDone, prep.monitorDone, prep.ioDone} {
					select {
					case <-ended:
					case <-time.After(7 * time.Second):
						t.Fatal("actual loss observers did not join before release resumed")
					}
				}
				if !prep.canceled.Load() || prep.current() || loss == "original_P" && time.Now().Before(deadline) {
					t.Fatal("cancellation/absolute expiry was not observed before release")
				}
				unblock()
				err := minimalPreparationJoin(t, done)
				joined = true
				if err == nil {
					t.Error("canceled revision-1 bootstrap reported success")
				}
				packet, receiveErr := minimalReleaseReceive(t, f.gatePeer)
				if receiveErr == nil && packet.Packet.Opcode == l8RuntimeOwnerOpcodeChildRelease {
					t.Error("observed original loss at revision 1 still sent ChildRelease")
				}
				if f.owned.selected.starter.released {
					t.Error("observed original loss still consumed a successful gate release")
				}
				record, loadErr := f.owned.store.Load(context.Background())
				if loadErr != nil || record.Revision != 1 || record.State != "starting" || record.ControllerState != "none" {
					t.Fatal("loss promoted revision 1 to published running/terminal state", loadErr)
				}
				// Existing Abort may honestly finish fake owned cleanup. This test
				// does not turn that into new quarantine, absence or idle authority.
			})
		})
	}
}

func TestMinimalReleaseRevisionOneTrackedOrderControl(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		starter := minimalReleaseUseTrackedFixture(t, f)
		entered, unblock := minimalReleasePauseAtRevisionOne(f)
		done, joined := f.start(t), false
		defer func() {
			unblock()
			if !joined {
				_ = minimalPreparationJoin(t, done)
			}
		}()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("positive actual revision-1 boundary not reached")
		}
		minimalReleaseRequireRevisionOne(t, f, starter)
		unblock()
		err := minimalPreparationJoin(t, done)
		joined = true
		if err != nil {
			t.Fatal("tracked positive bootstrap failed before release", err)
		}
		gate, gateErr := minimalReleaseReceive(t, f.gatePeer)
		reply, replyErr := minimalReleaseReceive(t, f.peer)
		record, err := f.owned.store.Load(context.Background())
		if gateErr != nil || gate.Packet.Opcode != l8RuntimeOwnerOpcodeChildRelease || replyErr != nil ||
			reply.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapPublished || len(reply.Packet.Body) != 8 ||
			binary.BigEndian.Uint64(reply.Packet.Body) != 2 || err != nil || record.Revision != 2 || record.State != "running" ||
			!slices.Equal(f.order, []string{"genesis", "armed", "revision1", "release"}) {
			t.Fatal("tracked actual gate/store/reply ordering prerequisite", gateErr, replyErr, err)
		}
		if !f.owned.minimalPreparation.current() {
			t.Fatal("positive bootstrap disposed the continuing original owner lifetime")
		}
	})
}

func minimalReleasePauseAtRevisionOne(f *minimalPreparationFixture) (<-chan struct{}, func()) {
	entered, resume := make(chan struct{}), make(chan struct{})
	start := f.owner.opts.StartChild
	f.owner.opts.StartChild = func() (l8RuntimeOwnerStartedChild, error) {
		child, err := start()
		if err != nil {
			return child, err
		}
		release := child.Release
		child.Release = func() error {
			close(entered) // The unchanged real FSM has persisted revision 1.
			<-resume
			return release()
		}
		return child, nil
	}
	var once sync.Once
	return entered, func() { once.Do(func() { close(resume) }) }
}

func minimalReleaseReceive(t *testing.T, fd int) (l8RuntimeOwnerReceivedPacketV1, error) {
	t.Helper()
	if setL8RuntimeOwnerSocketTimeout(fd, time.Second) != nil {
		t.Fatal("ordinary fixture packet receive bound")
	}
	packet, err := receiveL8RuntimeOwnerSeqpacket(fd)
	if len(packet.Files) != 0 {
		closeL8RuntimeOwnerFiles(packet.Files)
		t.Fatal("unexpected rights in fixture gate/reply")
	}
	return packet, err
}
