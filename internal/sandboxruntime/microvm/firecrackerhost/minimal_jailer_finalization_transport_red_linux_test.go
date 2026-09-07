//go:build linux

package firecrackerhost

import (
	"context"
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMinimalJailerFinalizationTransportInterruptedSyscallRed(t *testing.T) {
	for _, direction := range []string{"send", "receive"} {
		t.Run(direction, func(t *testing.T) {
			f, client, completion := minimalJailerFinalizedFixture(t)
			interrupted, sent := false, 0
			client.ops.minimalIO = &minimalJailerSocketOps{
				sendmsg: func(fd int, wire, oob []byte, to unix.Sockaddr, flags int) error {
					if direction == "send" && !interrupted {
						interrupted = true
						return unix.EINTR
					}
					err := unix.Sendmsg(fd, wire, oob, to, flags)
					if err == nil {
						sent++
					}
					return err
				},
				recvmsg: func(fd int, wire, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
					if direction == "receive" && !interrupted {
						interrupted = true
						return -1, 0, 0, nil, unix.EINTR
					}
					return unix.Recvmsg(fd, wire, oob, flags)
				},
			}
			err := completion.commit(context.Background())
			f.waitConnection()
			if !interrupted {
				t.Fatal("selected syscall boundary was not reached")
			}
			if err != nil {
				t.Fatal("one interrupted syscall prevented actual same-owner Commit", err)
			}
			// Exactly handshake, Finalize and Commit reached the genuine peer.
			if sent != 3 || !completion.state.acknowledged || !f.owned.store.selected.retired {
				t.Fatal("interruption resent a request or bypassed real ACK/retirement", sent)
			}
		})
	}
}

func TestMinimalJailerFinalizationTransportReceivedAckCancellationRed(t *testing.T) {
	f, client, completion := minimalJailerFinalizedFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := 0
	target := completion.state.frozen.FinalizeTargetRevision
	client.ops.minimalIO = &minimalJailerSocketOps{
		sendmsg: unix.Sendmsg,
		recvmsg: func(fd int, wire, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
			n, oobn, receivedFlags, from, err := unix.Recvmsg(fd, wire, oob, flags)
			// Observe only the actual exact Commit reply. Do not create a
			// packet, replace bytes, retire the record or change return values.
			if err == nil && oobn == 0 && receivedFlags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) == 0 && n >= l8RuntimeOwnerPacketHeaderSize {
				packet, decodeErr := decodeL8RuntimeOwnerPacket(wire[:n])
				if decodeErr == nil && validateL8RuntimeOwnerPacketRole(packet, true, 0) == nil &&
					packet.Opcode == l8RuntimeOwnerOpcodeCommit && packet.Sequence == 2 && packet.Status == l8RuntimeOwnerStatusOK &&
					len(packet.Body) == 8 && binary.BigEndian.Uint64(packet.Body) == target {
					seen++
					cancel()
				}
			}
			return n, oobn, receivedFlags, from, err
		},
	}
	first := completion.commit(ctx)
	f.waitConnection()
	if seen != 1 || ctx.Err() != context.Canceled || first == nil {
		t.Fatal("actual exact received-ACK/canceled-caller prerequisite missing", seen, ctx.Err(), first)
	}
	if !f.owned.store.selected.retired {
		t.Fatal("genuine peer did not retire the original record")
	}
	if _, err := f.owned.store.Load(context.Background()); err == nil {
		t.Fatal("actual retired record remains loadable")
	}
	if !completion.state.acknowledged {
		t.Error("exact received Commit ACK discarded after actual cancellation")
	}
	if err := completion.commit(context.Background()); err != nil {
		t.Error("same original handle lost its actually received Commit ACK", err)
	}
}

func TestMinimalJailerFinalizationTransportPartialOpsControl(t *testing.T) {
	for _, ops := range []minimalJailerSocketOps{{}, {sendmsg: unix.Sendmsg}, {recvmsg: unix.Recvmsg}} {
		f, client, completion := minimalJailerFinalizedFixture(t)
		client.ops.minimalIO = &ops
		if completion.commit(context.Background()) == nil {
			t.Fatal("partial selected syscall operations admitted")
		}
		f.waitConnection()
		if completion.state.acknowledged || f.owned.store.selected.retired {
			t.Fatal("invalid operations fabricated acknowledgment")
		}
		client.ops.minimalIO = nil
		if completion.commit(context.Background()) != nil {
			t.Fatal("default concrete operations did not preserve explicit retry")
		}
		f.waitConnection()
	}
}
