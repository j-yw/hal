//go:build linux

package firecrackerhost

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLegacyClientReceiveRejectsUnsetBudget(t *testing.T) {
	client, _ := legacyClientReceivePair(t, 0)
	before := legacyClientReceiveBudgets(t, int(client.Fd()))
	calls := 0
	_, err := receiveJailerRecoveryClientReply(context.Background(), int(client.Fd()), func(int, []byte, []byte, int) (int, int, int, unix.Sockaddr, error) {
		calls++
		return -1, 0, 0, nil, unix.EINTR
	})
	if err == nil || calls != 0 || legacyClientReceiveBudgets(t, int(client.Fd())) != before {
		t.Fatalf("unset budget reached receive or changed options: %v calls=%d", err, calls)
	}
}

func TestLegacyClientReceiveRejectsExpiredContextBeforeSyscall(t *testing.T) {
	client, _ := legacyClientReceivePair(t, time.Second)
	before := legacyClientReceiveBudgets(t, int(client.Fd()))
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	calls := 0
	_, err := receiveJailerRecoveryClientReply(ctx, int(client.Fd()), func(int, []byte, []byte, int) (int, int, int, unix.Sockaddr, error) {
		calls++
		return -1, 0, 0, nil, unix.EINTR
	})
	if err == nil || calls != 0 || legacyClientReceiveBudgets(t, int(client.Fd())) != before {
		t.Fatalf("expired context reached receive or changed options: %v calls=%d", err, calls)
	}
}

func TestLegacyClientReceiveRejectsLateValidPacketAndRestoresBudget(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller_canceled", true: "original_budget_expired"}[deadline], func(t *testing.T) {
			client, _ := legacyClientReceivePair(t, 20*time.Millisecond)
			before := legacyClientReceiveBudgets(t, int(client.Fd()))
			_, reply := legacyClientReceivePackets(t)
			wire, _ := encodeL8RuntimeOwnerPacket(reply)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			response, err := receiveJailerRecoveryClientReply(ctx, int(client.Fd()), func(_ int, buf, _ []byte, _ int) (int, int, int, unix.Sockaddr, error) {
				calls++
				if deadline {
					time.Sleep(30 * time.Millisecond)
				} else {
					cancel()
				}
				copy(buf, wire)
				return len(wire), 0, 0, nil, nil
			})
			closeL8RuntimeOwnerFiles(response.Files)
			if err == nil || calls != 1 || response.Packet.Body != nil || legacyClientReceiveBudgets(t, int(client.Fd())) != before {
				t.Fatalf("late reply authorized data or changed options: %v calls=%d", err, calls)
			}
		})
	}
}

func TestLegacyClientReceivePreservesSuccessfulSyscallFlags(t *testing.T) {
	client, peer := legacyClientReceivePair(t, time.Second)
	_, reply := legacyClientReceivePackets(t)
	if err := sendL8RuntimeOwnerSeqpacket(int(peer.Fd()), reply, nil); err != nil {
		t.Fatal(err)
	}
	var observedFlags int
	response, err := receiveJailerRecoveryClientReply(context.Background(), int(client.Fd()), func(fd int, buf, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
		n, oobn, receivedFlags, from, err := unix.Recvmsg(fd, buf, oob, flags)
		observedFlags = receivedFlags
		return n, oobn, receivedFlags, from, err
	})
	defer closeL8RuntimeOwnerFiles(response.Files)
	if err != nil || response.Packet.Opcode != reply.Opcode {
		t.Fatalf("normal successful receive flags rejected: flags=%d err=%v", observedFlags, err)
	}
	t.Logf("successful real syscall flags=%d; shared decoder policy retained", observedFlags)
}
