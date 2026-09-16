//go:build linux

package firecrackerhost

import (
	"context"
	"os"
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

func TestLegacyClientReceiveShortAncillaryCountClosesOwnedPrefix(t *testing.T) {
	for _, count := range []int{1, unix.CmsgLen(4) - 1} {
		t.Run(map[bool]string{true: "short_header", false: "short_rights"}[count == 1], func(t *testing.T) {
			client, _ := legacyClientReceivePair(t, time.Second)
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			right, err := unix.FcntlInt(reader.Fd(), unix.F_DUPFD_CLOEXEC, 3)
			if err != nil {
				t.Fatal(err)
			}
			var owned unix.Stat_t
			if unix.Fstat(right, &owned) != nil {
				t.Fatal("duplicate unavailable")
			}
			t.Cleanup(func() {
				var current unix.Stat_t
				if unix.Fstat(right, &current) == nil && current.Dev == owned.Dev && current.Ino == owned.Ino {
					_ = unix.Close(right)
				}
			})
			_, reply := legacyClientReceivePackets(t)
			wire, _ := encodeL8RuntimeOwnerPacket(reply)
			calls := 0
			response, err := receiveJailerRecoveryClientReply(context.Background(), int(client.Fd()), func(_ int, buf, oob []byte, _ int) (int, int, int, unix.Sockaddr, error) {
				calls++
				copy(buf, wire)
				copy(oob, unix.UnixRights(right))
				// Impossible kernel tuple: a valid owned prefix remains beyond
				// an undersized reported count. Rejection must still dispose it.
				return len(wire), count, 0, nil, nil
			})
			closeL8RuntimeOwnerFiles(response.Files)
			if err == nil || calls != 1 {
				t.Errorf("invalid ancillary count accepted or retried: %v calls=%d", err, calls)
			}
			if _, err := unix.FcntlInt(uintptr(right), unix.F_GETFD, 0); err != unix.EBADF {
				t.Errorf("short-count rejection leaked its actual owned FD: %v", err)
			}
		})
	}
}
