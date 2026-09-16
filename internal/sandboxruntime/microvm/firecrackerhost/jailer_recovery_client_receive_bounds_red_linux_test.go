//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLegacyClientReceiveInterruptedReplyRestoresBudgets(t *testing.T) {
	client, _ := legacyClientReceivePair(t, 80*time.Millisecond)
	fd := int(client.Fd())
	before := legacyClientReceiveBudgets(t, fd)
	_, reply := legacyClientReceivePackets(t)
	wire, _ := encodeL8RuntimeOwnerPacket(reply)
	calls := 0
	response, err := receiveJailerRecoveryClientReply(context.Background(), fd, func(fd int, buf, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
		calls++
		if calls == 1 {
			time.Sleep(5 * time.Millisecond)
			return -1, 0, 0, nil, unix.EINTR
		}
		if current := legacyClientReceiveBudgets(t, fd); current[0].Nano() >= before[0].Nano() || current[0].Nano() <= 0 {
			t.Error("retry did not use a strictly smaller positive remaining budget")
		}
		copy(buf, wire)
		return len(wire), 0, 0, nil, nil
	})
	defer closeL8RuntimeOwnerFiles(response.Files)
	if err != nil || calls != 2 || !bytes.Equal(response.Packet.Body, reply.Body) {
		t.Errorf("interrupted then genuine reply = %v, calls=%d; want success after two receives", err, calls)
	}
	if after := legacyClientReceiveBudgets(t, fd); after != before {
		t.Errorf("socket budgets changed: before=%v after=%v", before, after)
	}
}

func TestLegacyClientReceiveUsesOneAbsoluteBudget(t *testing.T) {
	for _, contextCap := range []bool{false, true} {
		t.Run(map[bool]string{false: "configured_socket", true: "earlier_context"}[contextCap], func(t *testing.T) {
			client, _ := legacyClientReceivePair(t, 80*time.Millisecond)
			fd := int(client.Fd())
			before := legacyClientReceiveBudgets(t, fd)
			budget := time.Duration(before[0].Nano())
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			start := time.Now()
			if contextCap {
				cancel()
				budget = 30 * time.Millisecond
				ctx, cancel = context.WithDeadline(context.Background(), start.Add(budget))
				defer cancel()
			}
			calls, guarded := 0, false
			response, err := receiveJailerRecoveryClientReply(ctx, fd, func(fd int, _, _ []byte, _ int) (int, int, int, unix.Sockaddr, error) {
				calls++
				current := legacyClientReceiveBudgets(t, fd)
				if contextCap && time.Duration(current[0].Nano()) > budget+2*time.Millisecond {
					t.Error("receive syscall budget exceeded original context cap")
				}
				// Bound the diagnostic even if an implementation incorrectly
				// rebases its timeout after every synthetic interruption.
				if time.Since(start) > 250*time.Millisecond {
					guarded = true
					return -1, 0, 0, nil, unix.ETIMEDOUT
				}
				time.Sleep(3 * time.Millisecond)
				return -1, 0, 0, nil, unix.EINTR
			})
			defer closeL8RuntimeOwnerFiles(response.Files)
			if err == nil || calls < 2 || time.Since(start) < budget || guarded {
				t.Errorf("interruption storm did not exhaust one original budget: err=%v calls=%d elapsed=%v budget=%v guard=%t", err, calls, time.Since(start), budget, guarded)
			}
			if after := legacyClientReceiveBudgets(t, fd); after != before {
				t.Errorf("failed receive changed socket budgets: before=%v after=%v", before, after)
			}
		})
	}
}

func TestLegacyClientReceiveCancellationAndClosedPeer(t *testing.T) {
	t.Run("canceled_before_exchange", func(t *testing.T) {
		client, peer := legacyClientReceivePair(t, time.Second)
		request, _ := legacyClientReceivePackets(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := jailerRecoveryClientExchange(ctx, int(client.Fd()), request); err == nil {
			t.Fatal("canceled exchange succeeded")
		}
		buf := make([]byte, l8RuntimeOwnerPacketLimit)
		if n, _, _, _, err := unix.Recvmsg(int(peer.Fd()), buf, nil, unix.MSG_DONTWAIT); n > 0 || err != unix.EAGAIN && err != unix.EWOULDBLOCK {
			t.Fatal("canceled exchange sent a request")
		}
	})
	t.Run("cancel_at_interruption", func(t *testing.T) {
		client, _ := legacyClientReceivePair(t, time.Second)
		before := legacyClientReceiveBudgets(t, int(client.Fd()))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		response, err := receiveJailerRecoveryClientReply(ctx, int(client.Fd()), func(int, []byte, []byte, int) (int, int, int, unix.Sockaddr, error) {
			calls++
			cancel()
			return -1, 0, 0, nil, unix.EINTR
		})
		closeL8RuntimeOwnerFiles(response.Files)
		if err == nil || calls != 1 || legacyClientReceiveBudgets(t, int(client.Fd())) != before {
			t.Fatalf("cancellation retried or changed budgets: %v, calls=%d", err, calls)
		}
	})
	for _, shutdown := range []bool{false, true} {
		t.Run(map[bool]string{false: "peer_eof", true: "owned_shutdown"}[shutdown], func(t *testing.T) {
			client, peer := legacyClientReceivePair(t, time.Second)
			ready, done := make(chan struct{}), make(chan struct{})
			var resultErr error
			go func() {
				defer close(done)
				close(ready)
				received, err := receiveJailerRecoveryClientReply(context.Background(), int(client.Fd()), unix.Recvmsg)
				closeL8RuntimeOwnerFiles(received.Files)
				resultErr = err
			}()
			t.Cleanup(func() {
				_ = unix.Shutdown(int(client.Fd()), unix.SHUT_RDWR)
				legacyClientReceiveJoin(t, done)
			})
			<-ready
			if shutdown {
				if err := unix.Shutdown(int(client.Fd()), unix.SHUT_RDWR); err != nil {
					t.Fatal(err)
				}
			} else if err := peer.Close(); err != nil {
				t.Fatal(err)
			}
			legacyClientReceiveJoin(t, done)
			if resultErr == nil {
				t.Fatal("closed stream authorized a reply")
			}
		})
	}
}

func TestLegacyClientReceiveAmbiguousRightsNeverRetry(t *testing.T) {
	for _, name := range []string{"error_with_rights", "error_with_bytes", "stale_ancillary_buffer", "malformed_with_rights", "truncated_with_rights", "timeout_with_rights"} {
		t.Run(name, func(t *testing.T) {
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
				t.Fatal("owned duplicate unavailable")
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
				if calls != 1 {
					return -1, 0, 0, nil, unix.EIO
				}
				copy(buf, wire)
				n := copy(oob, unix.UnixRights(right))
				// Error-plus-rights and zero-count stale-buffer observations are
				// synthetic impossible kernel tuples, using real owned FDs to
				// lock disposal and prove they can never authorize a retry.
				switch name {
				case "error_with_bytes":
					return len(wire), n, 0, nil, unix.EINTR
				case "stale_ancillary_buffer":
					return -1, 0, 0, nil, unix.EINTR
				case "malformed_with_rights":
					clear(buf)
					return 1, n, 0, nil, nil
				case "truncated_with_rights":
					return len(wire), n, unix.MSG_TRUNC, nil, nil
				case "timeout_with_rights":
					return -1, n, 0, nil, unix.EAGAIN
				default:
					return -1, n, 0, nil, unix.EINTR
				}
			})
			closeL8RuntimeOwnerFiles(response.Files)
			if err == nil || calls != 1 {
				t.Errorf("ambiguous receive retried or succeeded: %v calls=%d", err, calls)
			}
			if _, err := unix.FcntlInt(uintptr(right), unix.F_GETFD, 0); err != unix.EBADF {
				t.Errorf("rejected ancillary FD was not closed: %v", err)
			}
		})
	}
}

func legacyClientReceiveBudgets(t *testing.T, fd int) [2]unix.Timeval {
	t.Helper()
	var budgets [2]unix.Timeval
	for i, option := range []int{unix.SO_RCVTIMEO, unix.SO_SNDTIMEO} {
		value, err := unix.GetsockoptTimeval(fd, unix.SOL_SOCKET, option)
		if err != nil {
			t.Fatal(err)
		}
		budgets[i] = *value
	}
	return budgets
}
