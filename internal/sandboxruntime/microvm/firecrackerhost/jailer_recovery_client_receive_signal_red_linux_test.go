//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLegacyClientReceiveActualSignal(t *testing.T) {
	for _, exchange := range []bool{false, true} {
		for _, interrupt := range []bool{false, true} {
			name := map[bool]string{false: "observed_receive", true: "actual_exchange"}[exchange] + "/" + map[bool]string{false: "reply_control", true: "interrupted"}[interrupt]
			t.Run(name, func(t *testing.T) {
				client, peer := legacyClientReceivePair(t, time.Second)
				request, reply := legacyClientReceivePackets(t)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				ready, requestSeen := make(chan struct{}), make(chan struct{})
				allowReply, stopSender := make(chan struct{}), make(chan struct{})
				releaseReply := sync.OnceFunc(func() { close(allowReply) })
				stopSignals := sync.OnceFunc(func() { close(stopSender) })
				peerDone, senderDone, workerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
				operationDone := make(chan struct{})
				var tid int
				var operationErr, peerErr, senderErr error
				var response l8RuntimeOwnerPacketV1
				var rawInterrupts, sent atomic.Int32
				go func() {
					defer close(peerDone)
					received, err := receiveL8RuntimeOwnerSeqpacket(int(peer.Fd()))
					closeL8RuntimeOwnerFiles(received.Files)
					if err != nil || received.Packet.Opcode != request.Opcode || received.Packet.Sequence != request.Sequence || !bytes.Equal(received.Packet.Body, request.Body) {
						peerErr = errors.New("peer did not receive the one genuine request")
						return
					}
					close(requestSeen)
					<-allowReply
					peerErr = sendL8RuntimeOwnerSeqpacket(int(peer.Fd()), reply, nil)
				}()
				go func() {
					defer close(senderDone)
					defer releaseReply()
					select {
					case <-ready:
					case <-stopSender:
						return
					}
					select {
					case <-requestSeen:
					case <-stopSender:
						return
					}
					if !interrupt {
						return
					}
					for attempt := 0; attempt < 8; attempt++ {
						select {
						case <-stopSender:
							return
						case <-operationDone:
							return
						case <-time.After(10 * time.Millisecond):
						}
						if err := unix.Tgkill(os.Getpid(), tid, unix.SIGURG); err != nil {
							senderErr = err
							return
						}
						sent.Add(1)
						if !exchange && rawInterrupts.Load() > 0 {
							return
						}
					}
				}()
				go func() {
					runtime.LockOSThread()
					defer close(workerDone)
					defer runtime.UnlockOSThread()
					tid = unix.Gettid()
					close(ready)
					if exchange {
						response, operationErr = jailerRecoveryClientExchange(ctx, int(client.Fd()), request)
					} else if operationErr = sendL8RuntimeOwnerSeqpacket(int(client.Fd()), request, nil); operationErr == nil {
						var received l8RuntimeOwnerReceivedPacketV1
						received, operationErr = receiveJailerRecoveryClientReply(ctx, int(client.Fd()), func(fd int, buf, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
							n, oobn, resultFlags, from, err := unix.Recvmsg(fd, buf, oob, flags)
							if err == unix.EINTR {
								rawInterrupts.Add(1)
								t.Logf("actual recvmsg EINTR: n=%d oob=%d flags=%d", n, oobn, resultFlags)
							}
							return n, oobn, resultFlags, from, err
						})
						response = received.Packet
						closeL8RuntimeOwnerFiles(received.Files)
					}
					close(operationDone)
					<-senderDone // The retained locked TID cannot be reused early.
				}()
				t.Cleanup(func() {
					cancel()
					stopSignals()
					releaseReply()
					_ = unix.Shutdown(int(client.Fd()), unix.SHUT_RDWR)
					_ = unix.Shutdown(int(peer.Fd()), unix.SHUT_RDWR)
					legacyClientReceiveJoin(t, workerDone)
					legacyClientReceiveJoin(t, senderDone)
					legacyClientReceiveJoin(t, peerDone)
				})
				legacyClientReceiveJoin(t, workerDone)
				legacyClientReceiveJoin(t, peerDone)
				if senderErr != nil || peerErr != nil {
					t.Fatalf("signal/peer setup: %v / %v", senderErr, peerErr)
				}
				if interrupt && (sent.Load() == 0 || !exchange && rawInterrupts.Load() == 0) {
					t.Fatal("required real interruption was not observed")
				}
				if operationErr != nil || response.Opcode != reply.Opcode || response.Sequence != reply.Sequence || !bytes.Equal(response.Body, reply.Body) {
					t.Errorf("genuine reply after interruption was lost: %v", operationErr)
				}
				buf := make([]byte, l8RuntimeOwnerPacketLimit)
				n, _, _, _, err := unix.Recvmsg(int(peer.Fd()), buf, nil, unix.MSG_DONTWAIT)
				if err != unix.EAGAIN && err != unix.EWOULDBLOCK || n > 0 {
					t.Errorf("client resent request: n=%d err=%v", n, err)
				}
			})
		}
	}
}

func legacyClientReceivePair(t *testing.T, budget time.Duration) (*os.File, *os.File) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	client, peer := os.NewFile(uintptr(pair[0]), "legacy-client-receive"), os.NewFile(uintptr(pair[1]), "legacy-client-peer")
	t.Cleanup(func() { _ = client.Close(); _ = peer.Close() })
	if setL8RuntimeOwnerSocketTimeout(pair[0], budget) != nil {
		t.Fatal("socket budget setup failed")
	}
	return client, peer
}

func legacyClientReceivePackets(t *testing.T) (l8RuntimeOwnerPacketV1, l8RuntimeOwnerPacketV1) {
	t.Helper()
	body, err := encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1{SupervisorGeneration: l8RuntimeOwnerTestToken(1), RuntimeGeneration: "fixture-runtime", RecordRevision: 1, ReconnectSecret: l8RuntimeOwnerTestToken(2)})
	if err != nil {
		t.Fatal(err)
	}
	ack, err := encodeL8RuntimeOwnerHandshakeAck(l8RuntimeOwnerHandshakeAckV1{ControllerSessionGeneration: l8RuntimeOwnerTestToken(3), RecordRevision: 2})
	if err != nil {
		t.Fatal(err)
	}
	return l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: body}, l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeHandshake, Body: ack}
}

func legacyClientReceiveJoin(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("legacy receive diagnostic goroutine did not join")
	}
}
