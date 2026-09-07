//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Ordinary transport fixture only: no authenticated owner or cleanup proof.
func minimalJailerTransportFixture(t *testing.T, ctx context.Context, ops *minimalJailerSocketOps) (*minimalJailerIO, *os.File) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket, peer := os.NewFile(uintptr(pair[0]), "transport-fixture"), os.NewFile(uintptr(pair[1]), "transport-peer")
	stream, err := newMinimalJailerIO(ctx, socket, ops)
	if err != nil {
		_ = socket.Close()
		_ = peer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stream.close(); _ = socket.Close(); _ = peer.Close() })
	return stream, peer
}

func minimalJailerTransportPackets() (l8RuntimeOwnerPacketV1, l8RuntimeOwnerPacketV1) {
	return l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Sequence: 1, Body: []byte(l8RuntimeOwnerTestToken(1))},
		l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeInspect, Sequence: 1, Body: make([]byte, 24)}
}

type minimalJailerFixedDeadline struct {
	context.Context
	deadline time.Time
}

func (ctx minimalJailerFixedDeadline) Deadline() (time.Time, bool) { return ctx.deadline, true }

func TestMinimalJailerTransportBudgetDoesNotRebase(t *testing.T) {
	ctx := minimalJailerFixedDeadline{Context: context.Background(), deadline: time.Now().Add(160 * time.Millisecond)}
	sends, receives := 0, 0
	var budgets []time.Duration
	observe := func(fd int) {
		value, err := unix.GetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO)
		if err != nil {
			t.Fatal(err)
		}
		budgets = append(budgets, time.Duration(value.Nano()))
	}
	ops := &minimalJailerSocketOps{
		sendmsg: func(fd int, _, _ []byte, _ unix.Sockaddr, _ int) error {
			sends++
			observe(fd)
			<-time.After(45 * time.Millisecond)
			return nil
		},
		recvmsg: func(fd int, _, _ []byte, _ int) (int, int, int, unix.Sockaddr, error) {
			receives++
			observe(fd)
			if receives > 32 {
				return -1, 0, 0, nil, unix.EIO // Finite fixture failure, never success.
			}
			<-time.After(20 * time.Millisecond)
			return -1, 0, 0, nil, unix.EINTR
		},
	}
	stream, _ := minimalJailerTransportFixture(t, ctx, ops)
	request, _ := minimalJailerTransportPackets()
	if _, err := stream.exchange(request); err == nil {
		t.Fatal("exhausted absolute deadline accepted")
	}
	if ctx.Err() != nil || time.Now().Before(ctx.deadline) || sends != 1 || receives < 2 || receives > 10 || len(budgets) != receives+1 {
		t.Fatal("absolute budget boundary not reached independently of Err", sends, receives, ctx.Err())
	}
	for index := 1; index < len(budgets); index++ {
		if budgets[index] >= budgets[index-1] {
			t.Fatal("remaining socket budget was rebased", budgets)
		}
	}
}

func TestMinimalJailerTransportFiveSecondCap(t *testing.T) {
	for _, ctx := range []context.Context{context.Background(), minimalJailerFixedDeadline{context.Background(), time.Now().Add(time.Minute)}} {
		calls := 0
		ops := &minimalJailerSocketOps{
			sendmsg: func(fd int, _, _ []byte, _ unix.Sockaddr, _ int) error {
				calls++
				value, err := unix.GetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO)
				if err != nil || value.Nano() <= 0 || value.Nano() > int64(5*time.Second) {
					t.Fatal("selected five-second syscall cap missing", value, err)
				}
				return unix.EIO
			},
			recvmsg: unix.Recvmsg,
		}
		stream, _ := minimalJailerTransportFixture(t, ctx, ops)
		request, _ := minimalJailerTransportPackets()
		if _, err := stream.exchange(request); err == nil || calls != 1 {
			t.Fatal("non-EINTR send failure retried or accepted", calls)
		}
	}
}

func TestMinimalJailerTransportRejectedReceiveClosesActualRights(t *testing.T) {
	for _, mode := range []string{"rights", "negative_data", "oversize_data", "negative_control", "oversize_control", "partial_control", "clipped_control", "hidden_control", "interrupted_rights", "interrupted_data", "truncated", "control_truncated"} {
		t.Run(mode, func(t *testing.T) {
			var receivedFDs []int
			calls := 0
			ops := &minimalJailerSocketOps{sendmsg: unix.Sendmsg,
				recvmsg: func(fd int, wire, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
					calls++
					n, oobn, receivedFlags, from, err := unix.Recvmsg(fd, wire, oob, flags)
					if err != nil {
						t.Fatal("actual rights receive prerequisite", err)
					}
					messages, err := unix.ParseSocketControlMessage(oob[:oobn])
					if err != nil || len(messages) != 1 {
						t.Fatal("actual SCM prerequisite", err)
					}
					receivedFDs, err = unix.ParseUnixRights(&messages[0])
					if err != nil || len(receivedFDs) != 1 {
						t.Fatal("actual received descriptor prerequisite", err)
					}
					switch mode {
					case "negative_data":
						n = -1
					case "oversize_data":
						n = len(wire) + 1
					case "negative_control":
						oobn = -1
					case "oversize_control":
						oobn = len(oob) + 1
					case "partial_control":
						oobn = 1
					case "clipped_control":
						oobn = unix.CmsgLen(4) - 1
					case "hidden_control":
						oobn = 0
					case "interrupted_rights":
						n, err = -1, unix.EINTR
					case "interrupted_data":
						err = unix.EINTR
					case "truncated":
						receivedFlags |= unix.MSG_TRUNC
					case "control_truncated":
						receivedFlags |= unix.MSG_CTRUNC
					}
					return n, oobn, receivedFlags, from, err
				},
			}
			stream, peer := minimalJailerTransportFixture(t, context.Background(), ops)
			file, err := os.CreateTemp(t.TempDir(), "rights-")
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			request, response := minimalJailerTransportPackets()
			if sendL8RuntimeOwnerSeqpacket(int(peer.Fd()), response, []*os.File{file}) != nil {
				t.Fatal("queue actual rights")
			}
			if packet, err := stream.exchange(request); err == nil || len(packet.Body) != 0 || calls != 1 {
				t.Error("ambiguous receive accepted or retried", mode, calls)
			}
			for _, fd := range receivedFDs {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
					_ = unix.Close(fd) // Immediately release this leaked fixture copy.
					t.Error("rejected receive leaked its actual descriptor", mode, err)
				}
			}
			if _, err := file.Stat(); err != nil {
				t.Fatal("disposed caller-owned source", err)
			}
		})
	}
}
