//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalJailerTransportInterruptThenCloseJoins(t *testing.T) {
	f, client, completion := minimalJailerFinalizedFixture(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	socket, peer := os.NewFile(uintptr(pair[0]), "interrupted-close"), os.NewFile(uintptr(pair[1]), "retained-close-peer")
	defer socket.Close()
	defer peer.Close()
	client.ops.connectMinimal = func(context.Context, *os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error) { return socket, nil }
	var injected atomic.Bool
	var receives atomic.Int32
	client.ops.minimalIO = &minimalJailerSocketOps{sendmsg: unix.Sendmsg,
		recvmsg: func(fd int, buf, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
			if injected.CompareAndSwap(false, true) {
				return -1, 0, 0, nil, unix.EINTR
			}
			receives.Add(1)
			return unix.Recvmsg(fd, buf, oob, flags)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- completion.commit(ctx) }()
	joined := false
	defer func() {
		cancel()
		_ = unix.Shutdown(int(peer.Fd()), unix.SHUT_RDWR)
		if !joined {
			_ = joinMinimalJailerResult(t, done)
		}
	}()
	waitMinimalJailerExchange(t, "recvmsg")
	// Real receives may also return EINTR and retry before the stack is observed.
	if !injected.Load() || receives.Load() < 1 {
		t.Fatal("did not enter actual receive after interruption", injected.Load(), receives.Load())
	}
	closed := make(chan error, 1)
	go func() { closed <- client.close() }()
	if joinMinimalJailerResult(t, done) == nil {
		t.Fatal("Close returned false Commit success")
	}
	joined = true
	if joinMinimalJailerResult(t, closed) != nil {
		t.Fatal("Close did not join interrupted selected stream")
	}
	if completion.state.active != nil || completion.state.acknowledged || f.owned.store.selected.retired {
		t.Fatal("Close retained work or fabricated acknowledgment")
	}
	if _, err := socket.Stat(); err == nil {
		t.Fatal("owned socket survived joined Close")
	}
	if _, err := peer.Stat(); err != nil {
		t.Fatal("Close disposed independent peer", err)
	}
}

func TestMinimalJailerTransportCanceledMalformedCommitDoesNotLatch(t *testing.T) {
	for _, mode := range []string{"sequence", "opcode", "status", "body", "trailing", "short"} {
		t.Run(mode, func(t *testing.T) {
			f, _ := minimalJailerReplyFaultFixture(t, l8RuntimeOwnerOpcodeCommit, mode)
			client := f.fresh(t)
			completion, err := client.finalizeMinimalCleanup(context.Background())
			if err != nil {
				t.Fatal("actual Finalize prerequisite", err)
			}
			f.waitConnection()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, observed := 0, false
			client.ops.minimalIO = &minimalJailerSocketOps{sendmsg: unix.Sendmsg,
				recvmsg: func(fd int, buf, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
					n, oobn, receivedFlags, from, err := unix.Recvmsg(fd, buf, oob, flags)
					calls++
					if calls == 3 && err == nil && n > 0 {
						observed = true
						cancel() // Actual peer altered only the genuine Commit reply.
					}
					return n, oobn, receivedFlags, from, err
				},
			}
			result := completion.commit(ctx)
			f.waitConnection()
			if !observed || ctx.Err() != context.Canceled || !f.owned.store.selected.retired {
				t.Fatal("malformed actual Commit/cancellation prerequisite missing", calls, observed)
			}
			if result == nil || completion.state.acknowledged || completion.commit(context.Background()) == nil {
				t.Fatal("canceled malformed ACK became cached success")
			}
		})
	}
}
