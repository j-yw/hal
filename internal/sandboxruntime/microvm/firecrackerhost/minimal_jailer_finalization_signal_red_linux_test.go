//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The sender targets one retained, locked thread in this test process, never
// an external process or an unlocked/reused TID. Syscall observations do not
// change the real receive result. The original external diagnostic is retained.
func TestMinimalJailerFinalizationTransportActualSignalRed(t *testing.T) {
	for _, signal := range []bool{false, true} {
		t.Run(map[bool]string{false: "actual_response_control", true: "targeted_interrupt"}[signal], func(t *testing.T) {
			f, client, completion := minimalJailerFinalizedFixture(t)
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			socket := os.NewFile(uintptr(pair[0]), "diagnostic-selected-receiver")
			defer socket.Close()
			peer := os.NewFile(uintptr(pair[1]), "retained-diagnostic-peer")
			defer peer.Close()
			allowReply, peerDone := make(chan struct{}), make(chan struct{})
			var replyOnce sync.Once
			go func() {
				defer close(peerDone)
				request, err := receiveL8RuntimeOwnerSeqpacket(pair[1])
				closeL8RuntimeOwnerFiles(request.Files)
				if err != nil {
					return
				}
				result, err := f.owner.AdmitController(context.Background(), 0, request)
				if err != nil {
					return
				}
				defer f.owner.ControllerLost(context.Background())
				<-allowReply
				if sendL8RuntimeOwnerControlResult(pair[1], result) != nil {
					return
				}
				for {
					request, err = receiveL8RuntimeOwnerSeqpacket(pair[1])
					closeL8RuntimeOwnerFiles(request.Files)
					if err != nil {
						return
					}
					result, err = f.owner.HandleController(context.Background(), request)
					if err != nil || sendL8RuntimeOwnerControlResult(pair[1], result) != nil || result.Exit {
						return
					}
				}
			}()
			client.ops.connectMinimal = func(context.Context, *os.File, firecrackerRuntimeOwnerRecordV1) (*os.File, error) { return socket, nil }
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			ready, beginSignals := make(chan struct{}), make(chan struct{})
			stopSender, senderDone := make(chan struct{}), make(chan struct{})
			operationDone, workerDone := make(chan struct{}), make(chan struct{})
			var operationErr error
			var tid int
			var thread, taskRoot *os.File
			var observed unix.Stat_t
			var setupErr, senderErr error
			var sent int
			var diagnosticSelectedTID atomic.Int64
			var diagnosticSelectedEINTR atomic.Int32
			client.ops.minimalIO = &minimalJailerSocketOps{
				sendmsg: unix.Sendmsg,
				recvmsg: func(fd int, buf, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
					n, oobn, receivedFlags, from, err := unix.Recvmsg(fd, buf, oob, flags)
					if err == unix.EINTR && int64(unix.Gettid()) == diagnosticSelectedTID.Load() {
						diagnosticSelectedEINTR.Add(1)
					}
					return n, oobn, receivedFlags, from, err
				},
			}
			go func() {
				defer close(senderDone)
				select {
				case <-ready:
				case <-stopSender:
					return
				}
				select {
				case <-beginSignals:
				case <-stopSender:
					return
				}
				if !signal || setupErr != nil {
					return
				}
				for attempts := 0; attempts < 8; attempts++ {
					select {
					case <-stopSender:
						return
					case <-operationDone:
						return
					default:
					}
					if diagnosticSelectedEINTR.Load() != 0 {
						return
					}
					var retained, current unix.Stat_t
					if unix.Fstat(int(thread.Fd()), &retained) != nil || unix.Fstatat(int(taskRoot.Fd()), strconv.Itoa(tid), &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
						retained.Dev != observed.Dev || retained.Ino != observed.Ino || current.Dev != observed.Dev || current.Ino != observed.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
						senderErr = errL8RuntimeOwnerInvalid
						return
					}
					if err := unix.Tgkill(unix.Getpid(), tid, unix.SIGURG); err != nil {
						senderErr = err
						return
					}
					sent++
					timer := time.NewTimer(25 * time.Millisecond)
					select {
					case <-timer.C:
					case <-stopSender:
						timer.Stop()
						return
					case <-operationDone:
						timer.Stop()
						return
					}
				}
			}()
			go func() {
				runtime.LockOSThread()
				defer close(workerDone)
				defer runtime.UnlockOSThread()
				tid = unix.Gettid()
				taskRoot, setupErr = os.Open("/proc/self/task")
				if setupErr == nil {
					var fd int
					fd, setupErr = unix.Openat(int(taskRoot.Fd()), strconv.Itoa(tid), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
					if setupErr == nil {
						thread = os.NewFile(uintptr(fd), "retained-task-thread")
						setupErr = unix.Fstat(fd, &observed)
					}
				}
				close(ready)
				if setupErr == nil {
					operationErr = completion.commit(ctx)
				} else {
					operationErr = setupErr
				}
				close(operationDone)
				<-senderDone // Sender joins before retained descriptors or thread exit.
				if thread != nil {
					_ = thread.Close()
				}
				if taskRoot != nil {
					_ = taskRoot.Close()
				}
			}()
			defer func() {
				cancel()
				close(stopSender)
				<-senderDone
				replyOnce.Do(func() { close(allowReply) })
				_ = unix.Shutdown(pair[1], unix.SHUT_RDWR)
				select {
				case <-workerDone:
				case <-time.After(3 * time.Second):
					t.Error("diagnostic worker did not join")
				}
				select {
				case <-peerDone:
				case <-time.After(3 * time.Second):
					t.Error("diagnostic peer did not join")
				}
				diagnosticSelectedTID.Store(0)
			}()
			select {
			case <-ready:
			case <-time.After(3 * time.Second):
				t.Fatal("locked diagnostic thread not ready")
			}
			if setupErr != nil {
				t.Fatal("retained task thread prerequisite", setupErr)
			}
			diagnosticSelectedEINTR.Store(0)
			diagnosticSelectedTID.Store(int64(tid))
			waitMinimalJailerExchange(t, "recvmsg")
			close(beginSignals)
			if !signal {
				replyOnce.Do(func() { close(allowReply) })
			}
			select {
			case <-senderDone:
			case <-time.After(time.Second):
				t.Fatal("bounded sender did not join")
			}
			if signal && diagnosticSelectedEINTR.Load() == 0 {
				t.Fatal("SIGURG did not establish actual selected receive EINTR", sent, senderErr)
			}
			replyOnce.Do(func() { close(allowReply) })
			select {
			case <-operationDone:
			case <-time.After(3 * time.Second):
				t.Fatal("selected receive did not return after the bounded signal observation")
			}
			if senderErr != nil || ctx.Err() != nil {
				t.Fatal("selected operation result not attributable to the targeted interruption", senderErr, ctx.Err())
			}
			if operationErr != nil {
				t.Error("selected receive rejected recoverable interruption instead of receiving the actual ACK", operationErr)
			}
			t.Logf("selected receive: sent=%d EINTR=%d unavailable=%t callerCurrent=%t", sent, diagnosticSelectedEINTR.Load(), operationErr != nil, ctx.Err() == nil)
			replyOnce.Do(func() { close(allowReply) })
			select {
			case <-peerDone:
			case <-time.After(3 * time.Second):
				t.Fatal("actual protocol peer did not join")
			}
			if operationErr == nil && (!completion.state.acknowledged || !f.owned.store.selected.retired) {
				t.Fatal("success did not retain actual Commit ACK and retirement")
			}
		})
	}
}
