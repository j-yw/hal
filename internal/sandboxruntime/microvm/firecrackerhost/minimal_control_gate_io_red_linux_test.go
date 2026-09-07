//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalGateIOBlockedReleaseObservesLoss(t *testing.T) {
	for _, loss := range []string{"original_EOF", "original_P", "starter_Close"} {
		t.Run(loss, func(t *testing.T) {
			deadline := time.Now().Add(time.Minute)
			if loss == "original_P" {
				deadline = time.Now().Add(3 * time.Second)
			}
			withMinimalPreparationFixture(t, deadline, func(f *minimalPreparationFixture) {
				starter := minimalReleaseUseTrackedFixture(t, f)
				entered, unblock := minimalReleasePauseAtRevisionOne(f)
				// Capture only this fixture's actual bootstrap goroutine identity;
				// another task's blocked syscall cannot satisfy the prerequisite.
				taskID := make(chan string, 1)
				start := f.owner.opts.StartChild
				f.owner.opts.StartChild = func() (l8RuntimeOwnerStartedChild, error) {
					taskID <- minimalGateIOCurrentTask()
					return start()
				}
				canary, err := os.CreateTemp(t.TempDir(), "gate-successor-")
				if err != nil {
					t.Fatal("successor canary prerequisite", err)
				}
				defer canary.Close()
				if _, err := canary.Write([]byte("retained successor canary")); err != nil {
					t.Fatal("successor canary contents", err)
				}
				done, joined := f.start(t), false
				var closeDone <-chan error
				var alias *os.File
				closeJoined := false
				// Shutdown is a last-resort test rescue, never a passing outcome.
				// It cannot recycle a raw FD under the blocked writer. Every task
				// joins before the fixture closes its retained descriptors.
				defer func() {
					unblock()
					if !joined {
						_ = unix.Shutdown(f.gatePeer, unix.SHUT_RD)
						_ = minimalPreparationJoin(t, done)
					}
					if closeDone != nil && !closeJoined {
						_ = minimalPreparationJoin(t, closeDone)
					}
					if alias != nil {
						_ = alias.Close()
					}
				}()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("actual revision-1 release prerequisite not reached")
				}
				minimalReleaseRequireRevisionOne(t, f, starter)
				prep := f.owned.minimalPreparation
				if !prep.current() {
					t.Fatal("preparation expired before blocked-send prerequisite")
				}
				gate := f.owned.selected.starter.gate
				gateFD := int(gate.Fd())
				aliasFD, err := unix.FcntlInt(gate.Fd(), unix.F_DUPFD_CLOEXEC, 10)
				if err != nil {
					t.Fatal("retained test alias", err)
				}
				alias = os.NewFile(uintptr(aliasFD), "gate-io-test-alias")
				var original unix.Stat_t
				if unix.Fstat(aliasFD, &original) != nil {
					t.Fatal("retained alias identity")
				}
				// Mirror the real starter's existing socket timeout. Prompt loss
				// must finish before this old bound, not merely benefit from it.
				if setL8RuntimeOwnerSocketTimeout(gateFD, l8RuntimeOwnerHandshakeTimeout) != nil {
					t.Fatal("existing gate timeout prerequisite")
				}
				fill, count := minimalGateIOFillQueue(t, gateFD)
				oldTimeoutNotBefore := time.Now().Add(l8RuntimeOwnerHandshakeTimeout)
				unblock()
				select {
				case task := <-taskID:
					minimalGateIOWaitActualSend(t, task)
				default:
					t.Fatal("revision-1 task identity was not captured")
				}
				// The actual selected Release has passed its current positive
				// admission and is in sendmsg; this is not a pre-entry cancel.
				if !prep.current() {
					t.Fatal("loss preceded actual blocked send")
				}
				if loss == "original_P" && time.Until(deadline) < time.Second {
					t.Fatal("insufficient original P after blocked-send prerequisite")
				}
				if loss == "starter_Close" {
					closed := make(chan error, 1)
					closeDone = closed
					go func() { closed <- f.owned.selected.starter.close() }()
				} else {
					if loss == "original_EOF" && unix.Shutdown(f.peer, unix.SHUT_RDWR) != nil {
						t.Fatal("original EOF prerequisite")
					}
					for _, observed := range []<-chan struct{}{prep.ctx.Done(), prep.observerDone, prep.monitorDone, prep.ioDone} {
						select {
						case <-observed:
						case <-time.After(7 * time.Second):
							t.Fatal("actual original loss observer failed to join")
						}
					}
				}
				margin := time.Second // One 750ms operation wait plus scheduling slack.
				if closeDone != nil {
					margin = 2 * time.Second // A second bounded Close wait.
				}
				if !time.Now().Add(margin).Before(oldTimeoutNotBefore) {
					t.Fatal("loss observation too late to distinguish cancellation from old socket timeout")
				}
				prompt := true
				var operationErr error
				select {
				case operationErr = <-done:
					joined = true
					if !time.Now().Before(oldTimeoutNotBefore) {
						t.Error("old socket timeout progress is not prompt cancellation")
					}
				case <-time.After(750 * time.Millisecond):
					prompt = false
					t.Error("observed loss did not interrupt the actual blocked gate release")
				}
				if closeDone != nil {
					select {
					case err := <-closeDone:
						closeJoined = true
						if err != nil {
							t.Error("starter Close failed", err)
						}
					case <-time.After(750 * time.Millisecond):
						prompt = false
						t.Error("starter Close waited behind blocked gate I/O")
					}
				}
				if !prompt {
					// Diagnostic cleanup only, after the intended assertion failed.
					// No queue draining or watchdog progress can turn RED into PASS.
					if unix.Shutdown(f.gatePeer, unix.SHUT_RD) != nil {
						t.Fatal("fixture rescue shutdown failed")
					}
					if !joined {
						operationErr = minimalPreparationJoin(t, done)
						joined = true
					}
					if closeDone != nil && !closeJoined {
						_ = minimalPreparationJoin(t, closeDone)
						closeJoined = true
					}
				}
				if operationErr == nil || f.owned.selected.starter.released {
					t.Error("blocked canceled operation became successful release")
				}
				// Drain only after all writers joined. Count exact filler and any
				// valid release separately; invalid bytes cannot masquerade as it.
				minimalGateIOCheckQueuedPackets(t, f.gatePeer, fill, count)
				var retained unix.Stat_t
				if unix.Fstat(aliasFD, &retained) != nil || retained.Dev != original.Dev || retained.Ino != original.Ino {
					t.Fatal("operation consumed or replaced the test-owned alias")
				}
				record, err := f.owned.store.Load(context.Background())
				if err != nil || record.Revision != 1 || record.State != "starting" || record.ControllerState != "none" {
					t.Fatal("failed gate I/O promoted canonical revision 1", err)
				}
				// Only after bootstrap/Close joined may preparation shutdown join
				// its observers and the old descriptor number become a successor.
				minimalGateIOCheckSuccessor(t, f, canary, gateFD)
				if unix.Fstat(aliasFD, &retained) != nil || retained.Dev != original.Dev || retained.Ino != original.Ino {
					t.Fatal("repeated cleanup consumed the retained socket alias")
				}
			})
		})
	}
}

func minimalGateIOFillQueue(t *testing.T, fd int) ([]byte, int) {
	t.Helper()
	wire, err := encodeL8RuntimeOwnerPacket(l8RuntimeOwnerPacketV1{Opcode: l8RuntimeOwnerOpcodeChildRelease})
	if err != nil {
		t.Fatal(err)
	}
	filler := bytes.Repeat([]byte{'Q'}, len(wire))
	if _, err := decodeL8RuntimeOwnerPacket(filler); err == nil {
		t.Fatal("filler accidentally became protocol")
	}
	if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4096) != nil {
		t.Fatal("bounded queue prerequisite")
	}
	for count := 0; count < 128; count++ {
		n, err := unix.SendmsgN(fd, filler, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
		if errors.Is(err, unix.EAGAIN) {
			if count == 0 {
				t.Fatal("queue was not empty before owned filler")
			}
			return filler, count
		}
		if err != nil || n != len(filler) {
			t.Fatal("bounded filler send", n, err)
		}
	}
	t.Fatal("bounded queue never filled")
	return nil, 0
}

// Observe only the actual bootstrap task blocked in its real Unix send. No
// callback/observer is injected into production and timeout is setup failure.
func minimalGateIOWaitActualSend(t *testing.T, task string) {
	t.Helper()
	if task == "" {
		t.Fatal("actual bootstrap task identity missing")
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		for _, stack := range strings.Split(string(buf[:n]), "\n\n") {
			if strings.HasPrefix(stack, task) &&
				strings.Contains(stack, "firecrackerhost.(*l8RuntimeOwnerLinuxRuntime).serveMinimalControlPreparation") &&
				strings.Contains(stack, "firecrackerhost.(*l8RuntimeOwnerSupervisor).HandleBootstrap") &&
				strings.Contains(stack, "firecrackerhost.(*jailerRecoveryStarter).release") &&
				strings.Contains(stack, "golang.org/x/sys/unix.Sendmsg") && strings.Contains(stack, "[syscall]") {
				return
			}
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("actual selected blocked sendmsg not reached")
		}
	}
}

func minimalGateIOCurrentTask() string {
	var buffer [128]byte
	n := runtime.Stack(buffer[:], false)
	header, _, _ := strings.Cut(string(buffer[:n]), "\n")
	fields := strings.Fields(header)
	if len(fields) < 2 || fields[0] != "goroutine" || fields[1] == "" {
		return ""
	}
	for _, digit := range fields[1] {
		if digit < '0' || digit > '9' {
			return ""
		}
	}
	return "goroutine " + fields[1] + " "
}

func minimalGateIOCheckSuccessor(t *testing.T, f *minimalPreparationFixture, canary *os.File, oldFD int) {
	t.Helper()
	if f.owned.shutdownMinimalControlPreparation() != nil || f.owned.selected.starter.close() != nil {
		t.Fatal("joined old owner close prerequisite")
	}
	// Allocate the now-free old number; never overwrite any occupied descriptor
	// with dup2/dup3 or recycle one while an operation/watcher still owns it.
	fd, err := unix.FcntlInt(canary.Fd(), unix.F_DUPFD_CLOEXEC, oldFD)
	if err != nil {
		t.Fatal("successor allocation", err)
	}
	successor := os.NewFile(uintptr(fd), "gate-io-successor")
	defer successor.Close()
	if fd != oldFD {
		t.Fatal("old gate number not available after all owned joins")
	}
	if f.owned.selected.starter.close() != nil || f.owned.shutdownMinimalControlPreparation() != nil {
		t.Fatal("repeated old owner close")
	}
	var original, retained unix.Stat_t
	contents := make([]byte, len("retained successor canary"))
	n, readErr := successor.ReadAt(contents, 0)
	if unix.Fstat(int(canary.Fd()), &original) != nil || unix.Fstat(fd, &retained) != nil ||
		original.Dev != retained.Dev || original.Ino != retained.Ino || readErr != nil || n != len(contents) ||
		string(contents) != "retained successor canary" {
		t.Fatal("old owner cleanup consumed or altered exact successor")
	}
}

func minimalGateIOCheckQueuedPackets(t *testing.T, fd int, filler []byte, count int) {
	t.Helper()
	fillers, releases := 0, 0
	buffer := make([]byte, l8RuntimeOwnerPacketLimit)
	for seen := 0; seen < count+2; seen++ {
		n, _, flags, _, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || err == nil && n == 0 {
			break
		}
		if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
			t.Fatal("post-join diagnostic receive", err)
		}
		if bytes.Equal(buffer[:n], filler) {
			fillers++
			continue
		}
		packet, err := decodeL8RuntimeOwnerPacket(buffer[:n])
		if err != nil || packet.Opcode != l8RuntimeOwnerOpcodeChildRelease {
			t.Fatal("unexpected non-filler packet", err)
		}
		releases++
	}
	if fillers != count || releases != 0 {
		t.Errorf("queued filler=%d want %d, actual ChildRelease=%d want 0", fillers, count, releases)
	}
}
