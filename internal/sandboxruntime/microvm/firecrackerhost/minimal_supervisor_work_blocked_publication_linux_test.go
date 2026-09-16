//go:build linux

package firecrackerhost

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalSupervisorWorkCancellationInterruptsBlockedAncillarySend(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		prep := f.owned.minimalPreparation
		prep.mu.Lock()
		f.producer.mu.Lock()
		prepLocked, producerLocked := true, true
		var rescue func()
		defer func() {
			if prepLocked {
				prep.mu.Unlock()
			}
			if producerLocked {
				f.producer.mu.Unlock()
			}
			if rescue != nil {
				rescue()
			}
		}()
		// The actual sole producer reader rejects this malformed peer packet.
		// Its original retirement mutex is held, so it cannot yet shut down the
		// channel. No replacement reader, event or currentness flag is injected.
		fd := int(prep.original.Fd())
		if n, err := unix.SendmsgN(fd, []byte{0}, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil || n != 1 {
			t.Fatal("bounded malformed peer input", err)
		}
		waitMinimalTemplateMutex(t, "firecrackerhost.(*minimalControlProducerLaunch).retire")
		if f.producer.retired || f.producer.ctx.Err() != nil || f.producer.candidate != nil {
			t.Fatal("original producer did not reach the held retirement boundary")
		}
		if unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 4096) != nil {
			t.Fatal("bounded original send queue")
		}
		queued := 0
		for ; queued < 1024; queued++ {
			n, err := unix.SendmsgN(fd, []byte{0}, nil, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
			if err == unix.EAGAIN {
				break
			}
			if err != nil || n != 1 {
				t.Fatal("bounded queue fill failed", err)
			}
		}
		if queued == 0 || queued == 1024 {
			t.Fatal("actual original socket did not reach bounded backpressure")
		}
		backend, verifier, guestDone, guestRescue := f.guest(t, nil)
		rescue = guestRescue
		serving := f.serving(t)
		var pair *minimalControlWorkServer
		minimalSupervisorWorkObserve(t, "authenticated original pair before blocked publication", func() bool {
			serving.mu.Lock()
			defer serving.mu.Unlock()
			pair = serving.server
			return pair != nil
		})
		prep.mu.Unlock()
		prepLocked = false
		// Observe the real publication call inside the kernel send, not its
		// preparation/pair bookkeeping mutex or a callback pretending to send.
		buffer := make([]byte, 256<<10)
		minimalSupervisorWorkObserve(t, "original publisher blocked in ancillary SendmsgN", func() bool {
			n := runtime.Stack(buffer, true)
			for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
				if strings.Contains(stack, "firecrackerhost.(*minimalControlSupervisorServing).sendWorkEndpoint") &&
					strings.Contains(stack, "unix.SendmsgN") && strings.Contains(stack, "[syscall]") {
					return true
				}
			}
			return false
		})
		window, ok := f.owned.selected.starter.minimalGate.releaseWindow()
		bound := earlierMinimalControlTime(prep.deadline, earlierMinimalControlTime(window.deadline, pair.ready.admissionDeadline))
		if !ok || !time.Now().Before(bound) || !prep.current() || !pair.ready.Current() ||
			backend.calls.Load() != 0 || verifier.calls.Load() != 1 || prep.canceled.workPublished() {
			t.Fatal("blocked send did not retain original current admission and zero backend")
		}
		originalP, originalH := prep.deadline, pair.ready.hardExpiry
		t.Log("actual original publisher reached kernel-blocked ancillary send with queue full, original admission current and backend zero")
		prep.revoke()
		// Keep the producer retirement mutex held: its deferred shutdown cannot
		// interrupt the send. The original supervisor's cancellation paths must
		// interrupt and join it, including the publication's own watcher.
		minimalJointAwait(t, serving.publicationDone, "canceled ancillary send and publication watcher joined")
		minimalJointAwait(t, serving.controllerDone, "original controller/key scope joined after blocked send")
		minimalJointAwait(t, prep.ioDone, "original preparation I/O watcher joined")
		minimalJointAwait(t, guestDone, "original guest joined after blocked send")
		if !time.Now().Before(bound) || prep.canceled.workPublished() || backend.calls.Load() != 0 || verifier.calls.Load() != 1 ||
			f.producer.retired || f.producer.ctx.Err() != nil || f.producer.candidate != nil {
			t.Fatal("cancellation did not interrupt publication before its unchanged deadline")
		}
		select {
		case <-pair.commit:
			t.Fatal("failed ancillary publication committed work")
		default:
		}
		f.producer.mu.Unlock()
		producerLocked = false
		minimalSupervisorWorkJoined(t, f)
		retained, ok := f.owned.selected.starter.minimalGate.releaseWindow()
		if !ok || retained != window || prep.deadline != originalP || pair.ready.hardExpiry != originalH || serving.publishWork(pair.ready) == nil {
			t.Fatal("failed blocked publication retried or rebased original R/D/P/H")
		}
		cleanupFD, session := f.cleanup(t)
		defer unix.Close(cleanupFD)
		minimalSupervisorJointInspect(t, cleanupFD, session)
	})
}
