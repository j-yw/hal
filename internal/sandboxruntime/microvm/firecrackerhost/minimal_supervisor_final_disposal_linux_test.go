//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMinimalSupervisorWorkFinalDisposerJoinsAndPreservesSuccessors(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		_, _, guestDone, rescueGuest := f.guest(t, nil)
		defer rescueGuest()
		client, _ := minimalSupervisorWorkClient(t, f)
		if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err != nil {
			t.Fatal("actual original work prerequisite", err)
		}
		fd, session := f.cleanup(t)
		connection := os.NewFile(uintptr(fd), "original-cleanup-client")
		defer connection.Close()
		minimalSupervisorJointInspect(t, fd, session)
		if connection.Close() != nil {
			t.Fatal("close authenticated client")
		}
		f.producer.close()
		minimalSupervisorWorkJoined(t, f)
		minimalJointAwait(t, guestDone, "original guest joined before final disposal")
		listenerFD := f.owned.listenerFD
		if unix.Shutdown(listenerFD, unix.SHUT_RDWR) != nil {
			t.Fatal("actual original listener shutdown")
		}
		minimalJointAwait(t, f.done, "actual accept scope returned")
		minimalJointAwait(t, f.serving(t).scopeDone, "original final scope joins")
		starter := f.owned.selected.starter
		starter.mu.Lock()
		locked := true
		first, second := make(chan struct{}), make(chan struct{})
		defer func() {
			if locked {
				starter.mu.Unlock()
			}
			minimalJointAwait(t, first, "explicit first disposer rescue")
			minimalJointAwait(t, second, "explicit second disposer rescue")
		}()
		go func() { defer close(first); f.owned.close() }()
		go func() { defer close(second); f.owned.close() }()
		minimalSupervisorWorkObserve(t, "original final-disposer election", func() bool {
			f.owned.mu.Lock()
			defer f.owned.mu.Unlock()
			return f.owned.minimalDisposalDone != nil
		})
		select {
		case <-first:
			t.Fatal("elected disposer bypassed held original starter")
		case <-second:
			t.Fatal("losing Close returned before the elected disposer joined")
		case <-time.After(25 * time.Millisecond):
		}
		// Acquiring this mutex while the disposer and loser wait proves their
		// waits do not retain original owned bookkeeping authority.
		f.owned.mu.Lock()
		f.owned.mu.Unlock()
		starter.mu.Unlock()
		locked = false
		minimalJointAwait(t, first, "first final disposer joined")
		minimalJointAwait(t, second, "second final disposer joined")
		if f.owned.listenerFD != -1 {
			t.Fatal("original listener not retired")
		}
		pair := minimalWorkTestPair(t, unix.SOCK_STREAM)
		successor, peer := pair[0], pair[1]
		if pair[1] == listenerFD {
			successor, peer = pair[1], pair[0]
		} else if pair[0] != listenerFD {
			duplicate, err := unix.FcntlInt(uintptr(pair[0]), unix.F_DUPFD_CLOEXEC, listenerFD)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.Close(duplicate) })
			if duplicate != listenerFD {
				t.Fatal("exact retired listener number was not free for the test-owned successor")
			}
			successor = duplicate
		}
		path := "/proc/self/fd/" + strconv.Itoa(f.owned.store.directoryFD) + "/" + f.owned.listenerKey
		replacement, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			t.Fatal("original listener entry not retired", err)
		}
		defer replacement.Close()
		f.owned.close()
		f.owned.close()
		var identity, retained unix.Stat_t
		if unix.Fstat(int(replacement.Fd()), &identity) != nil || unix.Fstatat(f.owned.store.directoryFD, f.owned.listenerKey, &retained, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			identity.Dev != retained.Dev || identity.Ino != retained.Ino {
			t.Fatal("spent final disposer removed the successor listener entry")
		}
		if n, err := unix.Write(successor, []byte{19}); n != 1 || err != nil {
			t.Fatal("spent final disposer closed or shut down the exact successor descriptor", err)
		}
		var observed [1]byte
		if n, err := unix.Read(peer, observed[:]); n != 1 || err != nil || observed[0] != 19 {
			t.Fatal("successor descriptor peer was not usable", err)
		}
	})
}
