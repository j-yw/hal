//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// Exercise the original selected owner after an actual accept-service error.
// No production source, close callback, or descriptor observation is replaced.
func TestMinimalSupervisorWorkConcurrentFinalDisposalAfterScopeExit(t *testing.T) {
	withMinimalSupervisorJointFixture(t, func(f *minimalSupervisorJointFixture) {
		_, _, _, rescueGuest := f.guest(t, nil)
		defer rescueGuest()
		client, _ := minimalSupervisorWorkClient(t, f)
		if _, err := client.Exec(context.Background(), minimalJointExecRequest()); err != nil {
			t.Fatal("actual original work prerequisite", err)
		}
		fd, session := f.cleanup(t)
		connection := os.NewFile(uintptr(fd), "original-cleanup-client")
		defer connection.Close()
		minimalSupervisorJointInspect(t, fd, session)
		if err := connection.Close(); err != nil {
			t.Fatal("close original authenticated client", err)
		}
		f.producer.close()
		minimalSupervisorWorkJoined(t, f)
		if err := unix.Shutdown(f.owned.listenerFD, unix.SHUT_RDWR); err != nil {
			t.Fatal("actual original listener shutdown", err)
		}
		minimalJointAwait(t, f.done, "original accept service exited")
		minimalJointAwait(t, f.serving(t).scopeDone, "whole selected scope joined")
		t.Log("reached actual work, authenticated Inspect, I/O/lifecycle joins and actual scope exit")
		start := make(chan struct{})
		var done sync.WaitGroup
		for index := 0; index < 16; index++ {
			done.Add(1)
			go func() {
				defer done.Done()
				<-start
				f.owned.close()
			}()
		}
		close(start)
		done.Wait()
		if f.owned.listenerFD != -1 {
			t.Fatal("original final listener ownership was not retired")
		}
	})
}
