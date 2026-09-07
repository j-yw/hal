//go:build linux

package firecrackerhost

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These observations intentionally agree with their fake genesis/revision-1
// metadata but disagree with /proc. Only the actual read-only kernel check can
// detect them. The self pidfd is never used to signal or kill the test process.
func TestMinimalReleaseRejectsArmedMetadataNotMatchingKernel(t *testing.T) {
	for _, field := range []string{"start", "parent"} {
		t.Run(field, func(t *testing.T) {
			withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
				starter := minimalReleaseUseTrackedFixture(t, f)
				if field == "start" {
					f.owned.selected.starter.observation.StartTime++
				} else {
					f.owned.selected.starter.observation.ParentPID++
					f.owned.genesis.SupervisorPID = f.owned.selected.starter.observation.ParentPID
					f.owner.opts.GenesisRecord = f.owned.genesis
				}
				entered, unblock := minimalReleasePauseAtRevisionOne(f)
				done, joined := f.start(t), false
				defer func() {
					unblock()
					if !joined {
						_ = minimalPreparationJoin(t, done)
					}
				}()
				select {
				case <-entered:
				case <-time.After(3 * time.Second):
					t.Fatal("actual revision-1 boundary not reached")
				}
				minimalReleaseRequireRevisionOne(t, f, starter)
				s := f.owned.selected
				s.mu.Lock()
				snapshot := s.captureMinimalRelease(s.minimalPreparation)
				s.mu.Unlock()
				if !snapshot.sameOwner() || snapshot.currentRecord() != nil {
					t.Fatal("metadata mismatch failed before independently observed kernel boundary")
				}
				if _, err := snapshot.currentProcess(); err != nil {
					t.Fatal("real manager prerequisite", err)
				}
				before, err := os.ReadDir("/proc/self/fd")
				if err != nil {
					t.Fatal("descriptor-count prerequisite", err)
				}
				for range 20 {
					if snapshot.currentArmedProcess() == nil {
						t.Fatal("accepted forged armed metadata")
					}
				}
				after, err := os.ReadDir("/proc/self/fd")
				if err != nil || len(before) != len(after) {
					t.Fatal("failed observation leaked temporary descriptors", len(before), len(after), err)
				}
				unblock()
				if err := minimalPreparationJoin(t, done); err == nil {
					t.Fatal("kernel mismatch completed bootstrap")
				}
				joined = true
				if s.starter.released {
					t.Fatal("kernel mismatch consumed gate release")
				}
				packet, receiveErr := minimalReleaseReceive(t, f.gatePeer)
				if receiveErr == nil && packet.Packet.Opcode == l8RuntimeOwnerOpcodeChildRelease {
					t.Fatal("kernel mismatch sent actual ChildRelease")
				}
			})
		})
	}
}

func TestMinimalReleaseArmedObservationKeepsOriginalDescriptor(t *testing.T) {
	withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
		starter := minimalReleaseUseTrackedFixture(t, f)
		entered, unblock := minimalReleasePauseAtRevisionOne(f)
		done, joined := f.start(t), false
		defer func() {
			unblock()
			if !joined {
				_ = minimalPreparationJoin(t, done)
			}
		}()
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("actual revision-1 boundary not reached")
		}
		minimalReleaseRequireRevisionOne(t, f, starter)
		s := f.owned.selected
		s.mu.Lock()
		snapshot := s.captureMinimalRelease(s.minimalPreparation)
		s.mu.Unlock()
		if snapshot.current() != nil {
			t.Fatal("positive retained snapshot prerequisite")
		}
		before, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for range 20 {
			if snapshot.currentArmedProcess() != nil {
				t.Fatal("positive actual observation")
			}
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(before) != len(after) {
			t.Fatal("successful observation leaked temporary descriptors", len(before), len(after), err)
		}
		flags, err := unix.FcntlInt(uintptr(snapshot.observation.pidfd), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 || !l8RuntimeOwnerProcessAlive(snapshot.observation.pidfd) {
			t.Fatal("observation consumed original pidfd")
		}
		unblock()
		if err := minimalPreparationJoin(t, done); err != nil {
			t.Fatal("positive release", err)
		}
		joined = true
	})
}
