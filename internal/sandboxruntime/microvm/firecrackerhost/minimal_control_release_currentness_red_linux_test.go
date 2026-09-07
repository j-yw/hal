//go:build linux

package firecrackerhost

import (
	"context"
	"testing"
	"time"
)

// The first GREEN rejects observed preparation loss, not resource drift. Both
// cases below keep original P/channel live and use the unchanged tracked
// fixture. They reach actual revision 1 before changing only owned test state.
func TestMinimalReleaseResourceCurrentnessBeforeGateSend(t *testing.T) {
	for _, changed := range []string{"tracked_process_done", "finite_cgroup_limit"} {
		t.Run(changed, func(t *testing.T) {
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
					t.Fatal("actual resource-currentness boundary not reached")
				}
				minimalReleaseRequireRevisionOne(t, f, starter)
				selected := f.owned.selected
				switch changed {
				case "tracked_process_done":
					// Close only the fake HostProcess channel. No signal reaches
					// the actual self PID retained for read-only observation.
					starter.process.mu.Lock()
					starter.process.closeLocked()
					starter.process.mu.Unlock()
					if _, err := selected.lifecycle.manager.resolveLiveProcessIdentity(selected.coordinator.generation.process.handle); err == nil {
						t.Fatal("real manager did not observe its tracked fake process exit")
					}
				case "finite_cgroup_limit":
					lease := starter.cgroup
					fs, ok := lease.fs.(*fakeJailerCgroupFilesystem)
					if !ok {
						t.Fatal("resource fixture attempted a non-fake cgroup mutation")
					}
					lease.mu.Lock()
					original := fs.values["memory.max"]
					fs.values["memory.max"] = "1073741824\n" // Finite and page-aligned, but not admitted 512 MiB.
					mismatch := lease.verifyLimitsLocked()
					lease.mu.Unlock()
					defer func() {
						lease.mu.Lock()
						fs.values["memory.max"] = original
						lease.mu.Unlock()
					}()
					if original == "1073741824\n" || mismatch == nil {
						t.Fatal("existing exact limit readback did not detect fixture drift")
					}
				}
				if !f.owned.minimalPreparation.current() || selected.starter.released || selected.terminal {
					t.Fatal("resource mutation changed preparation or claimed terminal/release authority")
				}
				unblock()
				err := minimalPreparationJoin(t, done)
				joined = true
				if err == nil {
					t.Error("changed retained resource still completed selected bootstrap")
				}
				packet, receiveErr := minimalReleaseReceive(t, f.gatePeer)
				if receiveErr == nil && packet.Packet.Opcode == l8RuntimeOwnerOpcodeChildRelease {
					t.Error("changed retained resource still received actual ChildRelease")
				}
				if selected.starter.released {
					t.Error("changed retained resource consumed successful release")
				}
				record, loadErr := f.owned.store.Load(context.Background())
				if loadErr != nil || record.Revision != 1 || record.State != "starting" || record.ControllerState != "none" {
					t.Error("changed retained resource advanced the actual revision-1 record")
				}
			})
		})
	}
}
