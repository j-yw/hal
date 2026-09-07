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

// Each mutation occurs after actual canonical revision 1. Restore only the
// test's in-memory corruption before the existing Abort runs, so cleanup still
// uses its original owner. No production recovery/repair is added by this table.
func TestMinimalReleaseRetainedMismatchMatrix(t *testing.T) {
	for _, change := range []string{
		"session", "generation", "state", "missing_process", "unresolved_staging", "lifecycle", "manager", "starter",
		"public_projection", "config", "store_projection", "store_reservation", "store_busy", "store_terminal", "record_revision", "record_missing", "record_closed",
		"identity_busy", "identity_closed", "staging_identity", "staging_closed", "cgroup_unlaunched", "cgroup_quiesced", "cgroup_request",
		"process_uid", "process_handle", "process_path", "armed_pid", "armed_start", "armed_parent", "pidfd_cloexec", "gate",
	} {
		t.Run(change, func(t *testing.T) {
			withMinimalPreparationFixture(t, time.Now().Add(time.Minute), func(f *minimalPreparationFixture) {
				starter := minimalReleaseUseTrackedFixture(t, f)
				var restore func()
				// Use the actual selected starter without the fixture's extra
				// order-assertion Load: record faults must reach production
				// currentness, not be intercepted by that test-only read.
				// Inner restoration precedes the supervisor's normal failure Abort.
				start := f.owned.selected.startMinimalControlChild
				f.owner.opts.StartChild = func() (l8RuntimeOwnerStartedChild, error) {
					child, err := start()
					if err != nil {
						return child, err
					}
					release := child.Release
					child.Release = func() error {
						err := release()
						if restore != nil {
							restore()
						}
						return err
					}
					return child, nil
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
				if err := snapshot.current(); err != nil {
					t.Fatal("unmutated retained currentness prerequisite", err)
				}
				restore = minimalReleaseCorruptRetainedFixture(t, f, change)
				if !s.minimalPreparation.current() {
					t.Fatal("mutation canceled original preparation")
				}
				unblock()
				err := minimalPreparationJoin(t, done)
				joined = true
				if err == nil || s.starter.released {
					t.Fatal("retained mismatch admitted release")
				}
				var byteBuffer [1]byte
				n, _, _, _, recvErr := unix.Recvmsg(f.gatePeer, byteBuffer[:], nil, unix.MSG_DONTWAIT)
				if n > 0 || recvErr != nil && !errors.Is(recvErr, unix.EAGAIN) {
					t.Fatal("unexpected gate packet/error", n, recvErr)
				}
				// A deliberately inconsistent cached record poisons canonical
				// readback. It must not be repaired or silently become terminal.
				if change == "record_revision" || change == "store_busy" || change == "record_missing" || change == "record_closed" {
					if !f.owned.store.selected.poisoned || s.terminal {
						t.Fatal("uncertain record was repaired or promoted")
					}
				} else {
					record, loadErr := f.owned.store.Load(context.Background())
					if loadErr != nil || record.Revision != 1 || record.State != "starting" || record.ControllerState != "none" {
						t.Fatal("mismatch advanced revision-1 state", loadErr)
					}
				}
			})
		})
	}
}

func minimalReleaseCorruptRetainedFixture(t *testing.T, f *minimalPreparationFixture, change string) func() {
	t.Helper()
	s := f.owned.selected
	g := s.coordinator.generation
	switch change {
	case "session":
		old := s.session
		s.session.generation++
		return func() { s.session = old }
	case "generation":
		old := g.id
		g.id++
		return func() { g.id = old }
	case "state":
		old := g.state
		g.state = strictJailerCoordinatorStopCleanupPending
		return func() { g.state = old }
	case "missing_process":
		g.hasProcess = false
		return func() { g.hasProcess = true }
	case "unresolved_staging":
		g.unresolvedStaging = true
		return func() { g.unresolvedStaging = false }
	case "lifecycle":
		old := s.lifecycle
		s.lifecycle = nil
		return func() { s.lifecycle = old }
	case "manager":
		old := s.lifecycle.manager
		s.lifecycle.manager = nil
		return func() { s.lifecycle.manager = old }
	case "starter":
		old := s.starter
		s.starter = &jailerRecoveryStarter{}
		return func() { s.starter = old }
	case "public_projection":
		old := *s.minimalControl
		s.minimalControl.configCorrelation[0] ^= 1
		return func() { *s.minimalControl = old }
	case "config":
		old := s.config.Job
		s.config.Job.RuntimeGeneration += "-changed"
		return func() { s.config.Job = old }
	case "store_projection":
		old := *s.store.selected.minimal
		s.store.selected.minimal.configCorrelation = l8RuntimeOwnerTestToken(19)
		return func() { *s.store.selected.minimal = old }
	case "store_reservation":
		old := s.store.selected.reservation
		s.store.selected.reservation = nil
		return func() { s.store.selected.reservation = old }
	case "store_busy":
		old := s.store.selected.busy
		s.store.selected.busy = nil
		return func() { s.store.selected.busy = old }
	case "store_terminal":
		s.store.selected.terminal = true
		return func() { s.store.selected.terminal = false }
	case "record_revision":
		old := s.store.selected.record
		s.store.selected.record.Revision++
		return func() { s.store.selected.record = old }
	case "record_missing":
		fd := s.store.directoryFD
		if unix.Renameat(fd, l8RuntimeOwnerRecordName, fd, "retained-original") != nil {
			t.Fatal("cannot preserve fixture record")
		}
		return func() {
			_ = unix.Renameat2(fd, "retained-original", fd, l8RuntimeOwnerRecordName, unix.RENAME_NOREPLACE)
		}
	case "record_closed":
		if s.store.selected.file.Close() != nil {
			t.Fatal("fixture retained record close")
		}
		return func() {} // Never reconstruct the lost retained handle.
	case "identity_busy":
		old := g.identity.busy
		g.identity.busy.Nonce = l8RuntimeOwnerTestToken(19)
		return func() { g.identity.busy = old }
	case "identity_closed":
		g.identity.closed = true
		return func() { g.identity.closed = false }
	case "staging_identity":
		root, ok := g.staging.lease.root.(*coordinatorFakeRoot)
		if !ok {
			t.Fatal("not fake staging")
		}
		root.verifyErr = errors.New("fixture root identity replaced")
		return func() { root.verifyErr = nil }
	case "staging_closed":
		g.staging.lease.released = true
		return func() { g.staging.lease.released = false }
	case "cgroup_unlaunched":
		g.cgroup.launched = false
		return func() { g.cgroup.launched = true }
	case "cgroup_quiesced":
		g.cgroup.quiesced = true
		return func() { g.cgroup.quiesced = false }
	case "cgroup_request":
		old := g.cgroup.request
		g.cgroup.request.runtimeID += "-changed"
		return func() { g.cgroup.request = old }
	case "process_uid":
		old := g.process
		g.process.runtimeUID++
		return func() { g.process = old }
	case "process_handle":
		old := g.process
		g.process.handle.ID += "-changed"
		return func() { g.process = old }
	case "process_path":
		old := g.process
		g.process.hostPaths.ConfigPath += "-changed"
		return func() { g.process = old }
	case "armed_pid":
		old := s.starter.observation
		s.starter.observation.PID++
		return func() { s.starter.observation = old }
	case "armed_start":
		old := s.starter.observation
		s.starter.observation.StartTime++
		return func() { s.starter.observation = old }
	case "armed_parent":
		old := s.starter.observation
		s.starter.observation.ParentPID++
		return func() { s.starter.observation = old }
	case "pidfd_cloexec":
		fd := uintptr(s.starter.observation.pidfd)
		flags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Fatal("CLOEXEC prerequisite")
		}
		if _, err := unix.FcntlInt(fd, unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		return func() { _, _ = unix.FcntlInt(fd, unix.F_SETFD, flags) }
	case "gate":
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		old := s.starter.gate
		replacement := os.NewFile(uintptr(pair[0]), "replacement-unused-fixture-gate")
		s.starter.gate = replacement
		return func() { s.starter.gate = old; _ = replacement.Close(); _ = unix.Close(pair[1]) }
	}
	t.Fatal("unknown retained mismatch")
	return nil
}
