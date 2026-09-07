//go:build linux

package firecrackerhost

import (
	"encoding/hex"
	"os"

	"golang.org/x/sys/unix"
)

// Captured from the successful start while selected.mu is held, not rebuilt
// from the later record. Invalid/incomplete captures reject Release so the
// existing started-child Abort still owns every allocated resource.
type minimalControlReleaseSnapshot struct {
	selected      *jailerRecoveryRuntime
	prep          *minimalControlPreparation
	coordinator   *strictJailerCoordinator
	lifecycle     *strictJailerLifecycle
	manager       *ProcessLifecycleManager
	starter       *jailerRecoveryStarter
	gate          *os.File
	store         *l8RuntimeOwnerLinuxRecordStore
	storeOwner    *jailerRecoveryStore
	session       strictJailerSession
	generation    *strictJailerCoordinatorGeneration
	process       strictJailerLifecycleProcess
	identity      *strictJailerIdentityLease
	busy          jailerIdentityRecord
	staging       jailerStagingResult
	cgroup        *strictJailerCgroupLease
	cgroupRequest strictJailerCgroupRequest
	observation   l8RuntimeOwnerProcessObservation
	expectation   minimalControlConfigExpectation
	binding       jailerRecoveryRecordBinding
	record        firecrackerRuntimeOwnerRecordV1
}

func (selected *jailerRecoveryRuntime) captureMinimalRelease(prep *minimalControlPreparation) minimalControlReleaseSnapshot {
	s := minimalControlReleaseSnapshot{selected: selected, prep: prep, coordinator: selected.coordinator,
		lifecycle: selected.lifecycle, starter: selected.starter, store: selected.store, session: selected.session}
	if selected.minimalControl != nil {
		s.expectation = *selected.minimalControl
	}
	if s.lifecycle != nil {
		s.manager = s.lifecycle.manager
	}
	if s.store != nil {
		s.storeOwner = s.store.selected
	}
	s.binding = jailerRecoveryRecordBinding{configCorrelation: hex.EncodeToString(prep.correlation[:]),
		job: selected.config.Job, uid: selected.config.Policy.UID, gid: selected.config.Policy.GID,
		firecrackerConfigSHA256: selected.config.Config.SHA256}
	s.coordinator.mu.Lock()
	s.generation = s.coordinator.generation
	if g := s.generation; g != nil {
		s.process, s.identity, s.staging, s.cgroup = g.process, g.identity, g.staging, g.cgroup
	}
	s.coordinator.mu.Unlock()
	if s.identity != nil {
		s.identity.mu.Lock()
		s.busy = s.identity.busy
		s.identity.mu.Unlock()
	}
	if s.cgroup != nil {
		s.cgroup.mu.Lock()
		s.cgroupRequest = s.cgroup.request
		s.cgroup.mu.Unlock()
	}
	s.starter.mu.Lock()
	s.observation = s.starter.observation
	s.gate = s.starter.gate
	s.starter.mu.Unlock()
	if prep.owner != nil {
		s.record = prep.owner.genesis
		s.record.Revision, s.record.State, s.record.ControllerState = 1, "starting", "none"
		s.record.FirecrackerPID, s.record.FirecrackerStartTime = s.observation.PID, s.observation.StartTime
	}
	return s
}

// No selected-runtime/coordinator/store bookkeeping lock is held over manager
// or kernel observation. The existing supervisor FSM still holds owner.mu
// across Release; this helper does not change that outer locking contract.
// This is retained-resource currentness only; atomic release admission and
// interruptible gate I/O are separate, still-required boundaries.
func (s minimalControlReleaseSnapshot) current() error {
	if !s.sameOwner() || s.currentRecord() != nil || s.identity.verify(s.prep.preparationCtx) != nil ||
		s.staging.verifyOwnedRoot() != nil || s.cgroup.verifyLaunched(s.prep, s.cgroupRequest) != nil {
		return errL8RuntimeOwnerInvalid
	}
	process, err := s.currentProcess()
	if err != nil || s.currentArmedProcess() != nil {
		return errL8RuntimeOwnerInvalid
	}
	after, err := s.currentProcess()
	if err != nil || process.pid != after.pid || process.done != after.done || process.handle != after.handle ||
		!cleanupPathPlansEqual(process.paths, after.paths) || !s.sameOwner() || s.currentRecord() != nil || !s.prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (s minimalControlReleaseSnapshot) sameOwner() bool {
	if s.selected == nil || s.prep == nil || !s.prep.current() || s.coordinator == nil || s.lifecycle == nil || s.manager == nil || s.gate == nil ||
		s.starter == nil || s.store == nil || s.storeOwner == nil || s.generation == nil || s.identity == nil || s.staging.lease == nil || s.cgroup == nil {
		return false
	}
	s.selected.mu.Lock()
	defer s.selected.mu.Unlock()
	s.coordinator.mu.Lock()
	defer s.coordinator.mu.Unlock()
	selected, g := s.selected, s.generation
	return s.prep.current() && selected.minimalPreparation == s.prep && s.prep.owner != nil && s.prep.owner.selected == selected &&
		s.prep.owner.store == s.store && selected.config.Version == minimalControlSupervisorConfigVersion &&
		jailerRecoveryConfigDigest(selected.config) == s.prep.configDigest && selected.minimalControl != nil && *selected.minimalControl == s.expectation &&
		s.expectation.configCorrelation == s.prep.correlation && s.expectation.job == s.binding.job && s.expectation.configSHA256 == s.binding.firecrackerConfigSHA256 &&
		selected.attempted && !selected.terminal && selected.coordinator == s.coordinator && selected.lifecycle == s.lifecycle && s.lifecycle.manager == s.manager &&
		selected.starter == s.starter && selected.store == s.store && s.store.selected == s.storeOwner && selected.session == s.session &&
		s.session.coordinator == s.coordinator && s.session.generation != 0 && s.session.generation == g.id &&
		s.coordinator.generation == g && s.coordinator.deps.lifecycle == s.lifecycle && g.state == strictJailerCoordinatorActive &&
		g.hasProcess && !g.unresolvedStaging && g.process == s.process && g.identity == s.identity && g.staging.lease == s.staging.lease && g.cgroup == s.cgroup
}

func (s minimalControlReleaseSnapshot) currentRecord() error {
	_, _, err := s.store.withLock(s.prep.preparationCtx, unix.LOCK_EX, func() (firecrackerRuntimeOwnerRecordV1, bool, error) {
		selected := s.store.selected
		if !s.prep.current() || selected != s.storeOwner || selected.minimal == nil || selected.terminal || selected.poisoned || selected.retired {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		binding, err := selected.recordBinding()
		if err != nil || binding != s.binding || !s.binding.valid() || s.record.SeedCorrelationDigest != s.binding.configCorrelation {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		record, exists, err := s.store.readRecord()
		if err != nil || !exists || record != s.record || selected.reservation != s.identity {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		s.identity.mu.Lock()
		defer s.identity.mu.Unlock()
		busy := s.identity.busy
		if !s.prep.current() || !s.identity.launched || busy != s.busy || busy.State != "busy" || busy.RuntimeID != s.binding.job.RuntimeID ||
			busy.Config != s.binding.firecrackerConfigSHA256 || busy.UID != s.binding.uid || busy.GID != s.binding.gid ||
			s.cgroupRequest.runtimeID != busy.RuntimeID || s.cgroupRequest.configSHA256 != busy.Config ||
			!equalJailerRecoveryBusy(selected.busy, &busy) || s.identity.verifyLocked(s.prep.preparationCtx) != nil || !s.prep.current() {
			return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
		}
		return record, true, nil
	})
	return err
}

func (s minimalControlReleaseSnapshot) currentProcess() (liveProcessIdentity, error) {
	if !s.prep.current() || !s.lifecycle.validProcess(s.process) {
		return liveProcessIdentity{}, errL8RuntimeOwnerInvalid
	}
	process, err := s.manager.resolveLiveProcessIdentity(s.process.handle)
	if err != nil || process.pid <= 1 || uint32(process.pid) != s.observation.PID || process.done == nil || process.handle != s.process.handle ||
		!cleanupPathPlansEqual(process.paths, s.process.hostPaths) || s.process.runtimeUID != s.binding.uid || !s.prep.current() {
		return liveProcessIdentity{}, errL8RuntimeOwnerInvalid
	}
	return process, nil
}

func (s minimalControlReleaseSnapshot) currentArmedProcess() (resultErr error) {
	// Close cannot recycle the retained descriptor while the owned duplicate is
	// being obtained. No borrowed raw descriptor escapes this locked section.
	s.starter.mu.Lock()
	if !s.prep.current() || !s.starter.started || s.starter.closed || s.starter.released || s.starter.gate != s.gate ||
		!s.observation.pidfdOwned || s.starter.observation != s.observation || s.observation.ParentPID != s.record.SupervisorPID {
		s.starter.mu.Unlock()
		return errL8RuntimeOwnerInvalid
	}
	flags, flagErr := unix.FcntlInt(uintptr(s.observation.pidfd), unix.F_GETFD, 0)
	fd, err := -1, flagErr
	if flagErr == nil && flags&unix.FD_CLOEXEC != 0 {
		fd, err = unix.FcntlInt(uintptr(s.observation.pidfd), unix.F_DUPFD_CLOEXEC, 10)
	}
	s.starter.mu.Unlock()
	if err != nil || fd < 0 {
		return errL8RuntimeOwnerInvalid
	}
	defer func() {
		if unix.Close(fd) != nil {
			resultErr = errL8RuntimeOwnerInvalid
		}
	}()
	if !s.prep.current() || !l8RuntimeOwnerProcessAlive(fd) {
		return errL8RuntimeOwnerInvalid
	}
	actual, err := inspectL8RuntimeOwnerProcess(s.observation.PID)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	defer func() {
		if actual.Close() != nil {
			resultErr = errL8RuntimeOwnerInvalid
		}
	}()
	if actual.PID != s.observation.PID || actual.StartTime != s.observation.StartTime || actual.ParentPID != s.observation.ParentPID ||
		!l8RuntimeOwnerProcessAlive(fd) || !s.prep.current() {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

// The prelaunch predicate deliberately rejects launched leases. Release must
// instead inspect the same already-launched finite cgroup without migrating,
// resetting its launch bit, or inferring terminal emptiness.
func (lease *strictJailerCgroupLease) verifyLaunched(prep *minimalControlPreparation, request strictJailerCgroupRequest) error {
	if lease == nil {
		return errJailerCgroup
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if !prep.current() || !lease.prepared || !lease.launched || lease.quiesced || lease.released ||
		lease.request != request || lease.verifyLimitsLocked() != nil || !prep.current() {
		return errJailerCgroup
	}
	return nil
}
