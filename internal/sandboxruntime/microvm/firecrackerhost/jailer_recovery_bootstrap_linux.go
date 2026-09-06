//go:build linux

package firecrackerhost

import "context"

func (owned *l8RuntimeOwnerLinuxRuntime) quarantineJailerBootstrap() error {
	if owned == nil || owned.selected == nil || owned.store == nil || owned.store.selected == nil {
		return errL8RuntimeOwnerInvalid
	}
	selected := owned.selected
	selected.mu.Lock()
	defer selected.mu.Unlock()
	if !selected.attempted || selected.coordinator == nil {
		return errL8RuntimeOwnerInvalid
	}
	selected.coordinator.mu.Lock()
	retained := selected.coordinator.generation != nil
	selected.coordinator.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), l8RuntimeOwnerHandshakeTimeout)
	defer cancel()
	if !retained && !selected.terminal && selected.finishTerminalCleanup(ctx) != nil {
		return errL8RuntimeOwnerInvalid
	}
	record, err := owned.store.Load(ctx)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	if record.State != "starting" {
		return nil
	}
	if record.ControllerState != "none" || record.Revision > 1 || record.Revision == ^uint64(0) {
		return errL8RuntimeOwnerInvalid
	}
	next := record
	next.Revision++
	next.State = "uncertain"
	next.ControllerState = "unclaimed"
	_, err = owned.store.Transition(ctx, record.Revision, next)
	return err
}

func validJailerRecoveryTransition(from, to firecrackerRuntimeOwnerRecordV1) bool {
	if from.ContractVersion != jailerRecoveryRecordVersion || to.ContractVersion != jailerRecoveryRecordVersion || from.Revision == ^uint64(0) || to.Revision != from.Revision+1 {
		return false
	}
	immutable := to
	immutable.Revision = from.Revision
	immutable.State = from.State
	immutable.ControllerState = from.ControllerState
	immutable.AbsenceKind = from.AbsenceKind
	immutable.AbsenceRevision = from.AbsenceRevision
	immutable.AbsenceObservedAtUnixNano = from.AbsenceObservedAtUnixNano
	immutable.FinalizeTargetRevision = from.FinalizeTargetRevision
	immutable.FinalizedCommitID = from.FinalizedCommitID
	immutable.ReconnectSecret = from.ReconnectSecret
	immutable.FirecrackerPID = from.FirecrackerPID
	immutable.FirecrackerStartTime = from.FirecrackerStartTime
	if immutable != from {
		return false
	}
	if from.State == "starting" && from.ControllerState == "none" && from.Revision <= 1 && to.State == "uncertain" && to.ControllerState == "unclaimed" {
		return to.FirecrackerPID == from.FirecrackerPID && to.FirecrackerStartTime == from.FirecrackerStartTime && to.ReconnectSecret == from.ReconnectSecret
	}
	if !(from.State == "starting" && from.Revision == 0) && (to.FirecrackerPID != from.FirecrackerPID || to.FirecrackerStartTime != from.FirecrackerStartTime) {
		return false
	}
	return validL8RuntimeOwnerTransition(from, to)
}
