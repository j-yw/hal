//go:build linux

package firecrackerhost

import (
	"os"

	"golang.org/x/sys/unix"
)

// Constructor-only handoff. Copy the admission-owned snapshot, never decoded
// config fields that the callback may have changed. No handle is transferred.
func bindMinimalControlNamespaces(owned *l8RuntimeOwnerLinuxRuntime, admission *minimalControlSupervisorAdmission) error {
	if owned == nil || admission == nil {
		return errL8RuntimeOwnerInvalid
	}
	owned.mu.Lock()
	defer owned.mu.Unlock()
	projection := admission.namespace
	if owned.minimalNamespaces != nil || owned.namespaces != ([2]*os.File{}) ||
		!projection.valid() || !owned.minimalNamespaceRecordMatches(projection) {
		return errL8RuntimeOwnerInvalid
	}
	binding, err := owned.store.selected.recordBinding()
	if err != nil || binding != jailerRecoveryRecordBinding(admission.recovery) {
		return errL8RuntimeOwnerInvalid
	}
	owned.minimalNamespaces = &projection
	return nil
}

// This is a pure comparison with the independently admitted record identity,
// not store I/O, namespace issuance or proof of current resource ownership.
func (owned *l8RuntimeOwnerLinuxRuntime) minimalNamespaceRecordMatches(projection minimalControlNamespaceProjection) bool {
	if owned.store == nil || owned.store.selected == nil || owned.store.selected.minimal == nil ||
		owned.store.selected.config.Version != minimalControlSupervisorConfigVersion {
		return false
	}
	binding, err := owned.store.selected.recordBinding()
	j := jailerRecoveryJob{SandboxID: owned.genesis.SandboxID, ExecutionID: owned.genesis.ExecutionID,
		WorkerID: owned.genesis.WorkerID, HostID: owned.genesis.HostID, RuntimeID: owned.genesis.RuntimeID, RuntimeGeneration: owned.genesis.RuntimeGeneration}
	return err == nil && binding.configCorrelation == projection.configCorrelation &&
		owned.genesis.SeedCorrelationDigest == projection.configCorrelation && binding.job == j
}

// The generic receiver has already checked actual nsfs device/inode identity.
// This additional selected check runs before received-FD ownership or the FSM.
// Missing selected pins cannot silently become the unchanged legacy branch.
func (owned *l8RuntimeOwnerLinuxRuntime) validateMinimalControlNamespaces(files []*os.File, correlation l8RuntimeOwnerNamespaceCorrelationV1) error {
	selected := owned.minimalNamespaces != nil
	if owned.store != nil && owned.store.selected != nil {
		selected = selected || owned.store.selected.minimal != nil || owned.store.selected.config.Version == minimalControlSupervisorConfigVersion
	}
	if owned.selected != nil {
		selected = selected || owned.selected.config.Version == minimalControlSupervisorConfigVersion
	}
	if !selected {
		return nil
	}
	projection := owned.minimalNamespaces
	if projection == nil || !projection.valid() || !owned.minimalNamespaceRecordMatches(*projection) ||
		minimalControlNamespaces(correlation) != projection.namespaces || len(files) != 2 || files[0] == nil || files[1] == nil {
		return errL8RuntimeOwnerInvalid
	}
	for i, expected := range []int{unix.CLONE_NEWUSER, unix.CLONE_NEWNET} {
		kind, err := unix.IoctlRetInt(int(files[i].Fd()), unix.NS_GET_NSTYPE)
		if err != nil || kind != expected {
			return errL8RuntimeOwnerInvalid
		}
	}
	return nil
}
