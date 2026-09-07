package firecrackerhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// The existing FSM uses its historical in-memory record shape; the selected
// disk schema deliberately contains only common owner/process state, measured
// configuration correlation, and actual reservation/checkpoint information.
// No legacy seed, helper, credential, vsock, proxy or network identity is encoded.
type jailerRecoveryDiskRecord struct {
	Version           string                `json:"version"`
	ConfigCorrelation string                `json:"configCorrelation"`
	Job               jailerRecoveryJob     `json:"job"`
	Owner             json.RawMessage       `json:"owner"`
	Reservation       *jailerIdentityRecord `json:"reservation"`
	CleanupCheckpoint bool                  `json:"cleanupCheckpoint"`
}

var jailerRecoveryOwnerFields = []string{
	"revision", "state", "controllerState", "absenceKind", "absenceRevision", "absenceObservedAtUnixNano", "finalizeTargetRevision",
	"hostBootId", "supervisorGeneration", "supervisorPid", "supervisorStartTime", "firecrackerPid", "firecrackerStartTime", "finalizedCommitId", "reconnectListenerIdentity", "reconnectSecret",
}

// Immutable scalar inputs to the common codec, not a launch/cleanup proof.
// Seven-role wrappers derive them only after their existing exact validation;
// eight-role stores consume the distinct admission-issued projection instead.
type jailerRecoveryRecordBinding struct {
	configCorrelation       string
	job                     jailerRecoveryJob
	uid, gid                uint32
	firecrackerConfigSHA256 string
}

func jailerRecoveryBinding(config jailerRecoverySupervisorConfig) (jailerRecoveryRecordBinding, error) {
	if validateJailerRecoverySupervisorConfig(config) != nil {
		return jailerRecoveryRecordBinding{}, errL8RuntimeOwnerInvalid
	}
	return jailerRecoveryRecordBinding{configCorrelation: jailerRecoveryConfigDigest(config), job: config.Job,
		uid: config.Policy.UID, gid: config.Policy.GID, firecrackerConfigSHA256: config.Config.SHA256}, nil
}

func (binding jailerRecoveryRecordBinding) valid() bool {
	if !validJailerStagingDigest(binding.configCorrelation) || !validJailerStagingDigest(binding.firecrackerConfigSHA256) ||
		binding.uid == 0 || binding.gid == 0 || !validStrictJailerRuntimeID(binding.job.RuntimeID) {
		return false
	}
	j := binding.job
	for _, id := range []string{j.SandboxID, j.ExecutionID, j.WorkerID, j.HostID, j.RuntimeID, j.RuntimeGeneration} {
		if !validL8RuntimeOwnerSafeID(id) {
			return false
		}
	}
	return true
}

func encodeJailerRecoveryRecord(record firecrackerRuntimeOwnerRecordV1, config jailerRecoverySupervisorConfig, reservation *jailerIdentityRecord, terminal bool) ([]byte, error) {
	binding, err := jailerRecoveryBinding(config)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	return encodeJailerRecoveryBoundRecord(record, binding, reservation, terminal)
}

func encodeJailerRecoveryBoundRecord(record firecrackerRuntimeOwnerRecordV1, binding jailerRecoveryRecordBinding, reservation *jailerIdentityRecord, terminal bool) ([]byte, error) {
	if !binding.valid() {
		return nil, errL8RuntimeOwnerInvalid
	}
	encoded, _ := json.Marshal(record)
	var all map[string]json.RawMessage
	if json.Unmarshal(encoded, &all) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	common := make(map[string]json.RawMessage, len(jailerRecoveryOwnerFields))
	for _, name := range jailerRecoveryOwnerFields {
		common[name] = all[name]
	}
	owner, _ := json.Marshal(common)
	disk := jailerRecoveryDiskRecord{Version: jailerRecoveryRecordVersion, ConfigCorrelation: binding.configCorrelation, Job: binding.job, Owner: owner, Reservation: reservation, CleanupCheckpoint: terminal}
	restored, err := jailerRecoveryRecordFromBinding(disk, binding)
	if err != nil || restored != record {
		return nil, errL8RuntimeOwnerInvalid
	}
	payload, err := json.Marshal(disk)
	if err != nil || len(payload) > l8RuntimeOwnerRecordLimit {
		return nil, errL8RuntimeOwnerInvalid
	}
	return payload, nil
}

func decodeJailerRecoveryRecord(payload []byte, config jailerRecoverySupervisorConfig) (firecrackerRuntimeOwnerRecordV1, *jailerIdentityRecord, bool, error) {
	binding, err := jailerRecoveryBinding(config)
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, nil, false, errL8RuntimeOwnerInvalid
	}
	return decodeJailerRecoveryBoundRecord(payload, binding)
}

func decodeJailerRecoveryBoundRecord(payload []byte, binding jailerRecoveryRecordBinding) (firecrackerRuntimeOwnerRecordV1, *jailerIdentityRecord, bool, error) {
	var disk jailerRecoveryDiskRecord
	if !binding.valid() || len(payload) == 0 || len(payload) > l8RuntimeOwnerRecordLimit || json.Unmarshal(payload, &disk) != nil {
		return firecrackerRuntimeOwnerRecordV1{}, nil, false, errL8RuntimeOwnerInvalid
	}
	record, err := jailerRecoveryRecordFromBinding(disk, binding)
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, nil, false, errL8RuntimeOwnerInvalid
	}
	canonical, err := encodeJailerRecoveryBoundRecord(record, binding, disk.Reservation, disk.CleanupCheckpoint)
	if err != nil || !bytes.Equal(payload, canonical) {
		return firecrackerRuntimeOwnerRecordV1{}, nil, false, errL8RuntimeOwnerInvalid
	}
	return record, disk.Reservation, disk.CleanupCheckpoint, nil
}

func jailerRecoveryConfigDigest(config jailerRecoverySupervisorConfig) string {
	payload, _ := json.Marshal(config)
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func jailerRecoveryRecordFromBinding(disk jailerRecoveryDiskRecord, binding jailerRecoveryRecordBinding) (firecrackerRuntimeOwnerRecordV1, error) {
	if disk.ConfigCorrelation != binding.configCorrelation || disk.Reservation != nil && (disk.Reservation.UID != binding.uid || disk.Reservation.GID != binding.gid || disk.Reservation.Config != binding.firecrackerConfigSHA256) {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	return jailerRecoveryCleanupRecordFromDisk(disk, binding.job)
}

// This decoder grants no resource authority. A fresh daemon uses only the
// common record to authenticate the same surviving owner, which still holds
// the complete config and exact leases and validates them before cleanup.
func decodeJailerRecoveryCleanupRecord(payload []byte, expected jailerRecoveryJob) (firecrackerRuntimeOwnerRecordV1, error) {
	var disk jailerRecoveryDiskRecord
	if len(payload) == 0 || len(payload) > l8RuntimeOwnerRecordLimit || json.Unmarshal(payload, &disk) != nil {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	record, err := jailerRecoveryCleanupRecordFromDisk(disk, expected)
	if err != nil {
		return record, err
	}
	encoded, _ := json.Marshal(record)
	var all map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &all)
	common := make(map[string]json.RawMessage, len(jailerRecoveryOwnerFields))
	for _, name := range jailerRecoveryOwnerFields {
		common[name] = all[name]
	}
	disk.Owner, _ = json.Marshal(common)
	canonical, err := json.Marshal(disk)
	if err != nil || !bytes.Equal(payload, canonical) {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	return record, nil
}

func jailerRecoveryCleanupRecordFromDisk(disk jailerRecoveryDiskRecord, expected jailerRecoveryJob) (firecrackerRuntimeOwnerRecordV1, error) {
	var record firecrackerRuntimeOwnerRecordV1
	for _, id := range []string{expected.SandboxID, expected.ExecutionID, expected.WorkerID, expected.HostID, expected.RuntimeID, expected.RuntimeGeneration} {
		if !validL8RuntimeOwnerSafeID(id) {
			return record, errL8RuntimeOwnerInvalid
		}
	}
	if !validStrictJailerRuntimeID(expected.RuntimeID) || disk.Version != jailerRecoveryRecordVersion || disk.Job != expected || !validJailerStagingDigest(disk.ConfigCorrelation) || json.Unmarshal(disk.Owner, &record) != nil {
		return record, errL8RuntimeOwnerInvalid
	}
	record.ContractVersion = jailerRecoveryRecordVersion
	record.SeedCorrelationDigest = disk.ConfigCorrelation
	record.SandboxID = expected.SandboxID
	record.ExecutionID = expected.ExecutionID
	record.WorkerID = expected.WorkerID
	record.HostID = expected.HostID
	record.RuntimeID = expected.RuntimeID
	record.RuntimeGeneration = expected.RuntimeGeneration
	if record.RuntimeDriver != "" || record.FirecrackerProcessGeneration != "" || record.VsockGeneration != "" || record.NetworkPlanID != "" || record.PolicySnapshotID != "" || record.ProxySessionID != "" || record.ProxyGenerationID != "" || record.TopologyGenerationID != "" || record.RuleGenerationID != "" {
		return record, errL8RuntimeOwnerInvalid
	}
	if !validL8RuntimeOwnerHostBootID(record.HostBootID) || !validL8RuntimeOwnerToken(record.SupervisorGeneration) || !validL8RuntimeOwnerToken(record.ReconnectListenerIdentity) || !validL8RuntimeOwnerToken(record.ReconnectSecret) || record.SupervisorPID <= 1 || record.SupervisorStartTime == 0 || !validL8RuntimeOwnerState(record.State) || !validL8RuntimeOwnerControllerState(record.ControllerState) {
		return record, errL8RuntimeOwnerInvalid
	}
	if disk.Reservation != nil {
		busy, err := readJailerIdentityRecord(disk.Reservation.payload(), strictJailerIdentitySlot{uid: disk.Reservation.UID, gid: disk.Reservation.GID})
		if err != nil || busy.UID == 0 || busy.GID == 0 || busy.State != "busy" || busy.RuntimeID != expected.RuntimeID {
			return record, errL8RuntimeOwnerInvalid
		}
	} else if disk.CleanupCheckpoint || record.FirecrackerPID != 0 {
		return record, errL8RuntimeOwnerInvalid
	}
	if record.State == "starting" {
		if record.ControllerState != "none" || record.Revision > 1 {
			return record, errL8RuntimeOwnerInvalid
		}
	} else if record.Revision < 2 && !(record.Revision == 1 && record.State == "uncertain" && record.ControllerState == "unclaimed" && disk.Reservation != nil) {
		return record, errL8RuntimeOwnerInvalid
	}
	if record.State == "starting" && record.Revision == 0 {
		if record.FirecrackerPID != 0 || record.FirecrackerStartTime != 0 {
			return record, errL8RuntimeOwnerInvalid
		}
	} else if record.FirecrackerPID <= 1 || record.FirecrackerStartTime == 0 {
		// Zero is only unresolved selected ownership metadata. It is never a
		// process-absence test: terminal states additionally require the exact
		// reservation's durable owned-cleanup checkpoint below.
		if record.FirecrackerPID != 0 || record.FirecrackerStartTime != 0 || disk.Reservation == nil || record.ControllerState == "none" || (record.State != "uncertain" && record.State != "absent" && record.State != "finalizing" && record.State != "finalized") {
			return record, errL8RuntimeOwnerInvalid
		}
	}
	if record.State == "finalizing" || record.State == "finalized" {
		if !disk.CleanupCheckpoint || !validL8RuntimeOwnerToken(record.FinalizedCommitID) || record.FinalizeTargetRevision == 0 || record.ControllerState == "none" {
			return record, errL8RuntimeOwnerInvalid
		}
		if record.State == "finalizing" && (record.Revision == ^uint64(0) || record.FinalizeTargetRevision != record.Revision+1) || record.State == "finalized" && record.FinalizeTargetRevision > record.Revision {
			return record, errL8RuntimeOwnerInvalid
		}
	} else if record.FinalizedCommitID != "" || record.FinalizeTargetRevision != 0 {
		return record, errL8RuntimeOwnerInvalid
	}
	absence := record.AbsenceKind != "" || record.AbsenceRevision != 0 || record.AbsenceObservedAtUnixNano != 0
	switch record.State {
	case "starting", "running", "stopping":
		if absence {
			return record, errL8RuntimeOwnerInvalid
		}
	case "absent", "finalizing", "finalized":
		if !absence || !disk.CleanupCheckpoint {
			return record, errL8RuntimeOwnerInvalid
		}
	}
	if absence && (record.AbsenceKind != "direct_wait" || record.AbsenceRevision == 0 || record.AbsenceRevision > record.Revision || record.AbsenceObservedAtUnixNano <= 0) {
		return record, errL8RuntimeOwnerInvalid
	}
	return record, nil
}
