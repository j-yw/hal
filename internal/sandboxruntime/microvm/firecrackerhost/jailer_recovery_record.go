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

func encodeJailerRecoveryRecord(record firecrackerRuntimeOwnerRecordV1, config jailerRecoverySupervisorConfig, reservation *jailerIdentityRecord, terminal bool) ([]byte, error) {
	if validateJailerRecoverySupervisorConfig(config) != nil {
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
	disk := jailerRecoveryDiskRecord{Version: jailerRecoveryRecordVersion, ConfigCorrelation: jailerRecoveryConfigDigest(config), Job: config.Job, Owner: owner, Reservation: reservation, CleanupCheckpoint: terminal}
	restored, err := jailerRecoveryRecordFromDisk(disk, config)
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
	var disk jailerRecoveryDiskRecord
	if len(payload) == 0 || len(payload) > l8RuntimeOwnerRecordLimit || json.Unmarshal(payload, &disk) != nil {
		return firecrackerRuntimeOwnerRecordV1{}, nil, false, errL8RuntimeOwnerInvalid
	}
	record, err := jailerRecoveryRecordFromDisk(disk, config)
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, nil, false, errL8RuntimeOwnerInvalid
	}
	canonical, err := encodeJailerRecoveryRecord(record, config, disk.Reservation, disk.CleanupCheckpoint)
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

func jailerRecoveryRecordFromDisk(disk jailerRecoveryDiskRecord, config jailerRecoverySupervisorConfig) (firecrackerRuntimeOwnerRecordV1, error) {
	var record firecrackerRuntimeOwnerRecordV1
	if disk.Version != jailerRecoveryRecordVersion || disk.Job != config.Job || disk.ConfigCorrelation != jailerRecoveryConfigDigest(config) || json.Unmarshal(disk.Owner, &record) != nil {
		return record, errL8RuntimeOwnerInvalid
	}
	record.ContractVersion = jailerRecoveryRecordVersion
	record.SeedCorrelationDigest = disk.ConfigCorrelation
	record.SandboxID = config.Job.SandboxID
	record.ExecutionID = config.Job.ExecutionID
	record.WorkerID = config.Job.WorkerID
	record.HostID = config.Job.HostID
	record.RuntimeID = config.Job.RuntimeID
	record.RuntimeGeneration = config.Job.RuntimeGeneration
	if record.RuntimeDriver != "" || record.FirecrackerProcessGeneration != "" || record.VsockGeneration != "" || record.NetworkPlanID != "" || record.PolicySnapshotID != "" || record.ProxySessionID != "" || record.ProxyGenerationID != "" || record.TopologyGenerationID != "" || record.RuleGenerationID != "" {
		return record, errL8RuntimeOwnerInvalid
	}
	if !validL8RuntimeOwnerHostBootID(record.HostBootID) || !validL8RuntimeOwnerToken(record.SupervisorGeneration) || !validL8RuntimeOwnerToken(record.ReconnectListenerIdentity) || !validL8RuntimeOwnerToken(record.ReconnectSecret) || record.SupervisorPID <= 1 || record.SupervisorStartTime == 0 || !validL8RuntimeOwnerState(record.State) || !validL8RuntimeOwnerControllerState(record.ControllerState) {
		return record, errL8RuntimeOwnerInvalid
	}
	if disk.Reservation != nil {
		busy, err := readJailerIdentityRecord(disk.Reservation.payload(), strictJailerIdentitySlot{uid: config.Policy.UID, gid: config.Policy.GID})
		if err != nil || busy.State != "busy" || busy.RuntimeID != config.Job.RuntimeID || busy.Config != config.Config.SHA256 {
			return record, errL8RuntimeOwnerInvalid
		}
	} else if disk.CleanupCheckpoint || record.FirecrackerPID != 0 {
		return record, errL8RuntimeOwnerInvalid
	}
	if record.State == "starting" {
		if record.ControllerState != "none" || record.Revision > 1 {
			return record, errL8RuntimeOwnerInvalid
		}
	} else if record.Revision < 2 {
		return record, errL8RuntimeOwnerInvalid
	}
	if record.State == "starting" && record.Revision == 0 {
		if record.FirecrackerPID != 0 || record.FirecrackerStartTime != 0 {
			return record, errL8RuntimeOwnerInvalid
		}
	} else if record.FirecrackerPID <= 1 || record.FirecrackerStartTime == 0 {
		return record, errL8RuntimeOwnerInvalid
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
