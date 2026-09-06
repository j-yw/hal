package firecrackerhost

import (
	"bytes"
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
	return nil, errL8RuntimeOwnerInvalid
}

func decodeJailerRecoveryRecord(payload []byte, config jailerRecoverySupervisorConfig) (firecrackerRuntimeOwnerRecordV1, *jailerIdentityRecord, bool, error) {
	return firecrackerRuntimeOwnerRecordV1{}, nil, false, errL8RuntimeOwnerInvalid
}

func jailerRecoveryCanonicalEqual(left, right []byte) bool { return bytes.Equal(left, right) }
