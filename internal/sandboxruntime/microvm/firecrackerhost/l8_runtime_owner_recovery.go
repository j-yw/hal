package firecrackerhost

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	l8RuntimeOwnerContractVersion = "firecracker-runtime-owner-private-v1"
	l8RuntimeOwnerRecordName      = "runtime-owner.json"
	l8RuntimeOwnerRecordLimit     = 16 << 10

	l8RuntimeOwnerSeedDomain      = "hal/job-credential-runtime-absence/seed/v1"
	l8RuntimeOwnerCommitDomain    = "firecracker-runtime-owner-receipt-hmac-v1"
	l8RuntimeOwnerKeyGenerationV1 = "firecracker-runtime-owner-receipt-key-generation-v1"
)

var (
	errL8RuntimeOwnerInvalid     = errors.New("firecracker runtime owner state invalid")
	errL8RuntimeOwnerUnsupported = errors.New("firecracker runtime owner unsupported")
)

type firecrackerRuntimeOwnerRecordV1 struct {
	ContractVersion              string `json:"contractVersion"`
	Revision                     uint64 `json:"revision"`
	State                        string `json:"state"`
	HostBootID                   string `json:"hostBootId"`
	SeedCorrelationDigest        string `json:"seedCorrelationDigest"`
	SupervisorGeneration         string `json:"supervisorGeneration"`
	SupervisorPID                uint32 `json:"supervisorPid"`
	SupervisorStartTime          uint64 `json:"supervisorStartTime"`
	FirecrackerPID               uint32 `json:"firecrackerPid"`
	FirecrackerStartTime         uint64 `json:"firecrackerStartTime"`
	FinalizedCommitID            string `json:"finalizedCommitId"`
	SandboxID                    string `json:"sandboxId"`
	ExecutionID                  string `json:"executionId"`
	WorkerID                     string `json:"workerId"`
	HostID                       string `json:"hostId"`
	RuntimeDriver                string `json:"runtimeDriver"`
	RuntimeID                    string `json:"runtimeId"`
	RuntimeGeneration            string `json:"runtimeGeneration"`
	FirecrackerProcessGeneration string `json:"firecrackerProcessGeneration"`
	VsockGeneration              string `json:"vsockGeneration"`
	NetworkPlanID                string `json:"networkPlanId"`
	PolicySnapshotID             string `json:"policySnapshotId"`
	ProxySessionID               string `json:"proxySessionId"`
	ProxyGenerationID            string `json:"proxyGenerationId"`
	TopologyGenerationID         string `json:"topologyGenerationId"`
	RuleGenerationID             string `json:"ruleGenerationId"`
	ReconnectListenerIdentity    string `json:"reconnectListenerIdentity"`
	ReconnectSecret              string `json:"reconnectSecret"`
}

// l8RuntimeOwnerRecoveryBinding is reserved for the exact future concrete
// finalizer contract. R1 deliberately does not implement the neutral binding:
// recovered L7 termination authority does not exist yet.
type l8RuntimeOwnerRecoveryBinding struct {
	seed sandboxruntime.JobCredentialIdentitySeed
}

type l8RuntimeOwnerProcessObservation struct {
	PID        uint32
	StartTime  uint64
	state      byte
	pidfd      int
	pidfdOwned bool
}

func (observation *l8RuntimeOwnerProcessObservation) Close() error {
	if observation == nil || !observation.pidfdOwned {
		return nil
	}
	fd := observation.pidfd
	observation.pidfdOwned = false
	observation.pidfd = -1
	return closeL8RuntimeOwnerProcessFD(fd)
}

func validateL8RuntimeOwnerProcessCorrelation(record firecrackerRuntimeOwnerRecordV1, supervisor, firecracker l8RuntimeOwnerProcessObservation) error {
	if supervisor.PID != record.SupervisorPID || supervisor.StartTime != record.SupervisorStartTime || !supervisor.pidfdOwned || supervisor.pidfd < 0 || supervisor.state == 'Z' ||
		firecracker.PID != record.FirecrackerPID || firecracker.StartTime != record.FirecrackerStartTime || !firecracker.pidfdOwned || firecracker.pidfd < 0 || firecracker.state == 'Z' {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func l8RuntimeOwnerSeedDigest(seed sandboxruntime.JobCredentialIdentitySeed) ([32]byte, error) {
	if err := sandboxruntime.ValidateJobCredentialIdentitySeed(seed); err != nil {
		return [32]byte{}, errL8RuntimeOwnerInvalid
	}
	digest := sha256.New()
	l8RuntimeOwnerWriteString(digest, l8RuntimeOwnerSeedDomain)
	for _, value := range []string{
		seed.SandboxID, seed.ExecutionID, seed.WorkerID, seed.HostID,
		seed.RuntimeDriver, seed.RuntimeID, seed.RuntimeGeneration,
		seed.FirecrackerProcessGeneration, seed.VsockGeneration,
		seed.WorkerJobID, seed.SubmissionID, seed.PlanID,
		seed.ActivationGeneration, seed.CredentialGeneration,
		seed.NetworkPlanID, seed.PolicySnapshotID, seed.ProxySessionID,
		seed.ProxyGenerationID, seed.TopologyGenerationID, seed.RuleGenerationID,
		seed.AdmissionGrantID, seed.PrincipalID, seed.TemplatePolicyID,
		seed.WorkspacePolicyID, seed.ControllerKeyGeneration, seed.GuestBootGeneration,
		seed.GuestImageGeneration, seed.GuestImageDigest,
	} {
		l8RuntimeOwnerWriteString(digest, value)
	}
	var numeric [8]byte
	binary.BigEndian.PutUint64(numeric[:], seed.AdmissionGrantRevision)
	_, _ = digest.Write(numeric[:])
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(seed.BindingIDs)))
	_, _ = digest.Write(count[:])
	for index := range seed.BindingIDs {
		l8RuntimeOwnerWriteString(digest, seed.BindingIDs[index])
		l8RuntimeOwnerWriteString(digest, string(seed.DeliveryModes[index]))
	}
	binary.BigEndian.PutUint64(numeric[:], uint64(seed.IssuedAt.UnixNano()))
	_, _ = digest.Write(numeric[:])
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func l8RuntimeOwnerCommitID(key []byte, seedDigest [32]byte, revision uint64) (string, error) {
	if len(key) != sha256.Size || seedDigest == ([32]byte{}) || revision == 0 {
		return "", errL8RuntimeOwnerInvalid
	}
	keyGenerationHash := sha256.New()
	l8RuntimeOwnerWriteString(keyGenerationHash, l8RuntimeOwnerKeyGenerationV1)
	_, _ = keyGenerationHash.Write(key)
	keyGeneration := keyGenerationHash.Sum(nil)

	digest := hmac.New(sha256.New, key)
	l8RuntimeOwnerWriteString(digest, l8RuntimeOwnerCommitDomain)
	l8RuntimeOwnerWriteString(digest, l8RuntimeOwnerContractVersion)
	_, _ = digest.Write(keyGeneration)
	_, _ = digest.Write(seedDigest[:])
	var numeric [8]byte
	binary.BigEndian.PutUint64(numeric[:], revision)
	_, _ = digest.Write(numeric[:])
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil)), nil
}

func commitJobCredentialRuntimeRecovery(receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, key []byte, seed sandboxruntime.JobCredentialIdentitySeed, expectedRevision uint64) error {
	if sandboxruntime.ValidateJobCredentialRuntimeRecoveryCommitReceipt(receipt) != nil {
		return errL8RuntimeOwnerInvalid
	}
	seedDigest, err := l8RuntimeOwnerSeedDigest(seed)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	expectedCommitID, err := l8RuntimeOwnerCommitID(key, seedDigest, expectedRevision)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	commitID := receipt.CommitID
	if receipt.FinalizedRevision != expectedRevision || !validL8RuntimeOwnerToken(expectedCommitID) ||
		subtle.ConstantTimeCompare([]byte(commitID), []byte(expectedCommitID)) != 1 {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func validateFirecrackerRuntimeOwnerRecordV1(record firecrackerRuntimeOwnerRecordV1, seed sandboxruntime.JobCredentialIdentitySeed, currentBootID string) error {
	digest, err := l8RuntimeOwnerSeedDigest(seed)
	if err != nil || record.ContractVersion != l8RuntimeOwnerContractVersion || !validL8RuntimeOwnerHostBootID(currentBootID) ||
		record.HostBootID != currentBootID || record.SeedCorrelationDigest != hex.EncodeToString(digest[:]) ||
		!validL8RuntimeOwnerToken(record.SupervisorGeneration) || !validL8RuntimeOwnerToken(record.ReconnectListenerIdentity) ||
		!validL8RuntimeOwnerToken(record.ReconnectSecret) || record.SupervisorPID == 0 || record.SupervisorStartTime == 0 {
		return errL8RuntimeOwnerInvalid
	}
	if record.SandboxID != seed.SandboxID || record.ExecutionID != seed.ExecutionID || record.WorkerID != seed.WorkerID ||
		record.HostID != seed.HostID || record.RuntimeDriver != seed.RuntimeDriver || record.RuntimeID != seed.RuntimeID ||
		record.RuntimeGeneration != seed.RuntimeGeneration || record.FirecrackerProcessGeneration != seed.FirecrackerProcessGeneration ||
		record.VsockGeneration != seed.VsockGeneration || record.NetworkPlanID != seed.NetworkPlanID ||
		record.PolicySnapshotID != seed.PolicySnapshotID || record.ProxySessionID != seed.ProxySessionID ||
		record.ProxyGenerationID != seed.ProxyGenerationID || record.TopologyGenerationID != seed.TopologyGenerationID ||
		record.RuleGenerationID != seed.RuleGenerationID {
		return errL8RuntimeOwnerInvalid
	}
	if !validL8RuntimeOwnerState(record.State) {
		return errL8RuntimeOwnerInvalid
	}
	prelaunch := record.State == "starting" && record.Revision == 0
	if prelaunch {
		if record.FirecrackerPID != 0 || record.FirecrackerStartTime != 0 {
			return errL8RuntimeOwnerInvalid
		}
	} else if record.Revision == 0 || record.FirecrackerPID == 0 || record.FirecrackerStartTime == 0 {
		return errL8RuntimeOwnerInvalid
	}
	if record.State == "finalized" {
		if !validL8RuntimeOwnerToken(record.FinalizedCommitID) {
			return errL8RuntimeOwnerInvalid
		}
	} else if record.FinalizedCommitID != "" {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func encodeFirecrackerRuntimeOwnerRecordV1(record firecrackerRuntimeOwnerRecordV1, seed sandboxruntime.JobCredentialIdentitySeed, currentBootID string) ([]byte, error) {
	if validateFirecrackerRuntimeOwnerRecordV1(record, seed, currentBootID) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	payload, err := json.Marshal(record)
	if err != nil || len(payload)+1 > l8RuntimeOwnerRecordLimit {
		return nil, errL8RuntimeOwnerInvalid
	}
	return append(payload, '\n'), nil
}

func decodeFirecrackerRuntimeOwnerRecordV1(payload []byte, seed sandboxruntime.JobCredentialIdentitySeed, currentBootID string) (firecrackerRuntimeOwnerRecordV1, error) {
	if len(payload) < 3 || len(payload) > l8RuntimeOwnerRecordLimit || payload[len(payload)-1] != '\n' ||
		len(bytes.TrimSpace(payload[:len(payload)-1])) != len(payload)-1 || !l8RuntimeOwnerUniqueJSONObject(payload[:len(payload)-1]) {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var record firecrackerRuntimeOwnerRecordV1
	if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF || validateFirecrackerRuntimeOwnerRecordV1(record, seed, currentBootID) != nil {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	return record, nil
}

func l8RuntimeOwnerUniqueJSONObject(payload []byte) bool {
	allowed := map[string]bool{
		"contractVersion": true, "revision": true, "state": true, "hostBootId": true,
		"seedCorrelationDigest": true, "supervisorGeneration": true, "supervisorPid": true,
		"supervisorStartTime": true, "firecrackerPid": true, "firecrackerStartTime": true,
		"finalizedCommitId": true, "sandboxId": true, "executionId": true, "workerId": true,
		"hostId": true, "runtimeDriver": true, "runtimeId": true, "runtimeGeneration": true,
		"firecrackerProcessGeneration": true, "vsockGeneration": true, "networkPlanId": true,
		"policySnapshotId": true, "proxySessionId": true, "proxyGenerationId": true,
		"topologyGenerationId": true, "ruleGenerationId": true,
		"reconnectListenerIdentity": true, "reconnectSecret": true,
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || !l8RuntimeOwnerJSONFieldTypeValid(name, value) {
			return false
		}
	}
	token, err = decoder.Token()
	return err == nil && token == json.Delim('}') && len(seen) == len(allowed)
}

func l8RuntimeOwnerJSONFieldTypeValid(name string, payload json.RawMessage) bool {
	if bytes.Equal(bytes.TrimSpace(payload), []byte("null")) {
		return false
	}
	switch name {
	case "revision", "supervisorStartTime", "firecrackerStartTime":
		var value uint64
		return json.Unmarshal(payload, &value) == nil
	case "supervisorPid", "firecrackerPid":
		var value uint32
		return json.Unmarshal(payload, &value) == nil
	default:
		var value string
		return json.Unmarshal(payload, &value) == nil
	}
}

func validL8RuntimeOwnerState(state string) bool {
	switch state {
	case "starting", "unclaimed", "controlled", "stopping", "absent", "finalized", "uncertain":
		return true
	default:
		return false
	}
}

func validL8RuntimeOwnerToken(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validL8RuntimeOwnerHostBootID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func l8RuntimeOwnerWriteString(digest hash.Hash, value string) {
	l8RuntimeOwnerWriteBytes(digest, []byte(value))
}

func l8RuntimeOwnerWriteBytes(digest hash.Hash, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write(value)
}
