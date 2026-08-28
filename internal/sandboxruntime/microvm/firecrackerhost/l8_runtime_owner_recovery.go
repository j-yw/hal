package firecrackerhost

import (
	"bytes"
	"context"
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
	"sync"
	"time"

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
	ControllerState              string `json:"controllerState"`
	AbsenceKind                  string `json:"absenceKind"`
	AbsenceRevision              uint64 `json:"absenceRevision"`
	AbsenceObservedAtUnixNano    int64  `json:"absenceObservedAtUnixNano"`
	FinalizeTargetRevision       uint64 `json:"finalizeTargetRevision"`
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

// l8RuntimeOwnerRecoveryBinding is the seed-bound Firecracker runtime-owner
// recovery binding. Stop/reap is the sole production issuer of
// sandboxruntime.NewJobCredentialRuntimeAbsenceProof. Finalize fail-closes
// without a recovered l7network.TerminatedVMBinding constructor.
type l8RuntimeOwnerRecoveryBinding struct {
	mu                 sync.Mutex
	seed               sandboxruntime.JobCredentialIdentitySeed
	commitKey          []byte
	store              l8RuntimeOwnerRecordStore
	proveAbsence       func(context.Context) (l8RuntimeOwnerAbsenceObservation, error)
	recoverCredentials func(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error)
	currentBootID      func() (string, error)
	now                func() time.Time
	closed             bool
	commitOnly         bool
}

var _ sandboxruntime.JobCredentialRuntimeRecoveryBinding = (*l8RuntimeOwnerRecoveryBinding)(nil)

func (binding *l8RuntimeOwnerRecoveryBinding) RecoverJobCredentials(ctx context.Context, request sandboxruntime.JobCredentialRecoveryRequest) (proof sandboxruntime.JobCredentialCleanupProof, err error) {
	defer func() {
		if recover() != nil {
			proof = sandboxruntime.JobCredentialCleanupProof{}
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if binding == nil || ctx == nil {
		return sandboxruntime.JobCredentialCleanupProof{}, errL8RuntimeOwnerInvalid
	}
	binding.mu.Lock()
	if binding.closed || binding.commitOnly {
		binding.mu.Unlock()
		return sandboxruntime.JobCredentialCleanupProof{}, errL8RuntimeOwnerInvalid
	}
	seed := binding.seed
	recoverFn := binding.recoverCredentials
	binding.mu.Unlock()
	if sandboxruntime.ValidateJobCredentialIdentityCompletion(seed, request.Identity) != nil {
		return sandboxruntime.JobCredentialCleanupProof{}, sandboxruntime.ErrJobCredentialIdentityMismatch
	}
	recovered, recoverErr := callL8RuntimeOwnerRecoverCredentials(recoverFn, ctx, request)
	_, stopErr := binding.StopReapJobCredentialRuntime(ctx)
	if stopErr != nil {
		return sandboxruntime.JobCredentialCleanupProof{}, errL8RuntimeOwnerInvalid
	}
	if recoverErr != nil || sandboxruntime.CleanupProofKind(recovered) == "" {
		return sandboxruntime.JobCredentialCleanupProof{}, errL8RuntimeOwnerInvalid
	}
	return recovered, nil
}

func callL8RuntimeOwnerRecoverCredentials(
	fn func(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error),
	ctx context.Context,
	request sandboxruntime.JobCredentialRecoveryRequest,
) (proof sandboxruntime.JobCredentialCleanupProof, err error) {
	defer func() {
		if recover() != nil {
			proof = sandboxruntime.JobCredentialCleanupProof{}
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if fn == nil {
		return sandboxruntime.JobCredentialCleanupProof{}, errL8RuntimeOwnerInvalid
	}
	return fn(ctx, request)
}

func (binding *l8RuntimeOwnerRecoveryBinding) StopReapJobCredentialRuntime(ctx context.Context) (proof sandboxruntime.JobCredentialRuntimeAbsenceProof, err error) {
	defer func() {
		if recover() != nil {
			proof = sandboxruntime.JobCredentialRuntimeAbsenceProof{}
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if binding == nil || ctx == nil {
		return sandboxruntime.JobCredentialRuntimeAbsenceProof{}, errL8RuntimeOwnerInvalid
	}
	if !l8RuntimeOwnerPlatformSupported() {
		return sandboxruntime.JobCredentialRuntimeAbsenceProof{}, errL8RuntimeOwnerUnsupported
	}
	binding.mu.Lock()
	if binding.closed || binding.commitOnly || binding.proveAbsence == nil {
		binding.mu.Unlock()
		return sandboxruntime.JobCredentialRuntimeAbsenceProof{}, errL8RuntimeOwnerInvalid
	}
	seed := binding.seed
	prove := binding.proveAbsence
	nowFn := binding.now
	binding.mu.Unlock()
	stopCtx, cancel := context.WithTimeout(context.Background(), sandboxruntime.JobCredentialRuntimeStopReapTimeout)
	defer cancel()
	observation, proveErr := prove(stopCtx)
	if proveErr != nil || (observation.Kind != l8RuntimeOwnerAbsenceKindWait && observation.Kind != l8RuntimeOwnerAbsenceKindProc) ||
		observation.ObservedAt.IsZero() || observation.ObservedAt.Before(seed.IssuedAt) {
		return sandboxruntime.JobCredentialRuntimeAbsenceProof{}, errL8RuntimeOwnerInvalid
	}
	proof, err = sandboxruntime.NewJobCredentialRuntimeAbsenceProof(sandboxruntime.JobCredentialRuntimeAbsenceProofInput{
		Seed:               seed,
		AbsenceInspectedAt: observation.ObservedAt,
	})
	if err != nil {
		return sandboxruntime.JobCredentialRuntimeAbsenceProof{}, errL8RuntimeOwnerInvalid
	}
	now := time.Now().UTC()
	if nowFn != nil {
		now = nowFn()
	}
	if err := sandboxruntime.ValidateJobCredentialRuntimeAbsenceProof(proof, seed, now); err != nil {
		return sandboxruntime.JobCredentialRuntimeAbsenceProof{}, errL8RuntimeOwnerInvalid
	}
	return proof, nil
}

func (binding *l8RuntimeOwnerRecoveryBinding) FinalizeJobCredentialRuntimeRecovery(ctx context.Context, proof sandboxruntime.JobCredentialRuntimeAbsenceProof) (receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt, err error) {
	defer func() {
		if recover() != nil {
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if binding == nil || ctx == nil {
		err = errL8RuntimeOwnerInvalid
		return
	}
	if !l8RuntimeOwnerPlatformSupported() {
		err = errL8RuntimeOwnerUnsupported
		return
	}
	binding.mu.Lock()
	if binding.closed || binding.commitOnly {
		binding.mu.Unlock()
		err = errL8RuntimeOwnerInvalid
		return
	}
	seed := binding.seed
	store := binding.store
	nowFn := binding.now
	bootFn := binding.currentBootID
	binding.mu.Unlock()
	now := time.Now().UTC()
	if nowFn != nil {
		now = nowFn()
	}
	if sandboxruntime.ValidateJobCredentialRuntimeAbsenceProof(proof, seed, now) != nil || store == nil {
		err = errL8RuntimeOwnerInvalid
		return
	}
	record, loadErr := store.Load(ctx)
	if loadErr != nil || (record.State != "absent" && record.State != "finalizing" && record.State != "finalized") {
		err = errL8RuntimeOwnerInvalid
		return
	}
	if bootFn != nil {
		bootID, bootErr := bootFn()
		if bootErr != nil || bootID != record.HostBootID {
			err = errL8RuntimeOwnerInvalid
			return
		}
	}
	err = errL8RuntimeOwnerInvalid
	return
}

func (binding *l8RuntimeOwnerRecoveryBinding) CommitJobCredentialRuntimeRecovery(ctx context.Context, receipt sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt) (err error) {
	defer func() {
		if recover() != nil {
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if binding == nil || ctx == nil {
		return errL8RuntimeOwnerInvalid
	}
	binding.mu.Lock()
	commitOnly := binding.commitOnly
	key := binding.commitKey
	seed := binding.seed
	store := binding.store
	binding.mu.Unlock()
	if commitOnly {
		if commitJobCredentialRuntimeRecovery(receipt, key, seed, receipt.FinalizedRevision) != nil {
			return errL8RuntimeOwnerInvalid
		}
		if store != nil {
			if _, err := store.Load(ctx); err == nil {
				return errL8RuntimeOwnerInvalid
			}
		}
		return nil
	}
	if store == nil {
		return errL8RuntimeOwnerInvalid
	}
	record, err := store.Load(ctx)
	if err != nil || record.State != "finalized" {
		return errL8RuntimeOwnerInvalid
	}
	if commitJobCredentialRuntimeRecovery(receipt, key, seed, record.FinalizeTargetRevision) != nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := store.RetireFinalized(ctx, record.Revision, record.FinalizedCommitID); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func (binding *l8RuntimeOwnerRecoveryBinding) Close(context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if binding == nil {
		return errL8RuntimeOwnerInvalid
	}
	_, cancel := context.WithTimeout(context.Background(), sandboxruntime.JobCredentialRuntimeRecoveryCloseTimeout)
	defer cancel()
	binding.mu.Lock()
	binding.closed = true
	binding.mu.Unlock()
	return nil
}

type l8RuntimeOwnerProcessObservation struct {
	PID        uint32
	ParentPID  uint32
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
	if !validL8RuntimeOwnerState(record.State) || !validL8RuntimeOwnerControllerState(record.ControllerState) {
		return errL8RuntimeOwnerInvalid
	}
	prelaunch := record.State == "starting" && record.Revision == 0
	if record.State == "starting" {
		if record.ControllerState != "none" || record.Revision > 1 {
			return errL8RuntimeOwnerInvalid
		}
	} else if record.Revision < 2 {
		return errL8RuntimeOwnerInvalid
	}
	if prelaunch {
		if record.FirecrackerPID != 0 || record.FirecrackerStartTime != 0 {
			return errL8RuntimeOwnerInvalid
		}
	} else if record.Revision == 0 || record.FirecrackerPID == 0 || record.FirecrackerStartTime == 0 {
		return errL8RuntimeOwnerInvalid
	}
	if record.State == "finalizing" || record.State == "finalized" {
		if !validL8RuntimeOwnerToken(record.FinalizedCommitID) || record.FinalizeTargetRevision == 0 {
			return errL8RuntimeOwnerInvalid
		}
		if record.State == "finalizing" && (record.ControllerState == "none" || record.Revision == ^uint64(0) || record.FinalizeTargetRevision != record.Revision+1) {
			return errL8RuntimeOwnerInvalid
		}
		if record.State == "finalized" && (record.ControllerState == "none" || record.FinalizeTargetRevision > record.Revision) {
			return errL8RuntimeOwnerInvalid
		}
	} else if record.FinalizedCommitID != "" || record.FinalizeTargetRevision != 0 {
		return errL8RuntimeOwnerInvalid
	}
	switch record.State {
	case "starting", "running", "stopping":
		if record.AbsenceKind != "" || record.AbsenceRevision != 0 || record.AbsenceObservedAtUnixNano != 0 {
			return errL8RuntimeOwnerInvalid
		}
	case "absent", "finalizing", "finalized":
		if !validL8RuntimeOwnerAbsence(record, seed) {
			return errL8RuntimeOwnerInvalid
		}
	case "uncertain":
		absentHistory := record.AbsenceKind != "" || record.AbsenceRevision != 0 || record.AbsenceObservedAtUnixNano != 0
		if absentHistory && !validL8RuntimeOwnerAbsence(record, seed) {
			return errL8RuntimeOwnerInvalid
		}
	}
	return nil
}

func validL8RuntimeOwnerAbsence(record firecrackerRuntimeOwnerRecordV1, seed sandboxruntime.JobCredentialIdentitySeed) bool {
	if record.AbsenceKind != "direct_wait" && record.AbsenceKind != "replacement_proc" {
		return false
	}
	return record.AbsenceRevision > 0 && record.AbsenceRevision <= record.Revision &&
		record.AbsenceObservedAtUnixNano >= seed.IssuedAt.UnixNano()
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
		"contractVersion": true, "revision": true, "state": true, "controllerState": true,
		"absenceKind": true, "absenceRevision": true, "absenceObservedAtUnixNano": true,
		"finalizeTargetRevision": true, "hostBootId": true,
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
	case "revision", "absenceRevision", "finalizeTargetRevision", "supervisorStartTime", "firecrackerStartTime":
		var value uint64
		return json.Unmarshal(payload, &value) == nil
	case "absenceObservedAtUnixNano":
		var value int64
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
	case "starting", "running", "stopping", "absent", "finalizing", "finalized", "uncertain":
		return true
	default:
		return false
	}
}

func validL8RuntimeOwnerControllerState(state string) bool {
	switch state {
	case "none", "unclaimed", "controlled":
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
