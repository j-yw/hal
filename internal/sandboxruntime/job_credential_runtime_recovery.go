package sandboxruntime

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"time"
)

const (
	MaxJobCredentialRuntimeAbsenceObservationAge = 5 * time.Minute
	JobCredentialRuntimeStopReapTimeout          = 30 * time.Second
	JobCredentialRuntimeRecoveryCloseTimeout     = 5 * time.Second

	jobCredentialRuntimeAbsenceProofKind = byte(0x03)
)

const jobCredentialRuntimeAbsenceSeedDomain = "hal/job-credential-runtime-absence/seed/v1"

type JobCredentialRuntimeAbsenceProofInput struct {
	Seed               JobCredentialIdentitySeed
	AbsenceInspectedAt time.Time
}

type JobCredentialRuntimeAbsenceProof struct {
	token [41]byte
}

func (JobCredentialRuntimeAbsenceProof) String() string {
	return "<sandboxruntime.JobCredentialRuntimeAbsenceProof>"
}

func (JobCredentialRuntimeAbsenceProof) GoString() string {
	return "<sandboxruntime.JobCredentialRuntimeAbsenceProof>"
}

func (JobCredentialRuntimeAbsenceProof) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<sandboxruntime.JobCredentialRuntimeAbsenceProof>")
}

func (JobCredentialRuntimeAbsenceProof) MarshalJSON() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialRuntimeAbsenceProof) MarshalText() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialRuntimeAbsenceProof) MarshalBinary() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialRuntimeAbsenceProof) GobEncode() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func NewJobCredentialRuntimeAbsenceProof(input JobCredentialRuntimeAbsenceProofInput) (JobCredentialRuntimeAbsenceProof, error) {
	digest, err := jobCredentialRuntimeAbsenceSeedDigest(input.Seed)
	if err != nil || input.AbsenceInspectedAt.IsZero() || input.AbsenceInspectedAt.Before(input.Seed.IssuedAt) {
		return JobCredentialRuntimeAbsenceProof{}, ErrJobCredentialProofInvalid
	}
	proof := JobCredentialRuntimeAbsenceProof{}
	proof.token[0] = jobCredentialRuntimeAbsenceProofKind
	copy(proof.token[1:33], digest[:])
	binary.BigEndian.PutUint64(proof.token[33:], uint64(input.AbsenceInspectedAt.UnixNano()))
	return proof, nil
}

func ValidateJobCredentialRuntimeAbsenceProof(proof JobCredentialRuntimeAbsenceProof, seed JobCredentialIdentitySeed, now time.Time) error {
	digest, err := jobCredentialRuntimeAbsenceSeedDigest(seed)
	if err != nil || now.IsZero() || proof.token[0] != jobCredentialRuntimeAbsenceProofKind ||
		subtle.ConstantTimeCompare(proof.token[1:33], digest[:]) != 1 {
		return ErrJobCredentialProofInvalid
	}
	inspectedAt := time.Unix(0, int64(binary.BigEndian.Uint64(proof.token[33:]))).UTC()
	if inspectedAt.Before(seed.IssuedAt) || inspectedAt.After(now) {
		return ErrJobCredentialProofInvalid
	}
	if now.Sub(inspectedAt) > MaxJobCredentialRuntimeAbsenceObservationAge {
		return ErrJobCredentialProofStale
	}
	return nil
}

type JobCredentialRuntimeRecoveryCommitReceipt struct {
	CommitID          string `json:"-" xml:"-"`
	FinalizedRevision uint64 `json:"-" xml:"-"`
}

func ValidateJobCredentialRuntimeRecoveryCommitReceipt(receipt JobCredentialRuntimeRecoveryCommitReceipt) error {
	commitID := receipt.CommitID
	if len(commitID) != 43 || receipt.FinalizedRevision == 0 {
		return ErrJobCredentialProofInvalid
	}
	decoded, err := base64.RawURLEncoding.DecodeString(commitID)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != commitID {
		return ErrJobCredentialProofInvalid
	}
	return nil
}

func (JobCredentialRuntimeRecoveryCommitReceipt) String() string {
	return "[job-credential-runtime-recovery-commit-receipt]"
}

func (JobCredentialRuntimeRecoveryCommitReceipt) GoString() string {
	return "[job-credential-runtime-recovery-commit-receipt]"
}

func (JobCredentialRuntimeRecoveryCommitReceipt) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "[job-credential-runtime-recovery-commit-receipt]")
}

func (JobCredentialRuntimeRecoveryCommitReceipt) MarshalJSON() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialRuntimeRecoveryCommitReceipt) MarshalText() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialRuntimeRecoveryCommitReceipt) MarshalBinary() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

func (JobCredentialRuntimeRecoveryCommitReceipt) GobEncode() ([]byte, error) {
	return nil, ErrJobCredentialSerialization
}

type JobCredentialRuntimeRecoveryProvider interface {
	BindJobCredentialRuntimeRecovery(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimeRecoveryBinding, error)
}

type JobCredentialRuntimeRecoveryBinding interface {
	RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error)
	StopReapJobCredentialRuntime(context.Context) (JobCredentialRuntimeAbsenceProof, error)
	FinalizeJobCredentialRuntimeRecovery(context.Context, JobCredentialRuntimeAbsenceProof) (JobCredentialRuntimeRecoveryCommitReceipt, error)
	CommitJobCredentialRuntimeRecovery(context.Context, JobCredentialRuntimeRecoveryCommitReceipt) error
	Close(context.Context) error
}

func jobCredentialRuntimeAbsenceSeedDigest(seed JobCredentialIdentitySeed) ([32]byte, error) {
	if err := ValidateJobCredentialIdentitySeed(seed); err != nil {
		return [32]byte{}, ErrJobCredentialProofInvalid
	}
	digest := sha256.New()
	jobCredentialRuntimeWriteDigestString(digest, jobCredentialRuntimeAbsenceSeedDomain)
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
		jobCredentialRuntimeWriteDigestString(digest, value)
	}
	var numeric [8]byte
	binary.BigEndian.PutUint64(numeric[:], seed.AdmissionGrantRevision)
	_, _ = digest.Write(numeric[:])
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(seed.BindingIDs)))
	_, _ = digest.Write(count[:])
	for index := range seed.BindingIDs {
		jobCredentialRuntimeWriteDigestString(digest, seed.BindingIDs[index])
		jobCredentialRuntimeWriteDigestString(digest, string(seed.DeliveryModes[index]))
	}
	binary.BigEndian.PutUint64(numeric[:], uint64(seed.IssuedAt.UnixNano()))
	_, _ = digest.Write(numeric[:])
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func jobCredentialRuntimeWriteDigestString(digest hash.Hash, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = io.WriteString(digest, value)
}
