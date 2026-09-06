package l7network

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

const recoveredVMTerminationProofDomain = "hal/l7-recovered-vm-termination/v1"

// RecoveredVMTerminationObservation is independently reacquired Firecracker
// absence correlated to a recovered L7 journal. PID values stay off this
// struct so they cannot leak into worker or status metadata.
type RecoveredVMTerminationObservation struct {
	Identity             Identity
	ProcessGeneration    string
	SupervisorGeneration string
	Stopped              bool
	Reaped               bool
}

// recoveredVMTerminationBinding implements TerminatedVMBinding for daemon-restart
// recovery. Same-process production trackers cannot be reacquired after restart.
type recoveredVMTerminationBinding struct {
	correlation networkenforcement.EnforcementCorrelation
	proofID     string
	stopped     bool
	reaped      bool
}

func (binding *recoveredVMTerminationBinding) VMCorrelation() networkenforcement.EnforcementCorrelation {
	if binding == nil {
		return networkenforcement.EnforcementCorrelation{}
	}
	return binding.correlation
}

func (binding *recoveredVMTerminationBinding) VMTerminationProofID() string {
	if binding == nil {
		return ""
	}
	return binding.proofID
}

// NewRecoveredVMTerminationBinding constructs a private recovered
// TerminatedVMBinding. Incomplete absence is still returned so the recovered
// verifier can reject still-running or unreaped observations.
func NewRecoveredVMTerminationBinding(observation RecoveredVMTerminationObservation) (TerminatedVMBinding, error) {
	if !validIdentity(observation.Identity) {
		return nil, ErrInvalidIdentity
	}
	proofID := recoveredVMTerminationProofID(observation)
	if !safeIDPattern.MatchString(proofID) {
		return nil, ErrInvalidIdentity
	}
	return &recoveredVMTerminationBinding{
		correlation: correlation(observation.Identity),
		proofID:     proofID,
		stopped:     observation.Stopped,
		reaped:      observation.Reaped,
	}, nil
}

type recoveredVMTerminationVerifier struct{}

// NewRecoveredVMTerminationVerifier accepts only recoveredVMTerminationBinding.
func NewRecoveredVMTerminationVerifier() VMTerminationVerifier {
	return recoveredVMTerminationVerifier{}
}

func (recoveredVMTerminationVerifier) VerifyVMTermination(_ context.Context, request VMTerminationRequest) (VMTerminationProof, error) {
	binding, ok := request.Binding.(*recoveredVMTerminationBinding)
	if !ok || binding == nil {
		return VMTerminationProof{}, ErrVMNotQuiesced
	}
	if request.TerminationProofID != binding.proofID ||
		!networkenforcement.EnforcementCorrelationsEqual(request.Correlation, binding.correlation) {
		return VMTerminationProof{}, ErrIdentityMismatch
	}
	if !binding.stopped || !binding.reaped {
		return VMTerminationProof{}, ErrVMNotQuiesced
	}
	proofID := recoveredVMTerminationVerifyID(binding)
	if !safeIDPattern.MatchString(proofID) {
		return VMTerminationProof{}, ErrVMNotQuiesced
	}
	return VMTerminationProof{
		ID:                 proofID,
		TerminationProofID: binding.proofID,
		Correlation:        binding.correlation,
		Stopped:            true,
		Reaped:             true,
	}, nil
}

func recoveredVMTerminationProofID(observation RecoveredVMTerminationObservation) string {
	identity := observation.Identity
	digest := sha256.New()
	l7RecoveredWriteString(digest, recoveredVMTerminationProofDomain)
	l7RecoveredWriteString(digest, identity.SandboxID)
	l7RecoveredWriteString(digest, identity.ExecutionID)
	l7RecoveredWriteString(digest, identity.WorkerID)
	l7RecoveredWriteString(digest, identity.RuntimeGenerationID)
	l7RecoveredWriteString(digest, identity.PlanID)
	l7RecoveredWriteString(digest, identity.PolicySnapshotID)
	l7RecoveredWriteString(digest, identity.ProxySessionID)
	l7RecoveredWriteString(digest, identity.ProxyGenerationID)
	l7RecoveredWriteString(digest, identity.TopologyGenerationID)
	l7RecoveredWriteString(digest, identity.RuleGenerationID)
	l7RecoveredWriteString(digest, observation.ProcessGeneration)
	l7RecoveredWriteString(digest, observation.SupervisorGeneration)
	return "recovered-" + hex.EncodeToString(digest.Sum(nil)[:16])
}

func recoveredVMTerminationVerifyID(binding *recoveredVMTerminationBinding) string {
	if binding == nil {
		return ""
	}
	digest := sha256.Sum256([]byte(recoveredVMTerminationProofDomain + "\x00vm\x00" + binding.proofID))
	return "vm-" + hex.EncodeToString(digest[:16])
}

func l7RecoveredWriteString(digest hash.Hash, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = digest.Write(length[:])
	_, _ = digest.Write([]byte(value))
}
