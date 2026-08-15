// Package strictcomposition owns the live L10 proof conjunction. The initial
// implementation is deliberately fail-closed so the red acceptance matrix can
// be committed before the evaluator is implemented.
package strictcomposition

import (
	"context"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

const (
	MaxActiveAttestationAge = 30 * time.Second
	MaxWorkspaceEvidenceAge = 5 * time.Minute
)

// RuntimeProofSource freshly inspects the exact retained L5/L7 authority.
type RuntimeProofSource interface {
	Inspect(context.Context, l7network.Identity) (l7network.Metadata, error)
}

// WorkspaceEvidence minimally correlates existing workspace and sync-out
// contracts to the exact sandbox execution and workspace policy.
type WorkspaceEvidence struct {
	SandboxID         string
	ExecutionID       string
	WorkspacePolicyID string
	ObservedAt        time.Time
	Workspace         sandbox.SandboxWorkspace
	SyncOut           sandboxworkspace.SyncOutSummary
	SafeApply         *sandboxworkspace.SafeApplyResult
	WarningCodes      []string
}

// ActiveRequest is live-only and intentionally has no JSON tags.
type ActiveRequest struct {
	Now                time.Time
	Identity           sandboxruntime.JobCredentialIdentity
	CredentialRevision uint64
	Runtime            RuntimeProofSource
	NetworkIdentity    l7network.Identity
	CredentialActive   sandboxruntime.JobCredentialActiveProof
	CredentialCleanup  sandboxruntime.JobCredentialCleanupProof
	Template           selection.Result
	TemplateBinding    selection.BindingRequest
	Workspace          WorkspaceEvidence
	FallbackUsed       bool
	Simulated          bool
	WarningCodes       []string
	CleanupIncomplete  bool
}

// ActiveAttestation is an opaque live token. Its fields are intentionally
// unavailable outside this package and it has no serialization methods.
type ActiveAttestation struct {
	token [32]byte
}

// TerminalRequest closes the credential phase of one exact active decision.
type TerminalRequest struct {
	Now                time.Time
	Identity           sandboxruntime.JobCredentialIdentity
	CredentialRevision uint64
	Attestation        ActiveAttestation
	CredentialActive   sandboxruntime.JobCredentialActiveProof
	CredentialCleanup  sandboxruntime.JobCredentialCleanupProof
	Template           selection.Result
	TemplateBinding    selection.BindingRequest
	Workspace          WorkspaceEvidence
	WarningCodes       []string
	CleanupIncomplete  bool
}

// EvaluateActive is fail-closed until the red-first implementation lands.
func EvaluateActive(context.Context, ActiveRequest) (ActiveAttestation, sandbox.SandboxStrictCompositionDecision) {
	return ActiveAttestation{}, sandbox.SandboxStrictCompositionDecision{
		State: sandbox.SandboxStrictCompositionStateBlocked,
		Code:  sandbox.SandboxStrictCompositionCodeIdentityInvalid,
	}
}

// EvaluateTerminal is fail-closed until the red-first implementation lands.
func EvaluateTerminal(context.Context, TerminalRequest) sandbox.SandboxStrictCompositionDecision {
	return sandbox.SandboxStrictCompositionDecision{
		State: sandbox.SandboxStrictCompositionStateBlocked,
		Code:  sandbox.SandboxStrictCompositionCodeIdentityInvalid,
	}
}

// AttestationValid reports false until the red-first implementation lands.
func AttestationValid(attestation ActiveAttestation, sandboxID, executionID, runtimeID string, now time.Time) bool {
	_ = attestation
	return false
}
