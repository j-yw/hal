package sandbox

import "time"

// SandboxStrictCompositionState is the durable state of one sanitized L10
// decision. It is data only and never authorizes a live operation.
type SandboxStrictCompositionState string

const (
	SandboxStrictCompositionStateBlocked  SandboxStrictCompositionState = "blocked"
	SandboxStrictCompositionStateActive   SandboxStrictCompositionState = "active"
	SandboxStrictCompositionStateComplete SandboxStrictCompositionState = "complete"
)

// SandboxStrictCompositionCode is a stable, redaction-safe L10 outcome code.
type SandboxStrictCompositionCode string

const (
	SandboxStrictCompositionCodeReady                    SandboxStrictCompositionCode = "strict_ready"
	SandboxStrictCompositionCodeComplete                 SandboxStrictCompositionCode = "strict_complete"
	SandboxStrictCompositionCodeIdentityInvalid          SandboxStrictCompositionCode = "identity_invalid"
	SandboxStrictCompositionCodeIdentityMismatch         SandboxStrictCompositionCode = "identity_mismatch"
	SandboxStrictCompositionCodeRuntimeProofMissing      SandboxStrictCompositionCode = "runtime_proof_missing"
	SandboxStrictCompositionCodeRuntimeProofStale        SandboxStrictCompositionCode = "runtime_proof_stale"
	SandboxStrictCompositionCodeRuntimeProofMismatch     SandboxStrictCompositionCode = "runtime_proof_mismatch"
	SandboxStrictCompositionCodeCredentialActiveMissing  SandboxStrictCompositionCode = "credential_active_missing"
	SandboxStrictCompositionCodeCredentialCleanupMissing SandboxStrictCompositionCode = "credential_cleanup_missing"
	SandboxStrictCompositionCodeCredentialProofStale     SandboxStrictCompositionCode = "credential_proof_stale"
	SandboxStrictCompositionCodeCredentialProofMismatch  SandboxStrictCompositionCode = "credential_proof_mismatch"
	SandboxStrictCompositionCodeTemplateProofMissing     SandboxStrictCompositionCode = "template_proof_missing"
	SandboxStrictCompositionCodeTemplateProofRejected    SandboxStrictCompositionCode = "template_proof_rejected"
	SandboxStrictCompositionCodeTemplateProofMismatch    SandboxStrictCompositionCode = "template_proof_mismatch"
	SandboxStrictCompositionCodeWorkspaceProofMissing    SandboxStrictCompositionCode = "workspace_proof_missing"
	SandboxStrictCompositionCodeWorkspaceProofStale      SandboxStrictCompositionCode = "workspace_proof_stale"
	SandboxStrictCompositionCodeWorkspaceProofUnsafe     SandboxStrictCompositionCode = "workspace_proof_unsafe"
	SandboxStrictCompositionCodeWorkspaceProofMismatch   SandboxStrictCompositionCode = "workspace_proof_mismatch"
	SandboxStrictCompositionCodeWarningBearing           SandboxStrictCompositionCode = "warning_bearing"
	SandboxStrictCompositionCodeFallbackForbidden        SandboxStrictCompositionCode = "fallback_forbidden"
	SandboxStrictCompositionCodeSimulationForbidden      SandboxStrictCompositionCode = "simulation_forbidden"
	SandboxStrictCompositionCodeCleanupIncomplete        SandboxStrictCompositionCode = "cleanup_incomplete"
	SandboxStrictCompositionCodeAttestationStale         SandboxStrictCompositionCode = "attestation_stale"
)

// SandboxStrictCompositionEvidenceKind identifies one conjunct without
// exposing its live proof.
type SandboxStrictCompositionEvidenceKind string

const (
	SandboxStrictCompositionEvidenceRuntime    SandboxStrictCompositionEvidenceKind = "runtime_network"
	SandboxStrictCompositionEvidenceCredential SandboxStrictCompositionEvidenceKind = "credential"
	SandboxStrictCompositionEvidenceTemplate   SandboxStrictCompositionEvidenceKind = "template"
	SandboxStrictCompositionEvidenceWorkspace  SandboxStrictCompositionEvidenceKind = "workspace"
)

// SandboxStrictCompositionEvidence records a bounded safe status for one
// required proof source.
type SandboxStrictCompositionEvidence struct {
	Kind  SandboxStrictCompositionEvidenceKind `json:"kind"`
	State SandboxStrictCompositionState        `json:"state"`
	Code  SandboxStrictCompositionCode         `json:"code,omitempty"`
}

// SandboxStrictCompositionDecision is a durable rendering of an L10 result.
// It is deliberately insufficient to recreate the opaque live attestation.
type SandboxStrictCompositionDecision struct {
	State         SandboxStrictCompositionState      `json:"state"`
	Code          SandboxStrictCompositionCode       `json:"code"`
	CompositionID string                             `json:"compositionId,omitempty"`
	ObservedAt    time.Time                          `json:"observedAt,omitempty"`
	ExpiresAt     time.Time                          `json:"expiresAt,omitempty"`
	Evidence      []SandboxStrictCompositionEvidence `json:"evidence,omitempty"`
}

// SanitizeSandboxStrictCompositionDecision returns a bounded safe copy.
func SanitizeSandboxStrictCompositionDecision(input SandboxStrictCompositionDecision) SandboxStrictCompositionDecision {
	state := sanitizeSandboxStrictCompositionState(input.State)
	code := sanitizeSandboxStrictCompositionCode(input.Code)
	compositionID := sanitizeSandboxSecurityCapabilityIdentifier(input.CompositionID)
	if state == "" || code == "" {
		return SandboxStrictCompositionDecision{
			State: SandboxStrictCompositionStateBlocked,
			Code:  SandboxStrictCompositionCodeIdentityInvalid,
		}
	}
	output := SandboxStrictCompositionDecision{
		State:         state,
		Code:          code,
		CompositionID: compositionID,
		ObservedAt:    input.ObservedAt.UTC(),
		ExpiresAt:     input.ExpiresAt.UTC(),
	}
	if output.ObservedAt.IsZero() {
		output.ObservedAt = time.Time{}
	}
	if output.ExpiresAt.IsZero() || output.ExpiresAt.Before(output.ObservedAt) {
		output.ExpiresAt = time.Time{}
	}
	for _, evidence := range input.Evidence {
		kind := sanitizeSandboxStrictCompositionEvidenceKind(evidence.Kind)
		evidenceState := sanitizeSandboxStrictCompositionState(evidence.State)
		evidenceCode := sanitizeSandboxStrictCompositionCode(evidence.Code)
		if kind == "" || evidenceState == "" {
			continue
		}
		output.Evidence = append(output.Evidence, SandboxStrictCompositionEvidence{
			Kind: kind, State: evidenceState, Code: evidenceCode,
		})
		if len(output.Evidence) == 4 {
			break
		}
	}
	return output
}

// CloneSandboxStrictCompositionDecisionPtr returns a sanitized deep copy.
func CloneSandboxStrictCompositionDecisionPtr(input *SandboxStrictCompositionDecision) *SandboxStrictCompositionDecision {
	if input == nil {
		return nil
	}
	output := SanitizeSandboxStrictCompositionDecision(*input)
	return &output
}

func sanitizeSandboxStrictCompositionState(value SandboxStrictCompositionState) SandboxStrictCompositionState {
	switch value {
	case SandboxStrictCompositionStateBlocked, SandboxStrictCompositionStateActive, SandboxStrictCompositionStateComplete:
		return value
	default:
		return ""
	}
}

func sanitizeSandboxStrictCompositionCode(value SandboxStrictCompositionCode) SandboxStrictCompositionCode {
	switch value {
	case SandboxStrictCompositionCodeReady,
		SandboxStrictCompositionCodeComplete,
		SandboxStrictCompositionCodeIdentityInvalid,
		SandboxStrictCompositionCodeIdentityMismatch,
		SandboxStrictCompositionCodeRuntimeProofMissing,
		SandboxStrictCompositionCodeRuntimeProofStale,
		SandboxStrictCompositionCodeRuntimeProofMismatch,
		SandboxStrictCompositionCodeCredentialActiveMissing,
		SandboxStrictCompositionCodeCredentialCleanupMissing,
		SandboxStrictCompositionCodeCredentialProofStale,
		SandboxStrictCompositionCodeCredentialProofMismatch,
		SandboxStrictCompositionCodeTemplateProofMissing,
		SandboxStrictCompositionCodeTemplateProofRejected,
		SandboxStrictCompositionCodeTemplateProofMismatch,
		SandboxStrictCompositionCodeWorkspaceProofMissing,
		SandboxStrictCompositionCodeWorkspaceProofStale,
		SandboxStrictCompositionCodeWorkspaceProofUnsafe,
		SandboxStrictCompositionCodeWorkspaceProofMismatch,
		SandboxStrictCompositionCodeWarningBearing,
		SandboxStrictCompositionCodeFallbackForbidden,
		SandboxStrictCompositionCodeSimulationForbidden,
		SandboxStrictCompositionCodeCleanupIncomplete,
		SandboxStrictCompositionCodeAttestationStale:
		return value
	default:
		return ""
	}
}

func sanitizeSandboxStrictCompositionEvidenceKind(value SandboxStrictCompositionEvidenceKind) SandboxStrictCompositionEvidenceKind {
	switch value {
	case SandboxStrictCompositionEvidenceRuntime,
		SandboxStrictCompositionEvidenceCredential,
		SandboxStrictCompositionEvidenceTemplate,
		SandboxStrictCompositionEvidenceWorkspace:
		return value
	default:
		return ""
	}
}
