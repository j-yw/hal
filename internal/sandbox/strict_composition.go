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

var sandboxStrictCompositionEvidenceKinds = [...]SandboxStrictCompositionEvidenceKind{
	SandboxStrictCompositionEvidenceRuntime,
	SandboxStrictCompositionEvidenceCredential,
	SandboxStrictCompositionEvidenceTemplate,
	SandboxStrictCompositionEvidenceWorkspace,
}

// SanitizeSandboxStrictCompositionDecision returns a bounded safe copy and
// fails closed when authority-shaped state is internally inconsistent.
func SanitizeSandboxStrictCompositionDecision(input SandboxStrictCompositionDecision) SandboxStrictCompositionDecision {
	state := sanitizeSandboxStrictCompositionState(input.State)
	code := sanitizeSandboxStrictCompositionCode(input.Code)
	if state == "" || code == "" {
		return invalidSandboxStrictCompositionDecision()
	}
	if state == SandboxStrictCompositionStateBlocked {
		if code == SandboxStrictCompositionCodeReady || code == SandboxStrictCompositionCodeComplete {
			return invalidSandboxStrictCompositionDecision()
		}
		return SandboxStrictCompositionDecision{State: state, Code: code}
	}

	compositionID := sanitizeSandboxSecurityCapabilityIdentifier(input.CompositionID)
	observedAt := input.ObservedAt.UTC()
	if compositionID == "" || observedAt.IsZero() {
		return invalidSandboxStrictCompositionDecision()
	}
	expiresAt := input.ExpiresAt.UTC()
	switch state {
	case SandboxStrictCompositionStateActive:
		if code != SandboxStrictCompositionCodeReady || expiresAt.IsZero() || !expiresAt.After(observedAt) {
			return invalidSandboxStrictCompositionDecision()
		}
	case SandboxStrictCompositionStateComplete:
		if code != SandboxStrictCompositionCodeComplete || !input.ExpiresAt.IsZero() {
			return invalidSandboxStrictCompositionDecision()
		}
		expiresAt = time.Time{}
	default:
		return invalidSandboxStrictCompositionDecision()
	}
	evidence, ok := sanitizeSandboxStrictCompositionEvidence(input.Evidence, state, code)
	if !ok {
		return invalidSandboxStrictCompositionDecision()
	}
	return SandboxStrictCompositionDecision{
		State: state, Code: code, CompositionID: compositionID,
		ObservedAt: observedAt, ExpiresAt: expiresAt, Evidence: evidence,
	}
}

// ProjectSandboxStrictCompositionDecision returns status-safe metadata at the
// supplied observation time. Expired or not-yet-active decisions fail closed.
func ProjectSandboxStrictCompositionDecision(input SandboxStrictCompositionDecision, now time.Time) SandboxStrictCompositionDecision {
	output := SanitizeSandboxStrictCompositionDecision(input)
	if output.State == SandboxStrictCompositionStateActive &&
		(now.IsZero() || now.Before(output.ObservedAt) || !now.Before(output.ExpiresAt)) {
		return SandboxStrictCompositionDecision{
			State: SandboxStrictCompositionStateBlocked,
			Code:  SandboxStrictCompositionCodeAttestationStale,
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

// ProjectSandboxStrictCompositionDecisionPtr returns a time-aware sanitized
// deep copy for command, status, and factory projection boundaries.
func ProjectSandboxStrictCompositionDecisionPtr(input *SandboxStrictCompositionDecision, now time.Time) *SandboxStrictCompositionDecision {
	if input == nil {
		return nil
	}
	output := ProjectSandboxStrictCompositionDecision(*input, now)
	return &output
}

func sanitizeSandboxStrictCompositionEvidence(input []SandboxStrictCompositionEvidence, state SandboxStrictCompositionState, code SandboxStrictCompositionCode) ([]SandboxStrictCompositionEvidence, bool) {
	if len(input) != len(sandboxStrictCompositionEvidenceKinds) {
		return nil, false
	}
	byKind := make(map[SandboxStrictCompositionEvidenceKind]SandboxStrictCompositionEvidence, len(input))
	for _, evidence := range input {
		kind := sanitizeSandboxStrictCompositionEvidenceKind(evidence.Kind)
		if kind == "" || evidence.State != state || evidence.Code != code {
			return nil, false
		}
		if _, exists := byKind[kind]; exists {
			return nil, false
		}
		byKind[kind] = SandboxStrictCompositionEvidence{Kind: kind, State: state, Code: code}
	}
	output := make([]SandboxStrictCompositionEvidence, 0, len(sandboxStrictCompositionEvidenceKinds))
	for _, kind := range sandboxStrictCompositionEvidenceKinds {
		evidence, exists := byKind[kind]
		if !exists {
			return nil, false
		}
		output = append(output, evidence)
	}
	return output, true
}

func invalidSandboxStrictCompositionDecision() SandboxStrictCompositionDecision {
	return SandboxStrictCompositionDecision{
		State: SandboxStrictCompositionStateBlocked,
		Code:  SandboxStrictCompositionCodeIdentityInvalid,
	}
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
