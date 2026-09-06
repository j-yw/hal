package credentialdelivery

import "github.com/jywlabs/hal/internal/sandbox"

// StatusMetadataFromPlan returns a compact durable summary of a planned
// credential delivery request. Plan-only summaries intentionally never carry
// active modes; active delivery is exposed only from successful activation.
func StatusMetadataFromPlan(plan Plan) StatusMetadata {
	sanitized := SanitizePlanMetadata(plan)
	if sanitized.ID == "" {
		return StatusMetadata{}
	}
	return SanitizeStatusMetadata(StatusMetadata{
		ID:             sanitized.ID,
		RequestID:      sanitized.RequestID,
		PlanID:         sanitized.ID,
		RequestedModes: sanitized.RequestedModes,
		Status:         sanitized.Status,
		WarningCount:   len(sanitized.Warnings),
		ErrorCount:     len(sanitized.Errors),
	})
}

// StatusMetadataFromActivation returns a compact durable activation summary.
// Active modes are projected only when the sanitized activation is active.
func StatusMetadataFromActivation(plan Plan, activation ActivationResult) StatusMetadata {
	sanitizedPlan := SanitizePlanMetadata(plan)
	sanitizedActivation := SanitizeActivationResultMetadata(activation)
	if sanitizedActivation.ID == "" {
		return StatusMetadataFromPlan(sanitizedPlan)
	}
	status := StatusMetadata{
		ID:             sanitizedActivation.ID,
		RequestID:      sanitizedPlan.RequestID,
		PlanID:         sanitizedActivation.PlanID,
		ActivationID:   sanitizedActivation.ID,
		RequestedModes: sanitizedActivation.RequestedModes,
		Status:         sanitizedActivation.Status,
		ReasonCode:     activationStatusReason(sanitizedActivation),
		WarningCount:   len(sanitizedActivation.Warnings),
		ErrorCount:     activationFailureCount(sanitizedActivation),
	}
	if status.RequestedModes == nil {
		status.RequestedModes = sanitizedPlan.RequestedModes
	}
	if status.PlanID == "" {
		status.PlanID = sanitizedPlan.ID
	}
	activeProofs := secureActiveStatusProofSummaries(sanitizedActivation)
	activeModes := secureActiveStatusProofModes(activeProofs)
	if sanitizedActivation.Status == StatusActive && len(activeModes) == 0 {
		status.Status = StatusSkipped
		if status.ReasonCode == ReasonRequested {
			status.ReasonCode = secureActivationMissingProofReason(sanitizedActivation)
		}
	}
	if status.Status == StatusActive {
		status.ActiveModes = activeModes
		status.ActiveProofs = activeProofs
	}
	return SanitizeStatusMetadata(status)
}

func activationFailureCount(activation ActivationResult) int {
	if activation.Status == StatusFailed {
		return 1
	}
	return 0
}

func activationStatusReason(activation ActivationResult) ReasonCode {
	if activation.ReasonCode != "" {
		return activation.ReasonCode
	}
	if len(activation.Warnings) > 0 {
		return activation.Warnings[0].ReasonCode
	}
	return ReasonRequested
}

func secureActiveStatusModes(modes []Mode) []Mode {
	if modes == nil {
		return nil
	}
	active := newPlanModeSet()
	for _, mode := range modes {
		mode = normalizeMode(mode)
		if mode == ModeEnv || mode == ModeLegacyAuthSync {
			continue
		}
		active.add(mode)
	}
	return active.ordered()
}

func secureActiveStatusProofSummaries(activation ActivationResult) []sandbox.SandboxCredentialDeliveryProofSummary {
	if activation.Status != StatusActive || activation.ID == "" {
		return nil
	}
	activeBindings := secureActiveStatusProofBindings(activation)
	if len(activeBindings) == 0 {
		return nil
	}
	proofs := make([]sandbox.SandboxCredentialDeliveryProofSummary, 0, len(activation.ProofRefs))
	for _, proof := range activation.ProofRefs {
		binding, ok := activeBindings[proof.ProofID]
		if !ok || binding.DeliveryMode != proof.DeliveryMode {
			continue
		}
		if proof.BindingID != "" && proof.BindingID != binding.BindingID {
			continue
		}
		source := secureActiveStatusProofSource(proof.DeliveryMode)
		if source == "" {
			continue
		}
		proofs = append(proofs, sandbox.SandboxCredentialDeliveryProofSummary{
			ProofID:      proof.ProofID,
			BindingID:    binding.BindingID,
			DeliveryMode: string(proof.DeliveryMode),
			Status:       string(StatusActive),
			Source:       source,
		})
	}
	return sanitizeStatusActiveProofSummaries(activation.ID, activation.PlanID, activation.ID, proofs)
}

func secureActiveStatusProofBindings(activation ActivationResult) map[string]BindingActivationResult {
	if len(activation.Bindings) == 0 {
		return nil
	}
	bindings := make(map[string]BindingActivationResult, len(activation.Bindings))
	for _, binding := range activation.Bindings {
		if binding.Status != StatusActive || binding.ProofRef == "" {
			continue
		}
		if secureActiveStatusProofSource(binding.DeliveryMode) == "" {
			continue
		}
		bindings[binding.ProofRef] = binding
	}
	return bindings
}

func secureActiveStatusProofModes(proofs []sandbox.SandboxCredentialDeliveryProofSummary) []Mode {
	if len(proofs) == 0 {
		return nil
	}
	active := newPlanModeSet()
	for _, proof := range proofs {
		active.add(Mode(proof.DeliveryMode))
	}
	return active.ordered()
}

func secureActiveStatusProofSource(mode Mode) string {
	switch mode {
	case ModeHTTPProxy:
		return "credential_proxy"
	case ModeSSHAgent:
		return "handoff"
	case ModeFileTmpfs:
		return "simulation"
	default:
		return ""
	}
}

func secureActivationMissingProofReason(activation ActivationResult) ReasonCode {
	if activation.ReasonCode == ReasonCompatibilityMode {
		return ReasonCompatibilityMode
	}
	for _, warning := range SanitizeWarningMetadataRecords(activation.Warnings) {
		if warning.ReasonCode == ReasonCompatibilityMode {
			return ReasonCompatibilityMode
		}
	}
	return ReasonMissingActivationProof
}
