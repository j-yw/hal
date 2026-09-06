package credentialactivation

import (
	"strings"

	"github.com/jywlabs/hal/internal/credentialdelivery"
)

var _ credentialdelivery.ActivationAdapter = (*SSHAgentHandoffAdapter)(nil)

// SSHAgentHandoffOptions configures explicit ssh_agent handoff activation from
// existing proof metadata. It intentionally carries no socket or key material.
type SSHAgentHandoffOptions struct {
	Enabled bool
}

// SSHAgentHandoffAdapter activates ssh_agent metadata only when the sanitized
// delivery plan already carries a valid safe handoff proof.
type SSHAgentHandoffAdapter struct {
	enabled bool
	calls   []credentialdelivery.ActivationRequest
}

// NewSSHAgentHandoffAdapter returns a disabled-by-default ssh_agent handoff
// adapter. Callers must opt in with Enabled.
func NewSSHAgentHandoffAdapter(options SSHAgentHandoffOptions) *SSHAgentHandoffAdapter {
	return &SSHAgentHandoffAdapter{enabled: options.Enabled}
}

// Calls returns sanitized activation requests observed by the adapter.
func (a *SSHAgentHandoffAdapter) Calls() []credentialdelivery.ActivationRequest {
	if a == nil || a.calls == nil {
		return nil
	}
	calls := make([]credentialdelivery.ActivationRequest, len(a.calls))
	for i, call := range a.calls {
		calls[i] = credentialdelivery.SanitizeActivationRequestMetadata(call)
	}
	return calls
}

// ActivateCredentialDelivery implements credentialdelivery.ActivationAdapter.
func (a *SSHAgentHandoffAdapter) ActivateCredentialDelivery(input credentialdelivery.SanitizedActivationRequest) (credentialdelivery.ActivationResult, error) {
	request := input.Request()
	if a != nil {
		a.calls = append(a.calls, request)
	}
	if request.ActivationID == "" || request.Plan.ID == "" {
		return credentialdelivery.ActivationResult{}, nil
	}
	if a == nil || !a.enabled {
		return sshAgentDisabledResult(request), nil
	}

	resolution := resolveSSHAgentHandoff(request)
	if !resolution.active {
		return sshAgentSkippedResult(request, resolution.bindings, resolution.warnings, resolution.reason), nil
	}

	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeSSHAgent},
		Bindings:       resolution.bindings,
		ProofRefs:      resolution.proofs,
		Status:         credentialdelivery.StatusActive,
		ReasonCode:     credentialdelivery.ReasonRequested,
		Warnings:       resolution.warnings,
	}), nil
}

type sshAgentHandoffResolution struct {
	bindings []credentialdelivery.BindingActivationResult
	proofs   []credentialdelivery.ActivationProofReference
	warnings []credentialdelivery.Warning
	active   bool
	reason   credentialdelivery.ReasonCode
}

func resolveSSHAgentHandoff(request credentialdelivery.ActivationRequest) sshAgentHandoffResolution {
	resolution := sshAgentHandoffResolution{
		bindings: make([]credentialdelivery.BindingActivationResult, 0, len(request.Bindings)),
		proofs:   make([]credentialdelivery.ActivationProofReference, 0, len(request.Bindings)),
	}
	for _, binding := range request.Bindings {
		if binding.DeliveryMode != credentialdelivery.ModeSSHAgent {
			resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
				BindingID:    binding.ID,
				DeliveryMode: binding.DeliveryMode,
				Status:       credentialdelivery.StatusSkipped,
				ReasonCode:   credentialdelivery.ReasonUnsupportedMode,
			})
			resolution.warnings = appendSSHAgentWarningIfMissing(resolution.warnings, credentialdelivery.Warning{
				Code:       credentialdelivery.WarningUnsupportedMode,
				ReasonCode: credentialdelivery.ReasonUnsupportedMode,
				BindingID:  binding.ID,
				Mode:       binding.DeliveryMode,
			})
			continue
		}

		reason := credentialdelivery.SSHAgentProofActivationReason(request.Plan, binding)
		if reason != credentialdelivery.ReasonRequested {
			resolution.reason = reason
			resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
				BindingID:    binding.ID,
				DeliveryMode: credentialdelivery.ModeSSHAgent,
				Status:       credentialdelivery.StatusSkipped,
				ReasonCode:   reason,
			})
			resolution.warnings = appendSSHAgentWarningIfMissing(resolution.warnings, credentialdelivery.Warning{
				Code:       credentialdelivery.WarningActivationSkipped,
				ReasonCode: reason,
				BindingID:  binding.ID,
				Mode:       credentialdelivery.ModeSSHAgent,
			})
			continue
		}

		proofID := sshAgentHandoffProofID(request.Plan, binding)
		if proofID == "" {
			resolution.reason = credentialdelivery.ReasonMissingActivationProof
			resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
				BindingID:    binding.ID,
				DeliveryMode: credentialdelivery.ModeSSHAgent,
				Status:       credentialdelivery.StatusSkipped,
				ReasonCode:   credentialdelivery.ReasonMissingActivationProof,
			})
			resolution.warnings = appendSSHAgentWarningIfMissing(resolution.warnings, credentialdelivery.Warning{
				Code:       credentialdelivery.WarningActivationSkipped,
				ReasonCode: credentialdelivery.ReasonMissingActivationProof,
				BindingID:  binding.ID,
				Mode:       credentialdelivery.ModeSSHAgent,
			})
			continue
		}
		resolution.active = true
		resolution.proofs = append(resolution.proofs, credentialdelivery.ActivationProofReference{
			ProofID:      proofID,
			BindingID:    binding.ID,
			DeliveryMode: credentialdelivery.ModeSSHAgent,
		})
		resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: credentialdelivery.ModeSSHAgent,
			Status:       credentialdelivery.StatusActive,
			ReasonCode:   credentialdelivery.ReasonRequested,
			ProofRef:     proofID,
		})
	}
	if !resolution.active && resolution.reason == "" {
		resolution.reason = credentialdelivery.ReasonMissingActivationProof
	}
	return resolution
}

func sshAgentDisabledResult(request credentialdelivery.ActivationRequest) credentialdelivery.ActivationResult {
	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Bindings:       sshAgentBindingResults(request.Bindings, credentialdelivery.StatusDisabled, credentialdelivery.ReasonDisabled),
		Status:         credentialdelivery.StatusDisabled,
		ReasonCode:     credentialdelivery.ReasonDisabled,
	})
}

func sshAgentSkippedResult(request credentialdelivery.ActivationRequest, bindings []credentialdelivery.BindingActivationResult, warnings []credentialdelivery.Warning, reason credentialdelivery.ReasonCode) credentialdelivery.ActivationResult {
	if reason == "" {
		reason = credentialdelivery.ReasonMissingActivationProof
	}
	if len(bindings) == 0 {
		bindings = sshAgentBindingResults(request.Bindings, credentialdelivery.StatusSkipped, reason)
	}
	if len(warnings) == 0 {
		warnings = sshAgentActivationWarnings(request.Bindings, reason)
	}
	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Bindings:       bindings,
		Status:         credentialdelivery.StatusSkipped,
		ReasonCode:     reason,
		Warnings:       warnings,
	})
}

func sshAgentBindingResults(bindings []credentialdelivery.Binding, status credentialdelivery.Status, reason credentialdelivery.ReasonCode) []credentialdelivery.BindingActivationResult {
	if bindings == nil {
		return nil
	}
	out := make([]credentialdelivery.BindingActivationResult, 0, len(bindings))
	for _, binding := range credentialdelivery.SanitizeBindingMetadataRecords(bindings) {
		out = append(out, credentialdelivery.BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: binding.DeliveryMode,
			Status:       status,
			ReasonCode:   reason,
		})
	}
	return out
}

func sshAgentActivationWarnings(bindings []credentialdelivery.Binding, reason credentialdelivery.ReasonCode) []credentialdelivery.Warning {
	if len(bindings) == 0 {
		return nil
	}
	warnings := make([]credentialdelivery.Warning, 0, len(bindings))
	for _, binding := range credentialdelivery.SanitizeBindingMetadataRecords(bindings) {
		if binding.DeliveryMode != credentialdelivery.ModeSSHAgent {
			continue
		}
		warnings = appendSSHAgentWarningIfMissing(warnings, credentialdelivery.Warning{
			Code:       credentialdelivery.WarningActivationSkipped,
			ReasonCode: reason,
			BindingID:  binding.ID,
			Mode:       credentialdelivery.ModeSSHAgent,
		})
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

func appendSSHAgentWarningIfMissing(warnings []credentialdelivery.Warning, warning credentialdelivery.Warning) []credentialdelivery.Warning {
	for _, existing := range credentialdelivery.SanitizeWarningMetadataRecords(warnings) {
		if existing.Code == warning.Code && existing.ReasonCode == warning.ReasonCode && existing.Mode == warning.Mode && existing.BindingID == warning.BindingID {
			return warnings
		}
	}
	return append(warnings, warning)
}

func sshAgentHandoffProofID(plan credentialdelivery.Plan, binding credentialdelivery.Binding) string {
	proof := credentialdelivery.SanitizeSSHAgentProofMetadataPtr(plan.SSHAgentProof)
	if proof == nil || proof.BindingID != binding.ID {
		return ""
	}
	return sshAgentSafeIdentifier(proof.HandoffID)
}

func sshAgentSafeIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return ""
		}
	}
	if sshAgentIdentifierLooksUnsafe(value) {
		return ""
	}
	return value
}

func sshAgentIdentifierLooksUnsafe(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"ghp_",
		"github_pat_",
		"sk-",
		"authorization",
		"bearer",
		"token",
		"password",
		"passwd",
		"api_key",
		"api-key",
		"apikey",
		"access_key",
		"access-key",
		"private_key",
		"private-key",
		"secretvalue",
		"secret_value",
		"secret-value",
		"credentialvalue",
		"credential_value",
		"credential-value",
		"providercredential",
		"provider_credential",
		"provider-credential",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
