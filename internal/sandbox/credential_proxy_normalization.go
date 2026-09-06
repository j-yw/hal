package sandbox

import "strings"

// NormalizeSandboxCredentialProxyPlanMetadata returns a deterministic copy of
// credential proxy plan metadata before validation or persistence.
func NormalizeSandboxCredentialProxyPlanMetadata(plan SandboxCredentialProxyPlanMetadata) SandboxCredentialProxyPlanMetadata {
	normalized := SandboxCredentialProxyPlanMetadata{
		ID:                    strings.TrimSpace(plan.ID),
		Source:                normalizeSandboxCredentialProxySource(plan.Source),
		SecretBrokerSessionID: strings.TrimSpace(plan.SecretBrokerSessionID),
		NetworkProxySessionID: strings.TrimSpace(plan.NetworkProxySessionID),
		BindingCount:          plan.BindingCount,
		Mode:                  normalizeSandboxCredentialProxyMode(plan.Mode),
		Status:                normalizeSandboxCredentialProxyStatus(plan.Status),
	}
	if plan.PolicySnapshot != nil {
		normalized.PolicySnapshot = normalizeSandboxCredentialProxyPolicySnapshotIdentity(plan.PolicySnapshot)
	}
	return normalized
}

// NormalizeSandboxCredentialProxySessionMetadata returns a deterministic copy
// of credential proxy session metadata before validation or persistence.
func NormalizeSandboxCredentialProxySessionMetadata(session SandboxCredentialProxySessionMetadata) SandboxCredentialProxySessionMetadata {
	normalized := SandboxCredentialProxySessionMetadata{
		ID:                    strings.TrimSpace(session.ID),
		PlanID:                strings.TrimSpace(session.PlanID),
		Source:                normalizeSandboxCredentialProxySource(session.Source),
		SecretBrokerSessionID: strings.TrimSpace(session.SecretBrokerSessionID),
		NetworkProxySessionID: strings.TrimSpace(session.NetworkProxySessionID),
		Status:                normalizeSandboxCredentialProxyStatus(session.Status),
		WarningCode:           normalizeSandboxCredentialProxyWarningCode(session.WarningCode),
		ReasonCode:            normalizeSandboxCredentialProxyReasonCode(session.ReasonCode),
	}
	if session.PolicySnapshot != nil {
		normalized.PolicySnapshot = normalizeSandboxCredentialProxyPolicySnapshotIdentity(session.PolicySnapshot)
	}
	return normalized
}

// NormalizeSandboxCredentialProxyBindingMetadata returns a deterministic copy
// of credential proxy binding metadata before validation or persistence.
func NormalizeSandboxCredentialProxyBindingMetadata(binding SandboxCredentialProxyBindingMetadata) SandboxCredentialProxyBindingMetadata {
	return SandboxCredentialProxyBindingMetadata{
		ID:                  strings.TrimSpace(binding.ID),
		PlanID:              strings.TrimSpace(binding.PlanID),
		SessionID:           strings.TrimSpace(binding.SessionID),
		SecretID:            strings.TrimSpace(binding.SecretID),
		DeliveryMode:        normalizeSandboxCredentialProxyDeliveryMode(binding.DeliveryMode),
		RequestCategory:     normalizeSandboxCredentialProxyRequestCategory(binding.RequestCategory),
		DestinationCategory: normalizeSandboxNetworkPolicyDestinationCategory(binding.DestinationCategory),
		Outcome:             normalizeSandboxCredentialProxyBindingOutcome(binding.Outcome),
		Status:              normalizeSandboxCredentialProxyStatus(binding.Status),
		ReasonCode:          normalizeSandboxCredentialProxyReasonCode(binding.ReasonCode),
	}
}

// NormalizeSandboxCredentialProxyPlanMetadataRecords returns normalized copies
// of plan records while preserving nil versus explicit empty slices.
func NormalizeSandboxCredentialProxyPlanMetadataRecords(plans []SandboxCredentialProxyPlanMetadata) []SandboxCredentialProxyPlanMetadata {
	if plans == nil {
		return nil
	}
	normalized := make([]SandboxCredentialProxyPlanMetadata, len(plans))
	for i, plan := range plans {
		normalized[i] = NormalizeSandboxCredentialProxyPlanMetadata(plan)
	}
	return normalized
}

// NormalizeSandboxCredentialProxySessionMetadataRecords returns normalized
// copies of session records while preserving nil versus explicit empty slices.
func NormalizeSandboxCredentialProxySessionMetadataRecords(sessions []SandboxCredentialProxySessionMetadata) []SandboxCredentialProxySessionMetadata {
	if sessions == nil {
		return nil
	}
	normalized := make([]SandboxCredentialProxySessionMetadata, len(sessions))
	for i, session := range sessions {
		normalized[i] = NormalizeSandboxCredentialProxySessionMetadata(session)
	}
	return normalized
}

// NormalizeSandboxCredentialProxyBindingMetadataRecords returns normalized
// copies of binding records while preserving nil versus explicit empty slices.
func NormalizeSandboxCredentialProxyBindingMetadataRecords(bindings []SandboxCredentialProxyBindingMetadata) []SandboxCredentialProxyBindingMetadata {
	if bindings == nil {
		return nil
	}
	normalized := make([]SandboxCredentialProxyBindingMetadata, len(bindings))
	for i, binding := range bindings {
		normalized[i] = NormalizeSandboxCredentialProxyBindingMetadata(binding)
	}
	return normalized
}

func normalizeSandboxCredentialProxyPolicySnapshotIdentity(snapshot *SandboxNetworkPolicySnapshotIdentity) *SandboxNetworkPolicySnapshotIdentity {
	return &SandboxNetworkPolicySnapshotIdentity{
		ID:        strings.TrimSpace(snapshot.ID),
		Version:   strings.TrimSpace(snapshot.Version),
		Preset:    normalizeSandboxNetworkPolicyPreset(snapshot.Preset),
		RuleSetID: strings.TrimSpace(snapshot.RuleSetID),
	}
}

func normalizeSandboxCredentialProxySource(source SandboxCredentialProxySource) SandboxCredentialProxySource {
	return SandboxCredentialProxySource(strings.ToLower(strings.TrimSpace(string(source))))
}

func normalizeSandboxCredentialProxyMode(mode SandboxCredentialProxyMode) SandboxCredentialProxyMode {
	return SandboxCredentialProxyMode(strings.ToLower(strings.TrimSpace(string(mode))))
}

func normalizeSandboxCredentialProxyStatus(status SandboxCredentialProxyStatus) SandboxCredentialProxyStatus {
	return SandboxCredentialProxyStatus(strings.ToLower(strings.TrimSpace(string(status))))
}

func normalizeSandboxCredentialProxyBindingOutcome(outcome SandboxCredentialProxyBindingOutcome) SandboxCredentialProxyBindingOutcome {
	return SandboxCredentialProxyBindingOutcome(strings.ToLower(strings.TrimSpace(string(outcome))))
}

func normalizeSandboxCredentialProxyWarningCode(warning SandboxCredentialProxyWarningCode) SandboxCredentialProxyWarningCode {
	return SandboxCredentialProxyWarningCode(strings.ToLower(strings.TrimSpace(string(warning))))
}

func normalizeSandboxCredentialProxyReasonCode(reason SandboxCredentialProxyReasonCode) SandboxCredentialProxyReasonCode {
	return SandboxCredentialProxyReasonCode(strings.ToLower(strings.TrimSpace(string(reason))))
}

func normalizeSandboxCredentialProxyDeliveryMode(mode SandboxCredentialProxyDeliveryMode) SandboxCredentialProxyDeliveryMode {
	return SandboxCredentialProxyDeliveryMode(strings.ToLower(strings.TrimSpace(string(mode))))
}

func normalizeSandboxCredentialProxyRequestCategory(category SandboxCredentialProxyRequestCategory) SandboxCredentialProxyRequestCategory {
	return SandboxCredentialProxyRequestCategory(strings.ToLower(strings.TrimSpace(string(category))))
}
