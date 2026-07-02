package sandbox

// EvaluateSandboxSecurityCapabilityReadiness classifies safe sandbox metadata
// without treating durable records as proof of runtime support.
func EvaluateSandboxSecurityCapabilityReadiness(input SandboxSecurityCapabilityReadinessInput) SandboxSecurityCapabilityReadinessOutput {
	var results []SandboxSecurityCapabilityReadinessResult

	if input.NetworkProxySession != nil {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyNetworkProxy,
			SandboxSecurityCapabilityNetworkProxyEnforcement,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		))
	}
	for range input.NetworkPolicyDecisionLogs {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkDenyByDefault,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		))
	}
	if input.CredentialProxyPlan != nil {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyCredentialProxy,
			SandboxSecurityCapabilityCredentialProxy,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		))
	}
	if input.CredentialProxySession != nil {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyCredentialProxy,
			SandboxSecurityCapabilityCredentialProxy,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		))
	}
	for range input.CredentialProxyBindings {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyCredentialProxy,
			SandboxSecurityCapabilityCredentialProxy,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		))
	}

	return SandboxSecurityCapabilityReadinessOutput{Results: results}
}

func sandboxSecurityCapabilityMetadataOnlyResult(family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReadinessResult {
	warnings := []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability}
	metadata := SandboxSecurityCapabilityMetadata{
		Family:       family,
		Capability:   capability,
		Source:       SandboxSecurityCapabilitySourceMetadata,
		Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
		ReasonCode:   reason,
		WarningCodes: append([]SandboxSecurityCapabilityWarningCode(nil), warnings...),
	}
	return SandboxSecurityCapabilityReadinessResult{
		State:        SandboxSecurityCapabilityReadinessMetadataOnly,
		Metadata:     &metadata,
		ReasonCode:   reason,
		WarningCodes: warnings,
	}
}
