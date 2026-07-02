package sandbox

// EvaluateSandboxSecurityCapabilityReadiness classifies safe sandbox metadata
// without treating durable records as proof of runtime support.
func EvaluateSandboxSecurityCapabilityReadiness(input SandboxSecurityCapabilityReadinessInput) SandboxSecurityCapabilityReadinessOutput {
	var results []SandboxSecurityCapabilityReadinessResult

	for _, requested := range input.Requested {
		if !sandboxSecurityCapabilityHasCompatibleSupport(requested, input.Ready) {
			results = append(results, sandboxSecurityCapabilityUnsupportedResult(requested, input.Ready))
		}
	}

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

func sandboxSecurityCapabilityHasCompatibleSupport(requested SandboxSecurityCapabilityMetadata, ready []SandboxSecurityCapabilityMetadata) bool {
	for _, candidate := range ready {
		if !sandboxSecurityCapabilitySameRequest(requested, candidate) {
			continue
		}
		if !sandboxSecurityCapabilityExplicitSupportSource(candidate.Source) {
			continue
		}
		switch candidate.Status {
		case "", SandboxSecurityCapabilityReadinessReady:
			return true
		}
	}
	return false
}

func sandboxSecurityCapabilityUnsupportedResult(requested SandboxSecurityCapabilityMetadata, ready []SandboxSecurityCapabilityMetadata) SandboxSecurityCapabilityReadinessResult {
	reason := sandboxSecurityCapabilityUnsupportedReason(requested, ready)
	warnings := sandboxSecurityCapabilityUnsupportedWarnings(reason)
	requestedContext := sandboxSecurityCapabilityUnsupportedRequestedContext(requested, reason, warnings)
	return SandboxSecurityCapabilityReadinessResult{
		State:        SandboxSecurityCapabilityReadinessUnsupported,
		Requested:    &requestedContext,
		ReasonCode:   reason,
		WarningCodes: warnings,
	}
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

func sandboxSecurityCapabilityUnsupportedReason(requested SandboxSecurityCapabilityMetadata, ready []SandboxSecurityCapabilityMetadata) SandboxSecurityCapabilityReasonCode {
	for _, candidate := range ready {
		if candidate.Family != requested.Family || candidate.Capability != requested.Capability {
			continue
		}
		if sandboxSecurityCapabilityModeCompatible(requested.Mode, candidate.Mode) {
			continue
		}
		return SandboxSecurityCapabilityReasonModeUnsupported
	}
	return SandboxSecurityCapabilityReasonCapabilityMissing
}

func sandboxSecurityCapabilityUnsupportedWarnings(reason SandboxSecurityCapabilityReasonCode) []SandboxSecurityCapabilityWarningCode {
	if reason == SandboxSecurityCapabilityReasonModeUnsupported {
		return []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningUnsupportedMode}
	}
	return nil
}

func sandboxSecurityCapabilityUnsupportedRequestedContext(requested SandboxSecurityCapabilityMetadata, reason SandboxSecurityCapabilityReasonCode, warnings []SandboxSecurityCapabilityWarningCode) SandboxSecurityCapabilityMetadata {
	requestedContext := SandboxSecurityCapabilityMetadata{
		Family:       requested.Family,
		Capability:   requested.Capability,
		Mode:         sandboxSecurityCapabilitySafeMode(requested.Family, requested.Capability, requested.Mode),
		Source:       SandboxSecurityCapabilitySourceRequested,
		Status:       SandboxSecurityCapabilityReadinessUnsupported,
		ReasonCode:   reason,
		WarningCodes: append([]SandboxSecurityCapabilityWarningCode(nil), warnings...),
	}
	return requestedContext
}

func sandboxSecurityCapabilitySameRequest(requested, candidate SandboxSecurityCapabilityMetadata) bool {
	return candidate.Family == requested.Family &&
		candidate.Capability == requested.Capability &&
		sandboxSecurityCapabilityModeCompatible(requested.Mode, candidate.Mode)
}

func sandboxSecurityCapabilityModeCompatible(requestedMode, candidateMode string) bool {
	return requestedMode == "" || requestedMode == candidateMode
}

func sandboxSecurityCapabilityExplicitSupportSource(source SandboxSecurityCapabilitySource) bool {
	switch source {
	case SandboxSecurityCapabilitySourceRuntime, SandboxSecurityCapabilitySourceWorker:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilitySafeMode(family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, mode string) string {
	switch family {
	case SandboxSecurityCapabilityFamilyNetworkPolicy, SandboxSecurityCapabilityFamilyNetworkProxy:
		return sandboxSecurityCapabilitySafeNetworkMode(mode)
	case SandboxSecurityCapabilityFamilyCredentialProxy:
		if capability == SandboxSecurityCapabilityCredentialProxy {
			return sandboxSecurityCapabilitySafeCredentialProxyMode(mode)
		}
	case SandboxSecurityCapabilityFamilySecretDelivery:
		return sandboxSecurityCapabilitySafeSecretMode(mode)
	}
	return ""
}

func sandboxSecurityCapabilitySafeNetworkMode(mode string) string {
	switch mode {
	case SandboxNetworkEnforcementModeProxy,
		SandboxNetworkEnforcementModeFirewall,
		SandboxNetworkEnforcementModeRuntime,
		SandboxNetworkEnforcementModeProxyFirewall:
		return mode
	default:
		return ""
	}
}

func sandboxSecurityCapabilitySafeCredentialProxyMode(mode string) string {
	switch mode {
	case string(SandboxCredentialProxyModeMetadataOnly),
		string(SandboxCredentialProxyModeSecretBrokerReference),
		string(SandboxCredentialProxyModeNetworkProxyReference),
		string(SandboxCredentialProxyModeBrokeredNetworkReference):
		return mode
	default:
		return sandboxSecurityCapabilitySafeSecretMode(mode)
	}
}

func sandboxSecurityCapabilitySafeSecretMode(mode string) string {
	switch mode {
	case SandboxSecretModeEnv,
		SandboxSecretModeFileTmpfs,
		SandboxSecretModeSSHAgent,
		SandboxSecretModeHTTPProxy,
		SandboxSecretModeLegacyAuthSync:
		return mode
	default:
		return ""
	}
}
