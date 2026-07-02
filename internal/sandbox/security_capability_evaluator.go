package sandbox

// EvaluateSandboxSecurityCapabilityReadiness classifies safe sandbox metadata
// without treating durable records as proof of runtime support.
func EvaluateSandboxSecurityCapabilityReadiness(input SandboxSecurityCapabilityReadinessInput) SandboxSecurityCapabilityReadinessOutput {
	var results []SandboxSecurityCapabilityReadinessResult

	for _, requested := range input.Requested {
		if blocker, ok := sandboxSecurityCapabilityFindExplicitBlocker(requested, input.Ready); ok {
			results = append(results, sandboxSecurityCapabilityBlockedResult(requested, blocker))
			continue
		}
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

func sandboxSecurityCapabilityFindExplicitBlocker(requested SandboxSecurityCapabilityMetadata, ready []SandboxSecurityCapabilityMetadata) (SandboxSecurityCapabilityMetadata, bool) {
	for _, candidate := range ready {
		if !sandboxSecurityCapabilitySameRequest(requested, candidate) {
			continue
		}
		if !sandboxSecurityCapabilityExplicitBlockerMetadata(candidate) {
			continue
		}
		return candidate, true
	}
	return SandboxSecurityCapabilityMetadata{}, false
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

func sandboxSecurityCapabilityBlockedResult(requested, blocker SandboxSecurityCapabilityMetadata) SandboxSecurityCapabilityReadinessResult {
	reason := SandboxSecurityCapabilityReasonCapabilityBlocked
	warnings := sandboxSecurityCapabilityBlockedWarnings(blocker.WarningCodes)
	requestedContext := sandboxSecurityCapabilityBlockedRequestedContext(requested, reason, warnings)
	blockerContext := sandboxSecurityCapabilityBlockedReadyContext(blocker, reason, warnings)
	return SandboxSecurityCapabilityReadinessResult{
		State:        SandboxSecurityCapabilityReadinessBlocked,
		Requested:    &requestedContext,
		Ready:        &blockerContext,
		ReasonCode:   reason,
		WarningCodes: warnings,
	}
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

func sandboxSecurityCapabilityBlockedWarnings(warnings []SandboxSecurityCapabilityWarningCode) []SandboxSecurityCapabilityWarningCode {
	for _, warning := range warnings {
		if warning == SandboxSecurityCapabilityWarningBlockedByPolicy {
			return []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy}
		}
	}
	return nil
}

func sandboxSecurityCapabilityBlockedRequestedContext(requested SandboxSecurityCapabilityMetadata, reason SandboxSecurityCapabilityReasonCode, warnings []SandboxSecurityCapabilityWarningCode) SandboxSecurityCapabilityMetadata {
	return SandboxSecurityCapabilityMetadata{
		Family:       requested.Family,
		Capability:   requested.Capability,
		Mode:         sandboxSecurityCapabilitySafeMode(requested.Family, requested.Capability, requested.Mode),
		Source:       SandboxSecurityCapabilitySourceRequested,
		Status:       SandboxSecurityCapabilityReadinessBlocked,
		ReasonCode:   reason,
		WarningCodes: append([]SandboxSecurityCapabilityWarningCode(nil), warnings...),
	}
}

func sandboxSecurityCapabilityBlockedReadyContext(blocker SandboxSecurityCapabilityMetadata, reason SandboxSecurityCapabilityReasonCode, warnings []SandboxSecurityCapabilityWarningCode) SandboxSecurityCapabilityMetadata {
	return SandboxSecurityCapabilityMetadata{
		Family:       blocker.Family,
		Capability:   blocker.Capability,
		Mode:         sandboxSecurityCapabilitySafeMode(blocker.Family, blocker.Capability, blocker.Mode),
		Source:       blocker.Source,
		Status:       SandboxSecurityCapabilityReadinessBlocked,
		ReasonCode:   reason,
		WarningCodes: append([]SandboxSecurityCapabilityWarningCode(nil), warnings...),
	}
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

func sandboxSecurityCapabilityExplicitBlockerMetadata(candidate SandboxSecurityCapabilityMetadata) bool {
	if candidate.Status != SandboxSecurityCapabilityReadinessBlocked {
		return false
	}
	if !sandboxSecurityCapabilityExplicitSupportSource(candidate.Source) {
		return false
	}
	if !sandboxSecurityCapabilityKnownFamily(candidate.Family) || !sandboxSecurityCapabilityKnownCapability(candidate.Capability) {
		return false
	}
	if candidate.ReasonCode != "" && candidate.ReasonCode != SandboxSecurityCapabilityReasonCapabilityBlocked {
		return false
	}
	return candidate.Mode == "" || sandboxSecurityCapabilitySafeMode(candidate.Family, candidate.Capability, candidate.Mode) == candidate.Mode
}

func sandboxSecurityCapabilityExplicitSupportSource(source SandboxSecurityCapabilitySource) bool {
	switch source {
	case SandboxSecurityCapabilitySourceRuntime, SandboxSecurityCapabilitySourceWorker:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityKnownFamily(family SandboxSecurityCapabilityFamily) bool {
	switch family {
	case SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityFamilyNetworkProxy,
		SandboxSecurityCapabilityFamilyCredentialProxy,
		SandboxSecurityCapabilityFamilySecretDelivery,
		SandboxSecurityCapabilityFamilyIsolation:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityKnownCapability(capability SandboxSecurityCapabilityName) bool {
	switch capability {
	case SandboxSecurityCapabilityNetworkDenyByDefault,
		SandboxSecurityCapabilityNetworkProxyEnforcement,
		SandboxSecurityCapabilityNetworkFirewallEnforcement,
		SandboxSecurityCapabilityNetworkRuntimeEnforcement,
		SandboxSecurityCapabilityCredentialProxy,
		SandboxSecurityCapabilitySecretEnv,
		SandboxSecurityCapabilitySecretFileTmpfs,
		SandboxSecurityCapabilitySecretSSHAgent,
		SandboxSecurityCapabilitySecretHTTPProxy,
		SandboxSecurityCapabilityIsolationMicroVM:
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
