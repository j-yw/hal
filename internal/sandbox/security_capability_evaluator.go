package sandbox

import "strings"

// EvaluateSandboxSecurityCapabilityReadiness classifies safe sandbox metadata
// without treating durable records as proof of runtime support.
func EvaluateSandboxSecurityCapabilityReadiness(input SandboxSecurityCapabilityReadinessInput) SandboxSecurityCapabilityReadinessOutput {
	input = SanitizeSandboxSecurityCapabilityReadinessInput(input)
	var results []SandboxSecurityCapabilityReadinessResult

	for _, requested := range input.Requested {
		if blocker, ok := sandboxSecurityCapabilityFindExplicitBlocker(requested, input.Ready); ok {
			results = append(results, sandboxSecurityCapabilityBlockedResult(requested, blocker))
			continue
		}
		if ready, ok := sandboxSecurityCapabilityFindExplicitSupport(requested, input.Ready); ok {
			results = append(results, sandboxSecurityCapabilityReadyResult(requested, ready))
			continue
		}
		results = append(results, sandboxSecurityCapabilityUnsupportedResult(requested, input.Ready))
	}

	for _, posture := range input.WorkerPostures {
		results = append(results, sandboxSecurityCapabilityWorkerPostureResults(posture)...)
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

	return SanitizeSandboxSecurityCapabilityReadinessOutput(SandboxSecurityCapabilityReadinessOutput{Results: results})
}

func sandboxSecurityCapabilityWorkerPostureResults(posture SandboxSecurityCapabilityWorkerPostureMetadata) []SandboxSecurityCapabilityReadinessResult {
	var results []SandboxSecurityCapabilityReadinessResult
	if sandboxSecurityCapabilityWorkerNetworkPosturePresent(posture) {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkDenyByDefault,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		))
	}
	switch strings.TrimSpace(posture.NetworkEnforcement) {
	case SandboxNetworkEnforcementModeProxy:
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyNetworkProxy,
			SandboxSecurityCapabilityNetworkProxyEnforcement,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		))
	case SandboxNetworkEnforcementModeFirewall:
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkFirewallEnforcement,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		))
	case SandboxNetworkEnforcementModeRuntime:
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkRuntimeEnforcement,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		))
	case SandboxNetworkEnforcementModeProxyFirewall:
		results = append(results,
			sandboxSecurityCapabilityMetadataOnlyResult(
				SandboxSecurityCapabilityFamilyNetworkProxy,
				SandboxSecurityCapabilityNetworkProxyEnforcement,
				SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
			),
			sandboxSecurityCapabilityMetadataOnlyResult(
				SandboxSecurityCapabilityFamilyNetworkPolicy,
				SandboxSecurityCapabilityNetworkFirewallEnforcement,
				SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
			),
		)
	}
	if posture.CredentialProxyMode {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyCredentialProxy,
			SandboxSecurityCapabilityCredentialProxy,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		))
	}
	for _, mode := range posture.CredentialModes {
		switch strings.TrimSpace(mode) {
		case SandboxSecretModeEnv:
			results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
				SandboxSecurityCapabilityFamilySecretDelivery,
				SandboxSecurityCapabilitySecretEnv,
				SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
			))
		case SandboxSecretModeFileTmpfs:
			results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
				SandboxSecurityCapabilityFamilySecretDelivery,
				SandboxSecurityCapabilitySecretFileTmpfs,
				SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
			))
		case SandboxSecretModeSSHAgent:
			results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
				SandboxSecurityCapabilityFamilySecretDelivery,
				SandboxSecurityCapabilitySecretSSHAgent,
				SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
			))
		case SandboxSecretModeHTTPProxy:
			results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
				SandboxSecurityCapabilityFamilySecretDelivery,
				SandboxSecurityCapabilitySecretHTTPProxy,
				SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
			))
		}
	}
	if strings.TrimSpace(posture.RuntimeDriver) == SandboxRuntimeDriverMicroVM ||
		strings.TrimSpace(posture.IsolationLevel) == SandboxIsolationLevelVM {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyIsolation,
			SandboxSecurityCapabilityIsolationMicroVM,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		))
	}
	return results
}

func sandboxSecurityCapabilityWorkerNetworkPosturePresent(posture SandboxSecurityCapabilityWorkerPostureMetadata) bool {
	switch strings.TrimSpace(posture.NetworkPolicy) {
	case SandboxNetworkPolicyDenyByDefault, SandboxNetworkPolicyBestEffort:
		return true
	}
	switch strings.TrimSpace(posture.NetworkEnforcement) {
	case SandboxNetworkEnforcementModeNone,
		SandboxNetworkEnforcementModeBestEffort,
		SandboxNetworkEnforcementModeProxy,
		SandboxNetworkEnforcementModeFirewall,
		SandboxNetworkEnforcementModeRuntime,
		SandboxNetworkEnforcementModeProxyFirewall:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityFindExplicitSupport(requested SandboxSecurityCapabilityMetadata, ready []SandboxSecurityCapabilityMetadata) (SandboxSecurityCapabilityMetadata, bool) {
	for _, candidate := range ready {
		if !sandboxSecurityCapabilitySameRequest(requested, candidate) {
			continue
		}
		if !sandboxSecurityCapabilityExplicitReadyMetadata(candidate) {
			continue
		}
		return candidate, true
	}
	return SandboxSecurityCapabilityMetadata{}, false
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

func sandboxSecurityCapabilityReadyResult(requested, ready SandboxSecurityCapabilityMetadata) SandboxSecurityCapabilityReadinessResult {
	reason := SandboxSecurityCapabilityReasonCapabilityConfirmed
	requestedContext := sandboxSecurityCapabilityReadyRequestedContext(requested, reason)
	readyContext := sandboxSecurityCapabilityReadyContext(ready, reason)
	return SandboxSecurityCapabilityReadinessResult{
		State:      SandboxSecurityCapabilityReadinessReady,
		Requested:  &requestedContext,
		Ready:      &readyContext,
		ReasonCode: reason,
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
		if !sandboxSecurityCapabilityExplicitSupportOrBlockerMetadata(candidate) {
			continue
		}
		if sandboxSecurityCapabilityModeCompatible(requested.Mode, candidate.Mode) {
			continue
		}
		return SandboxSecurityCapabilityReasonModeUnsupported
	}
	return SandboxSecurityCapabilityReasonCapabilityMissing
}

func sandboxSecurityCapabilityExplicitSupportOrBlockerMetadata(candidate SandboxSecurityCapabilityMetadata) bool {
	return sandboxSecurityCapabilityExplicitReadyMetadata(candidate) ||
		sandboxSecurityCapabilityExplicitBlockerMetadata(candidate)
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

func sandboxSecurityCapabilityReadyRequestedContext(requested SandboxSecurityCapabilityMetadata, reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityMetadata {
	return SandboxSecurityCapabilityMetadata{
		Family:     requested.Family,
		Capability: requested.Capability,
		Mode:       sandboxSecurityCapabilitySafeMode(requested.Family, requested.Capability, requested.Mode),
		Source:     SandboxSecurityCapabilitySourceRequested,
		Status:     SandboxSecurityCapabilityReadinessReady,
		ReasonCode: reason,
	}
}

func sandboxSecurityCapabilityReadyContext(ready SandboxSecurityCapabilityMetadata, reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityMetadata {
	return SandboxSecurityCapabilityMetadata{
		Family:     ready.Family,
		Capability: ready.Capability,
		Mode:       sandboxSecurityCapabilitySafeMode(ready.Family, ready.Capability, ready.Mode),
		Source:     ready.Source,
		Status:     SandboxSecurityCapabilityReadinessReady,
		ReasonCode: reason,
	}
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
	requestedMode = strings.ToLower(strings.TrimSpace(requestedMode))
	candidateMode = strings.ToLower(strings.TrimSpace(candidateMode))
	return requestedMode == "" || requestedMode == candidateMode
}

func sandboxSecurityCapabilityExplicitReadyMetadata(candidate SandboxSecurityCapabilityMetadata) bool {
	if candidate.Status != SandboxSecurityCapabilityReadinessReady {
		return false
	}
	if !sandboxSecurityCapabilityExplicitSupportSource(candidate.Source) {
		return false
	}
	if !sandboxSecurityCapabilityKnownFamily(candidate.Family) || !sandboxSecurityCapabilityKnownCapability(candidate.Capability) {
		return false
	}
	if candidate.ReasonCode != "" && candidate.ReasonCode != SandboxSecurityCapabilityReasonCapabilityConfirmed {
		return false
	}
	return candidate.Mode == "" || sandboxSecurityCapabilitySafeMode(candidate.Family, candidate.Capability, candidate.Mode) == candidate.Mode
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
		SandboxSecurityCapabilityFamilyIsolation,
		SandboxSecurityCapabilityFamilyWorkspace,
		SandboxSecurityCapabilityFamilyTemplate:
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
		SandboxSecurityCapabilityIsolationMicroVM,
		SandboxSecurityCapabilityIsolatedWorkspace,
		SandboxSecurityCapabilityDirectHostWorktree,
		SandboxSecurityCapabilityTemplateLockDigest:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilitySafeMode(family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch family {
	case SandboxSecurityCapabilityFamilyNetworkPolicy, SandboxSecurityCapabilityFamilyNetworkProxy:
		return sandboxSecurityCapabilitySafeNetworkMode(capability, mode)
	case SandboxSecurityCapabilityFamilyCredentialProxy:
		if capability == SandboxSecurityCapabilityCredentialProxy {
			return sandboxSecurityCapabilitySafeCredentialProxyMode(mode)
		}
	case SandboxSecurityCapabilityFamilySecretDelivery:
		return sandboxSecurityCapabilitySafeSecretMode(mode)
	}
	return ""
}

func sandboxSecurityCapabilitySafeNetworkMode(capability SandboxSecurityCapabilityName, mode string) string {
	switch capability {
	case SandboxSecurityCapabilityNetworkProxyEnforcement:
		if mode == SandboxNetworkEnforcementModeProxy {
			return mode
		}
	case SandboxSecurityCapabilityNetworkFirewallEnforcement:
		if mode == SandboxNetworkEnforcementModeFirewall {
			return mode
		}
	case SandboxSecurityCapabilityNetworkRuntimeEnforcement:
		if mode == SandboxNetworkEnforcementModeRuntime {
			return mode
		}
	case SandboxSecurityCapabilityNetworkDenyByDefault:
		switch mode {
		case SandboxNetworkEnforcementModeProxy,
			SandboxNetworkEnforcementModeFirewall,
			SandboxNetworkEnforcementModeRuntime,
			SandboxNetworkEnforcementModeProxyFirewall:
			return mode
		}
	default:
		return ""
	}
	return ""
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
