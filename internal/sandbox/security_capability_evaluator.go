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
		if metadata, ok := sandboxSecurityCapabilityFindExplicitMetadataOnly(requested, input.Ready); ok {
			results = append(results, sandboxSecurityCapabilityMetadataOnlyEvidenceResult(metadata))
			continue
		}
		if unsupported, ok := sandboxSecurityCapabilityFindExplicitUnsupported(requested, input.Ready); ok {
			results = append(results, sandboxSecurityCapabilityUnsupportedEvidenceResult(requested, unsupported))
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
	credentialProxyHasExplicitSupport := sandboxSecurityCapabilityCredentialProxyHasExplicitSupport(input)
	if input.CredentialProxyPlan != nil && !credentialProxyHasExplicitSupport {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyCredentialProxy,
			SandboxSecurityCapabilityCredentialProxy,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		))
	}
	if input.CredentialProxySession != nil && !credentialProxyHasExplicitSupport {
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyCredentialProxy,
			SandboxSecurityCapabilityCredentialProxy,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		))
	}
	for _, binding := range input.CredentialProxyBindings {
		if sandboxSecurityCapabilityCredentialBindingHasExplicitSupport(binding, input.Ready) {
			continue
		}
		results = append(results, sandboxSecurityCapabilityMetadataOnlyResult(
			SandboxSecurityCapabilityFamilyCredentialProxy,
			SandboxSecurityCapabilityCredentialProxy,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		))
	}

	return SanitizeSandboxSecurityCapabilityReadinessOutput(SandboxSecurityCapabilityReadinessOutput{Results: results})
}

func sandboxSecurityCapabilityCredentialProxyHasExplicitSupport(input SandboxSecurityCapabilityReadinessInput) bool {
	for _, binding := range input.CredentialProxyBindings {
		if sandboxSecurityCapabilityCredentialBindingHasExplicitSupport(binding, input.Ready) {
			return true
		}
	}
	return false
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

func sandboxSecurityCapabilityCredentialBindingHasExplicitSupport(binding SandboxCredentialProxyBindingMetadata, ready []SandboxSecurityCapabilityMetadata) bool {
	binding = SanitizeSandboxCredentialProxyBindingMetadata(binding)
	if binding.ID == "" {
		return false
	}
	family, capability, mode, ok := sandboxSecurityCapabilityProjectionCredentialBindingSecretMode(string(binding.DeliveryMode))
	if !ok {
		return false
	}
	_, ok = sandboxSecurityCapabilityFindExplicitSupport(SandboxSecurityCapabilityMetadata{
		ID:         binding.ID,
		Family:     family,
		Capability: capability,
		Mode:       mode,
		Source:     SandboxSecurityCapabilitySourceRequested,
	}, ready)
	return ok
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
		if !sandboxSecurityCapabilitySameRequest(requested, candidate) &&
			!sandboxSecurityCapabilitySameProjectedEvidenceTarget(requested, candidate) {
			continue
		}
		if !sandboxSecurityCapabilityExplicitBlockerMetadata(candidate) {
			continue
		}
		return candidate, true
	}
	return SandboxSecurityCapabilityMetadata{}, false
}

func sandboxSecurityCapabilityFindExplicitMetadataOnly(requested SandboxSecurityCapabilityMetadata, ready []SandboxSecurityCapabilityMetadata) (SandboxSecurityCapabilityMetadata, bool) {
	for _, candidate := range ready {
		if !sandboxSecurityCapabilitySameRequest(requested, candidate) &&
			!sandboxSecurityCapabilitySameProjectedEvidenceTarget(requested, candidate) {
			continue
		}
		if !sandboxSecurityCapabilityExplicitMetadataOnlyMetadata(candidate) {
			continue
		}
		return candidate, true
	}
	return SandboxSecurityCapabilityMetadata{}, false
}

func sandboxSecurityCapabilityFindExplicitUnsupported(requested SandboxSecurityCapabilityMetadata, ready []SandboxSecurityCapabilityMetadata) (SandboxSecurityCapabilityMetadata, bool) {
	for _, candidate := range ready {
		if !sandboxSecurityCapabilitySameRequest(requested, candidate) &&
			!sandboxSecurityCapabilitySameProjectedEvidenceTarget(requested, candidate) {
			continue
		}
		if !sandboxSecurityCapabilityExplicitUnsupportedMetadata(candidate) {
			continue
		}
		return candidate, true
	}
	return SandboxSecurityCapabilityMetadata{}, false
}

func sandboxSecurityCapabilityBlockedResult(requested, blocker SandboxSecurityCapabilityMetadata) SandboxSecurityCapabilityReadinessResult {
	reason := sandboxSecurityCapabilityBlockedReason(blocker.ReasonCode)
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
	reason := sandboxSecurityCapabilityReadyReason(ready.ReasonCode)
	requestedContext := sandboxSecurityCapabilityReadyRequestedContext(requested, reason)
	readyContext := sandboxSecurityCapabilityReadyContext(ready, reason)
	return SandboxSecurityCapabilityReadinessResult{
		State:      SandboxSecurityCapabilityReadinessReady,
		Requested:  &requestedContext,
		Ready:      &readyContext,
		ReasonCode: reason,
	}
}

func sandboxSecurityCapabilityMetadataOnlyEvidenceResult(metadata SandboxSecurityCapabilityMetadata) SandboxSecurityCapabilityReadinessResult {
	reason := sandboxSecurityCapabilityMetadataOnlyReason(metadata.ReasonCode)
	warnings := []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability}
	context := SandboxSecurityCapabilityMetadata{
		Family:       metadata.Family,
		Capability:   metadata.Capability,
		Mode:         sandboxSecurityCapabilitySafeMode(metadata.Family, metadata.Capability, metadata.Mode),
		Source:       metadata.Source,
		Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
		ReasonCode:   reason,
		WarningCodes: append([]SandboxSecurityCapabilityWarningCode(nil), warnings...),
	}
	return SandboxSecurityCapabilityReadinessResult{
		State:        SandboxSecurityCapabilityReadinessMetadataOnly,
		Metadata:     &context,
		ReasonCode:   reason,
		WarningCodes: warnings,
	}
}

func sandboxSecurityCapabilityUnsupportedEvidenceResult(requested, unsupported SandboxSecurityCapabilityMetadata) SandboxSecurityCapabilityReadinessResult {
	reason := sandboxSecurityCapabilityUnsupportedEvidenceReason(unsupported.ReasonCode)
	warnings := sandboxSecurityCapabilityUnsupportedWarnings(reason)
	requestedContext := sandboxSecurityCapabilityUnsupportedRequestedContext(requested, reason, warnings)
	return SandboxSecurityCapabilityReadinessResult{
		State:        SandboxSecurityCapabilityReadinessUnsupported,
		Requested:    &requestedContext,
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
		if !sandboxSecurityCapabilityIDCompatible(requested.ID, candidate.ID) {
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
		sandboxSecurityCapabilityIDCompatible(requested.ID, candidate.ID) &&
		sandboxSecurityCapabilityModeCompatible(requested.Mode, candidate.Mode)
}

func sandboxSecurityCapabilitySameProjectedEvidenceTarget(requested, candidate SandboxSecurityCapabilityMetadata) bool {
	if candidate.Family != requested.Family || candidate.Capability != requested.Capability {
		return false
	}
	if !sandboxSecurityCapabilityIDCompatible(requested.ID, candidate.ID) {
		return false
	}
	switch candidate.Status {
	case SandboxSecurityCapabilityReadinessBlocked:
		return sandboxSecurityCapabilityProjectedBlockerReasonCode(candidate.ReasonCode)
	case SandboxSecurityCapabilityReadinessMetadataOnly:
		return sandboxSecurityCapabilityMetadataOnlyReasonCode(candidate.ReasonCode)
	case SandboxSecurityCapabilityReadinessUnsupported:
		return sandboxSecurityCapabilityUnsupportedEvidenceReasonCode(candidate.ReasonCode)
	default:
		return false
	}
}

func sandboxSecurityCapabilityIDCompatible(requestedID, candidateID string) bool {
	requestedID = sanitizeSandboxSecurityCapabilityIdentifier(requestedID)
	candidateID = sanitizeSandboxSecurityCapabilityIdentifier(candidateID)
	return requestedID == "" || requestedID == candidateID
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
	if !sandboxSecurityCapabilityReadyReasonCode(candidate.ReasonCode) {
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
	if !sandboxSecurityCapabilityBlockedReasonCode(candidate.ReasonCode) {
		return false
	}
	return candidate.Mode == "" || sandboxSecurityCapabilitySafeMode(candidate.Family, candidate.Capability, candidate.Mode) == candidate.Mode
}

func sandboxSecurityCapabilityExplicitMetadataOnlyMetadata(candidate SandboxSecurityCapabilityMetadata) bool {
	if candidate.Status != SandboxSecurityCapabilityReadinessMetadataOnly {
		return false
	}
	if !sandboxSecurityCapabilityEvidenceSource(candidate.Source) {
		return false
	}
	if !sandboxSecurityCapabilityKnownFamily(candidate.Family) || !sandboxSecurityCapabilityKnownCapability(candidate.Capability) {
		return false
	}
	if !sandboxSecurityCapabilityMetadataOnlyReasonCode(candidate.ReasonCode) {
		return false
	}
	return candidate.Mode == "" || sandboxSecurityCapabilitySafeMode(candidate.Family, candidate.Capability, candidate.Mode) == candidate.Mode
}

func sandboxSecurityCapabilityExplicitUnsupportedMetadata(candidate SandboxSecurityCapabilityMetadata) bool {
	if candidate.Status != SandboxSecurityCapabilityReadinessUnsupported {
		return false
	}
	if !sandboxSecurityCapabilityEvidenceSource(candidate.Source) {
		return false
	}
	if !sandboxSecurityCapabilityKnownFamily(candidate.Family) || !sandboxSecurityCapabilityKnownCapability(candidate.Capability) {
		return false
	}
	if !sandboxSecurityCapabilityUnsupportedEvidenceReasonCode(candidate.ReasonCode) {
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

func sandboxSecurityCapabilityEvidenceSource(source SandboxSecurityCapabilitySource) bool {
	switch source {
	case SandboxSecurityCapabilitySourceMetadata,
		SandboxSecurityCapabilitySourceRuntime,
		SandboxSecurityCapabilitySourceWorker:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityReadyReason(reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReasonCode {
	if sandboxSecurityCapabilityReadyReasonCode(reason) && reason != "" {
		return reason
	}
	return SandboxSecurityCapabilityReasonCapabilityConfirmed
}

func sandboxSecurityCapabilityBlockedReason(reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReasonCode {
	if sandboxSecurityCapabilityBlockedReasonCode(reason) && reason != "" {
		return reason
	}
	return SandboxSecurityCapabilityReasonCapabilityBlocked
}

func sandboxSecurityCapabilityMetadataOnlyReason(reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReasonCode {
	if sandboxSecurityCapabilityMetadataOnlyReasonCode(reason) && reason != "" {
		return reason
	}
	return SandboxSecurityCapabilityReasonMetadataOnly
}

func sandboxSecurityCapabilityUnsupportedEvidenceReason(reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReasonCode {
	if sandboxSecurityCapabilityUnsupportedEvidenceReasonCode(reason) && reason != "" {
		return reason
	}
	return SandboxSecurityCapabilityReasonCapabilityMissing
}

func sandboxSecurityCapabilityReadyReasonCode(reason SandboxSecurityCapabilityReasonCode) bool {
	switch sanitizeSandboxSecurityCapabilityReasonCodeValue(reason) {
	case "",
		SandboxSecurityCapabilityReasonCapabilityConfirmed,
		SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed,
		SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed,
		SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed,
		SandboxSecurityCapabilityReasonCredentialActivationConfirmed,
		SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed,
		SandboxSecurityCapabilityReasonSelectedTemplateTrustConfirmed:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityBlockedReasonCode(reason SandboxSecurityCapabilityReasonCode) bool {
	if reason == "" || reason == SandboxSecurityCapabilityReasonCapabilityBlocked {
		return true
	}
	return sandboxSecurityCapabilityProjectedBlockerReasonCode(reason)
}

func sandboxSecurityCapabilityProjectedBlockerReasonCode(reason SandboxSecurityCapabilityReasonCode) bool {
	switch sanitizeSandboxSecurityCapabilityReasonCodeValue(reason) {
	case SandboxSecurityCapabilityReasonMicroVMSupportMissing,
		SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree,
		SandboxSecurityCapabilityReasonNetworkEnforcementFailed,
		SandboxSecurityCapabilityReasonSelectedTemplateTrustRejected,
		SandboxSecurityCapabilityReasonSelectedTemplateProvenanceUnresolved,
		SandboxSecurityCapabilityReasonSelectedTemplateProvenanceMismatch:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityMetadataOnlyReasonCode(reason SandboxSecurityCapabilityReasonCode) bool {
	switch sanitizeSandboxSecurityCapabilityReasonCodeValue(reason) {
	case "",
		SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly,
		SandboxSecurityCapabilityReasonNetworkEnforcementBestEffort,
		SandboxSecurityCapabilityReasonNetworkEnforcementPartial,
		SandboxSecurityCapabilityReasonCredentialActivationMissing,
		SandboxSecurityCapabilityReasonTemplateLockDigestMissing,
		SandboxSecurityCapabilityReasonSelectedTemplateTrustAdvisoryOnly:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityUnsupportedEvidenceReasonCode(reason SandboxSecurityCapabilityReasonCode) bool {
	switch sanitizeSandboxSecurityCapabilityReasonCodeValue(reason) {
	case "",
		SandboxSecurityCapabilityReasonCapabilityMissing,
		SandboxSecurityCapabilityReasonModeUnsupported,
		SandboxSecurityCapabilityReasonReadinessMissing,
		SandboxSecurityCapabilityReasonWarningBearing,
		SandboxSecurityCapabilityReasonMicroVMReadinessMissing,
		SandboxSecurityCapabilityReasonWorkspaceIsolationMissing,
		SandboxSecurityCapabilityReasonNetworkEnforcementMissing,
		SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported,
		SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing,
		SandboxSecurityCapabilityReasonSelectedTemplateTrustUnavailable:
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
		SandboxSecurityCapabilityTemplateLockDigest,
		SandboxSecurityCapabilitySelectedTemplateTrust:
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
