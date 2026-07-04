package sandbox

// ProjectSandboxSecurityCapabilityReadinessInput maps existing redaction-safe
// sandbox security summaries into readiness evaluator input.
func ProjectSandboxSecurityCapabilityReadinessInput(security *SandboxSecurity) SandboxSecurityCapabilityReadinessInput {
	if security == nil {
		return SandboxSecurityCapabilityReadinessInput{}
	}
	input := SandboxSecurityCapabilityReadinessInput{}
	input.Requested = sandboxSecurityCapabilityProjectionRequestedNetwork(input.Requested, security.Network)
	input.Ready = sandboxSecurityCapabilityProjectionMetadataOnlyNetwork(input.Ready, security.Network)
	input.Requested = sandboxSecurityCapabilityProjectionRequestedSecrets(input.Requested, security.Secrets)
	input.Ready = sandboxSecurityCapabilityProjectionMetadataOnlySecrets(input.Ready, security.Secrets)
	return SanitizeSandboxSecurityCapabilityReadinessInput(input)
}

// SandboxWorkerRuntimeCapabilityReadinessProjection carries durable
// worker/runtime posture labels into readiness input.
type SandboxWorkerRuntimeCapabilityReadinessProjection struct {
	Host                  *SandboxHost
	Runtime               *SandboxRuntimeState
	Workspace             *SandboxWorkspace
	WorkerRouting         *WorkerRoutingMetadata
	TemplateLock          *SandboxTemplateLockMetadata
	MicroVMIsolationProof *SandboxMicroVMIsolationProofMetadata
	WorkerPostures        []SandboxSecurityCapabilityWorkerPostureMetadata
	Ready                 []SandboxSecurityCapabilityMetadata
}

// SandboxPolicyProxyCredentialCapabilityReadinessProjection carries durable
// policy, proxy, and credential proxy metadata into readiness input.
type SandboxPolicyProxyCredentialCapabilityReadinessProjection struct {
	Requested                 []SandboxSecurityCapabilityMetadata
	Ready                     []SandboxSecurityCapabilityMetadata
	NetworkPolicyResult       *SandboxNetworkPolicyResult
	NetworkProxySession       *SandboxNetworkProxySessionMetadata
	NetworkEnforcementProof   *SandboxNetworkEnforcementProofMetadata
	NetworkPolicyDecisionLogs []SandboxNetworkPolicyDecisionLogRecord
	CredentialProxyPlan       *SandboxCredentialProxyPlanMetadata
	CredentialProxySession    *SandboxCredentialProxySessionMetadata
	CredentialProxyBindings   []SandboxCredentialProxyBindingMetadata
	CredentialDelivery        *SandboxCredentialDeliveryStatusMetadata
}

// ProjectSandboxWorkerRuntimeCapabilityReadinessInput maps durable
// worker/runtime metadata into readiness evaluator input.
func ProjectSandboxWorkerRuntimeCapabilityReadinessInput(projection SandboxWorkerRuntimeCapabilityReadinessProjection) SandboxSecurityCapabilityReadinessInput {
	input := SandboxSecurityCapabilityReadinessInput{}
	input.WorkerPostures = sandboxSecurityCapabilityProjectionAppendWorkerPosture(
		input.WorkerPostures,
		sandboxSecurityCapabilityProjectionWorkerRuntimePosture(projection.Host, projection.Runtime, projection.WorkerRouting),
	)
	input.Ready = sandboxSecurityCapabilityProjectionAppendWorkspaceProof(input.Ready, projection.Workspace)
	input.Ready = sandboxSecurityCapabilityProjectionAppendMicroVMIsolationProof(input.Ready, projection.MicroVMIsolationProof)
	templateLock := sandboxSecurityCapabilityProjectionTemplateLock(projection.TemplateLock, projection.Runtime)
	if sandboxSecurityCapabilityProjectionTemplateTrustRequirementConfigured(templateLock) {
		input.Requested = sandboxSecurityCapabilityProjectionAppendUnique(input.Requested, SandboxSecurityCapabilityMetadata{
			Family:     SandboxSecurityCapabilityFamilyTemplate,
			Capability: SandboxSecurityCapabilitySelectedTemplateTrust,
			Source:     SandboxSecurityCapabilitySourceRequested,
		})
	}
	input.Ready = sandboxSecurityCapabilityProjectionAppendTemplateLockProof(input.Ready, templateLock)
	for _, posture := range projection.WorkerPostures {
		input.WorkerPostures = sandboxSecurityCapabilityProjectionAppendWorkerPosture(input.WorkerPostures, posture)
	}
	for _, ready := range projection.Ready {
		input.Ready = sandboxSecurityCapabilityProjectionAppendUnique(input.Ready, ready)
	}
	return SanitizeSandboxSecurityCapabilityReadinessInput(input)
}

func sandboxSecurityCapabilityProjectionTemplateTrustRequirementConfigured(lock *SandboxTemplateLockMetadata) bool {
	lock = SanitizeSandboxTemplateLockMetadata(lock)
	return lock != nil && lock.TrustPolicy != nil
}

// ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput maps durable
// policy, proxy, and credential proxy metadata into readiness evaluator input.
func ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(projection SandboxPolicyProxyCredentialCapabilityReadinessProjection) SandboxSecurityCapabilityReadinessInput {
	input := SandboxSecurityCapabilityReadinessInput{}
	for _, requested := range projection.Requested {
		input.Requested = sandboxSecurityCapabilityProjectionAppendUnique(input.Requested, requested)
	}
	input.Requested = sandboxSecurityCapabilityProjectionRequestedNetworkPolicyResult(input.Requested, projection.NetworkPolicyResult)
	input.Requested = sandboxSecurityCapabilityProjectionRequestedCredentialBindings(input.Requested, projection.CredentialProxyBindings)
	input.Ready = sandboxSecurityCapabilityProjectionMetadataOnlyNetworkPolicyResult(input.Ready, projection.NetworkPolicyResult)
	input.Ready = sandboxSecurityCapabilityProjectionAppendNetworkEnforcementProof(input.Ready, projection.NetworkEnforcementProof)
	input.Ready = sandboxSecurityCapabilityProjectionAppendCredentialDeliveryProof(input.Ready, projection.CredentialDelivery, projection.CredentialProxyPlan, projection.CredentialProxySession, projection.CredentialProxyBindings)
	for _, ready := range projection.Ready {
		input.Ready = sandboxSecurityCapabilityProjectionAppendUnique(input.Ready, ready)
	}
	input.NetworkProxySession = projection.NetworkProxySession
	input.NetworkPolicyDecisionLogs = append(input.NetworkPolicyDecisionLogs, projection.NetworkPolicyDecisionLogs...)
	input.CredentialProxyPlan = projection.CredentialProxyPlan
	input.CredentialProxySession = projection.CredentialProxySession
	input.CredentialProxyBindings = append(input.CredentialProxyBindings, projection.CredentialProxyBindings...)
	return SanitizeSandboxSecurityCapabilityReadinessInput(input)
}

// MergeSandboxSecurityCapabilityReadinessInputs combines already-projected
// readiness inputs into a deterministic, durable-safe evaluator input.
func MergeSandboxSecurityCapabilityReadinessInputs(inputs ...SandboxSecurityCapabilityReadinessInput) SandboxSecurityCapabilityReadinessInput {
	merged := SandboxSecurityCapabilityReadinessInput{}
	for _, input := range inputs {
		input = SanitizeSandboxSecurityCapabilityReadinessInput(input)
		for _, requested := range input.Requested {
			merged.Requested = sandboxSecurityCapabilityProjectionAppendUnique(merged.Requested, requested)
		}
		for _, ready := range input.Ready {
			merged.Ready = sandboxSecurityCapabilityProjectionAppendUnique(merged.Ready, ready)
		}
		for _, posture := range input.WorkerPostures {
			merged.WorkerPostures = sandboxSecurityCapabilityProjectionAppendWorkerPosture(merged.WorkerPostures, posture)
		}
		if merged.NetworkProxySession == nil && input.NetworkProxySession != nil {
			session := *input.NetworkProxySession
			merged.NetworkProxySession = &session
		}
		merged.NetworkPolicyDecisionLogs = append(merged.NetworkPolicyDecisionLogs, input.NetworkPolicyDecisionLogs...)
		if merged.CredentialProxyPlan == nil && input.CredentialProxyPlan != nil {
			plan := *input.CredentialProxyPlan
			merged.CredentialProxyPlan = &plan
		}
		if merged.CredentialProxySession == nil && input.CredentialProxySession != nil {
			session := *input.CredentialProxySession
			merged.CredentialProxySession = &session
		}
		merged.CredentialProxyBindings = append(merged.CredentialProxyBindings, input.CredentialProxyBindings...)
	}
	return SanitizeSandboxSecurityCapabilityReadinessInput(merged)
}

// EvaluateProjectedSandboxSecurityCapabilityReadiness runs projected input
// through the Phase 27 evaluator and returns sanitized output safe to attach to
// command or factory metadata.
func EvaluateProjectedSandboxSecurityCapabilityReadiness(inputs ...SandboxSecurityCapabilityReadinessInput) *SandboxSecurityCapabilityReadinessOutput {
	input := MergeSandboxSecurityCapabilityReadinessInputs(inputs...)
	input = sandboxSecurityCapabilityProjectionAppendMissingProofs(input)
	output := EvaluateSandboxSecurityCapabilityReadiness(input)
	sanitized := SanitizeSandboxSecurityCapabilityReadinessOutput(output)
	if len(sanitized.Results) == 0 {
		return nil
	}
	return &sanitized
}

func sandboxSecurityCapabilityProjectionRequestedNetwork(records []SandboxSecurityCapabilityMetadata, network *SandboxNetworkSecurity) []SandboxSecurityCapabilityMetadata {
	if network == nil {
		return records
	}
	switch sanitizeSandboxSecurityCapabilityNetworkPolicyValue(network.PolicyRequested) {
	case SandboxNetworkPolicyDenyByDefault:
		return sandboxSecurityCapabilityProjectionAppendUnique(records, SandboxSecurityCapabilityMetadata{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Source:     SandboxSecurityCapabilitySourceRequested,
		})
	default:
		records = sandboxSecurityCapabilityProjectionRequestedNetworkPolicyResult(records, network.PolicyResult)
		return records
	}
}

func sandboxSecurityCapabilityProjectionMetadataOnlyNetwork(records []SandboxSecurityCapabilityMetadata, network *SandboxNetworkSecurity) []SandboxSecurityCapabilityMetadata {
	if network == nil {
		return records
	}
	mode := sanitizeSandboxSecurityCapabilityNetworkEnforcementValue(network.EnforcementMode)
	if sanitizeSandboxSecurityCapabilityNetworkPolicyValue(network.PolicyEnforced) == SandboxNetworkPolicyDenyByDefault {
		records = sandboxSecurityCapabilityProjectionAppendMetadataOnly(records,
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkDenyByDefault,
			sandboxSecurityCapabilitySafeNetworkMode(SandboxSecurityCapabilityNetworkDenyByDefault, mode),
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		)
	}
	records = sandboxSecurityCapabilityProjectionMetadataOnlyNetworkEnforcementMode(records, mode)
	records = sandboxSecurityCapabilityProjectionMetadataOnlyNetworkPolicyResult(records, network.PolicyResult)
	return records
}

func sandboxSecurityCapabilityProjectionRequestedNetworkPolicyResult(records []SandboxSecurityCapabilityMetadata, result *SandboxNetworkPolicyResult) []SandboxSecurityCapabilityMetadata {
	if result == nil {
		return records
	}
	if !sandboxSecurityCapabilityProjectionPolicyIntentRequestsNetworkCapability(result.Requested) {
		return records
	}
	return sandboxSecurityCapabilityProjectionAppendUnique(records, SandboxSecurityCapabilityMetadata{
		Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
		Source:     SandboxSecurityCapabilitySourceRequested,
	})
}

func sandboxSecurityCapabilityProjectionMetadataOnlyNetworkPolicyResult(records []SandboxSecurityCapabilityMetadata, result *SandboxNetworkPolicyResult) []SandboxSecurityCapabilityMetadata {
	if result == nil {
		return records
	}
	mode := sanitizeSandboxSecurityCapabilityNetworkEnforcementValue(result.EnforcementMode)
	if sandboxSecurityCapabilityProjectionPolicyIntentRequestsNetworkCapability(result.Effective) {
		records = sandboxSecurityCapabilityProjectionAppendMetadataOnly(records,
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkDenyByDefault,
			sandboxSecurityCapabilitySafeNetworkMode(SandboxSecurityCapabilityNetworkDenyByDefault, mode),
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		)
	}
	return sandboxSecurityCapabilityProjectionMetadataOnlyNetworkEnforcementMode(records, mode)
}

func sandboxSecurityCapabilityProjectionPolicyIntentRequestsNetworkCapability(intent SandboxNetworkPolicyIntent) bool {
	if sandboxNetworkPolicyPresetNeedsDefaultDeny(intent.Preset) {
		return true
	}
	return len(intent.Rules) > 0
}

func sandboxSecurityCapabilityProjectionMetadataOnlyNetworkEnforcementMode(records []SandboxSecurityCapabilityMetadata, mode string) []SandboxSecurityCapabilityMetadata {
	switch sanitizeSandboxSecurityCapabilityNetworkEnforcementValue(mode) {
	case SandboxNetworkEnforcementModeProxy:
		records = sandboxSecurityCapabilityProjectionAppendMetadataOnly(records,
			SandboxSecurityCapabilityFamilyNetworkProxy,
			SandboxSecurityCapabilityNetworkProxyEnforcement,
			SandboxNetworkEnforcementModeProxy,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		)
	case SandboxNetworkEnforcementModeFirewall:
		records = sandboxSecurityCapabilityProjectionAppendMetadataOnly(records,
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkFirewallEnforcement,
			SandboxNetworkEnforcementModeFirewall,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		)
	case SandboxNetworkEnforcementModeRuntime:
		records = sandboxSecurityCapabilityProjectionAppendMetadataOnly(records,
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkRuntimeEnforcement,
			SandboxNetworkEnforcementModeRuntime,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		)
	case SandboxNetworkEnforcementModeProxyFirewall:
		records = sandboxSecurityCapabilityProjectionAppendMetadataOnly(records,
			SandboxSecurityCapabilityFamilyNetworkProxy,
			SandboxSecurityCapabilityNetworkProxyEnforcement,
			SandboxNetworkEnforcementModeProxy,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		)
		records = sandboxSecurityCapabilityProjectionAppendMetadataOnly(records,
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkFirewallEnforcement,
			SandboxNetworkEnforcementModeFirewall,
			SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		)
	}
	return records
}

func sandboxSecurityCapabilityProjectionRequestedSecrets(records []SandboxSecurityCapabilityMetadata, secrets *SandboxSecretSecurity) []SandboxSecurityCapabilityMetadata {
	if secrets == nil {
		return records
	}
	for _, mode := range secrets.RequestedModes {
		family, capability, sanitizedMode, ok := sandboxSecurityCapabilityProjectionSecretMode(mode)
		if !ok {
			continue
		}
		records = sandboxSecurityCapabilityProjectionAppendUnique(records, SandboxSecurityCapabilityMetadata{
			Family:     family,
			Capability: capability,
			Mode:       sanitizedMode,
			Source:     SandboxSecurityCapabilitySourceRequested,
		})
	}
	return records
}

func sandboxSecurityCapabilityProjectionMetadataOnlySecrets(records []SandboxSecurityCapabilityMetadata, secrets *SandboxSecretSecurity) []SandboxSecurityCapabilityMetadata {
	if secrets == nil {
		return records
	}
	for _, mode := range secrets.ActiveModes {
		family, capability, sanitizedMode, ok := sandboxSecurityCapabilityProjectionSecretMode(mode)
		if !ok {
			continue
		}
		records = sandboxSecurityCapabilityProjectionAppendMetadataOnly(records,
			family,
			capability,
			sanitizedMode,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		)
	}
	return records
}

func sandboxSecurityCapabilityProjectionSecretMode(mode string) (SandboxSecurityCapabilityFamily, SandboxSecurityCapabilityName, string, bool) {
	modes := sanitizeSandboxSecurityCapabilitySecretModes([]string{mode})
	if len(modes) == 0 {
		return "", "", "", false
	}
	switch modes[0] {
	case SandboxSecretModeEnv:
		return SandboxSecurityCapabilityFamilySecretDelivery, SandboxSecurityCapabilitySecretEnv, SandboxSecretModeEnv, true
	case SandboxSecretModeFileTmpfs:
		return SandboxSecurityCapabilityFamilySecretDelivery, SandboxSecurityCapabilitySecretFileTmpfs, SandboxSecretModeFileTmpfs, true
	case SandboxSecretModeSSHAgent:
		return SandboxSecurityCapabilityFamilySecretDelivery, SandboxSecurityCapabilitySecretSSHAgent, SandboxSecretModeSSHAgent, true
	case SandboxSecretModeHTTPProxy:
		return SandboxSecurityCapabilityFamilySecretDelivery, SandboxSecurityCapabilitySecretHTTPProxy, SandboxSecretModeHTTPProxy, true
	default:
		return "", "", "", false
	}
}

func sandboxSecurityCapabilityProjectionCredentialBindingSecretMode(mode string) (SandboxSecurityCapabilityFamily, SandboxSecurityCapabilityName, string, bool) {
	family, capability, sanitizedMode, ok := sandboxSecurityCapabilityProjectionSecretMode(mode)
	if ok {
		return family, capability, sanitizedMode, true
	}
	modes := sanitizeSandboxSecurityCapabilitySecretModes([]string{mode})
	if len(modes) == 0 || modes[0] != SandboxSecretModeLegacyAuthSync {
		return "", "", "", false
	}
	return SandboxSecurityCapabilityFamilySecretDelivery, SandboxSecurityCapabilitySecretEnv, SandboxSecretModeLegacyAuthSync, true
}

func sandboxSecurityCapabilityProjectionAppendNetworkEnforcementProof(records []SandboxSecurityCapabilityMetadata, proof *SandboxNetworkEnforcementProofMetadata) []SandboxSecurityCapabilityMetadata {
	if proof == nil {
		return records
	}
	sanitized := SanitizeSandboxNetworkEnforcementProofMetadata(*proof)
	if sandboxNetworkEnforcementProofEmpty(sanitized) {
		return records
	}
	status, reason := sandboxSecurityCapabilityProjectionNetworkProofReadiness(sanitized)
	return sandboxSecurityCapabilityProjectionAppendSafeEvidence(records,
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		sandboxSecurityCapabilitySafeNetworkMode(SandboxSecurityCapabilityNetworkDenyByDefault, sanitized.ResultEnforcementMode),
		SandboxSecurityCapabilitySourceRuntime,
		status,
		reason,
	)
}

func sandboxSecurityCapabilityProjectionNetworkProofReadiness(proof SandboxNetworkEnforcementProofMetadata) (SandboxSecurityCapabilityReadinessState, SandboxSecurityCapabilityReasonCode) {
	if proof.NetworkProxySessionID == "" || proof.PolicySnapshotID == "" || proof.NetworkEnforcementPlanID == "" {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonNetworkEnforcementMissing
	}
	if proof.ProxyLifecycleStatus == "failed" || proof.FirewallLifecycleStatus == "failed" || proof.ResultOutcome == "failure" {
		return SandboxSecurityCapabilityReadinessBlocked, SandboxSecurityCapabilityReasonNetworkEnforcementFailed
	}
	if proof.ResultOutcome == "best_effort" || proof.ResultEnforcementMode == SandboxNetworkEnforcementModeBestEffort {
		return SandboxSecurityCapabilityReadinessMetadataOnly, SandboxSecurityCapabilityReasonNetworkEnforcementBestEffort
	}
	if proof.WarningCount > 0 {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonWarningBearing
	}
	if proof.ResultOutcome == "unsupported" || !proof.ResultSupported {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported
	}
	if !sandboxNetworkEnforcementProofHasActiveProxy(proof) || !sandboxNetworkEnforcementProofHasActiveFirewall(proof) {
		return SandboxSecurityCapabilityReadinessMetadataOnly, SandboxSecurityCapabilityReasonNetworkEnforcementPartial
	}
	if SandboxNetworkEnforcementProofProvesActiveProxyFirewall(proof) {
		return SandboxSecurityCapabilityReadinessReady, SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed
	}
	if proof.ResultOutcome == "success" && proof.ResultSupported {
		return SandboxSecurityCapabilityReadinessMetadataOnly, SandboxSecurityCapabilityReasonNetworkEnforcementPartial
	}
	return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported
}

func sandboxSecurityCapabilityProjectionAppendMicroVMIsolationProof(records []SandboxSecurityCapabilityMetadata, proof *SandboxMicroVMIsolationProofMetadata) []SandboxSecurityCapabilityMetadata {
	if proof == nil {
		return records
	}
	sanitized := SanitizeSandboxMicroVMIsolationProofMetadata(*proof)
	if sandboxMicroVMIsolationProofEmpty(sanitized) {
		return records
	}
	status, reason := sandboxSecurityCapabilityProjectionMicroVMIsolationProofReadiness(sanitized)
	return sandboxSecurityCapabilityProjectionAppendSafeEvidence(records,
		SandboxSecurityCapabilityFamilyIsolation,
		SandboxSecurityCapabilityIsolationMicroVM,
		"",
		SandboxSecurityCapabilitySourceRuntime,
		status,
		reason,
	)
}

func sandboxSecurityCapabilityProjectionMicroVMIsolationProofReadiness(proof SandboxMicroVMIsolationProofMetadata) (SandboxSecurityCapabilityReadinessState, SandboxSecurityCapabilityReasonCode) {
	if proof.RuntimeDriver != SandboxRuntimeDriverMicroVM ||
		proof.IsolationLevel != SandboxIsolationLevelVM ||
		!proof.ResultSupported {
		return SandboxSecurityCapabilityReadinessBlocked, SandboxSecurityCapabilityReasonMicroVMSupportMissing
	}
	if proof.WarningCount > 0 {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonWarningBearing
	}
	if SandboxMicroVMIsolationProofProvesActiveVMIsolation(&proof) {
		return SandboxSecurityCapabilityReadinessReady, SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed
	}
	return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonMicroVMReadinessMissing
}

func sandboxSecurityCapabilityProjectionAppendCredentialDeliveryProof(records []SandboxSecurityCapabilityMetadata, status *SandboxCredentialDeliveryStatusMetadata, plan *SandboxCredentialProxyPlanMetadata, session *SandboxCredentialProxySessionMetadata, bindings []SandboxCredentialProxyBindingMetadata) []SandboxSecurityCapabilityMetadata {
	if status == nil {
		return records
	}
	sanitized := SanitizeSandboxCredentialDeliveryStatusMetadata(*status)
	if sanitized.ID == "" {
		return records
	}
	configuredBindings := sandboxSecurityCapabilityProjectionConfiguredCredentialBindings(plan, session, bindings)
	if sanitized.Status == "active" && sanitized.ActivationID != "" && len(sanitized.ActiveProofs) > 0 && sanitized.WarningCount == 0 && sanitized.ErrorCount == 0 {
		before := len(records)
		for _, proof := range sanitized.ActiveProofs {
			family, capability, sanitizedMode, ok := sandboxSecurityCapabilityProjectionSecretMode(proof.DeliveryMode)
			if !ok || proof.BindingID == "" || !sandboxSecurityCapabilityProjectionCredentialProofSourceAllowed(proof) {
				continue
			}
			binding, ok := configuredBindings[proof.BindingID]
			if !ok || string(binding.DeliveryMode) != sanitizedMode {
				continue
			}
			records = sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				proof.BindingID,
				family,
				capability,
				sanitizedMode,
				SandboxSecurityCapabilitySourceWorker,
				SandboxSecurityCapabilityReadinessReady,
				SandboxSecurityCapabilityReasonCredentialActivationConfirmed,
			)
		}
		if len(records) > before {
			return records
		}
	}
	if sanitized.Status == "active" && sanitized.ActivationID != "" && len(sanitized.ActiveProofs) > 0 && sanitized.WarningCount > 0 {
		before := len(records)
		for _, proof := range sanitized.ActiveProofs {
			family, capability, sanitizedMode, ok := sandboxSecurityCapabilityProjectionSecretMode(proof.DeliveryMode)
			if !ok || proof.BindingID == "" {
				continue
			}
			records = sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				proof.BindingID,
				family,
				capability,
				sanitizedMode,
				SandboxSecurityCapabilitySourceMetadata,
				SandboxSecurityCapabilityReadinessUnsupported,
				SandboxSecurityCapabilityReasonWarningBearing,
			)
		}
		if len(records) > before {
			return records
		}
	}
	for _, mode := range sanitized.RequestedModes {
		family, capability, sanitizedMode, ok := sandboxSecurityCapabilityProjectionSecretMode(mode)
		if !ok {
			continue
		}
		records = sandboxSecurityCapabilityProjectionAppendSafeEvidence(records,
			family,
			capability,
			sanitizedMode,
			SandboxSecurityCapabilitySourceMetadata,
			SandboxSecurityCapabilityReadinessMetadataOnly,
			SandboxSecurityCapabilityReasonCredentialActivationMissing,
		)
	}
	return records
}

func sandboxSecurityCapabilityProjectionConfiguredCredentialBindings(plan *SandboxCredentialProxyPlanMetadata, session *SandboxCredentialProxySessionMetadata, bindings []SandboxCredentialProxyBindingMetadata) map[string]SandboxCredentialProxyBindingMetadata {
	planContext := sandboxSecurityCapabilityProjectionCredentialProofPlan(plan)
	sessionContext := sandboxSecurityCapabilityProjectionCredentialProofSession(session, planContext)
	if planContext.ID == "" || sessionContext.ID == "" {
		return nil
	}
	sanitized := SanitizeSandboxCredentialProxyBindingMetadataRecords(bindings)
	if len(sanitized) == 0 {
		return nil
	}
	out := make(map[string]SandboxCredentialProxyBindingMetadata, len(sanitized))
	for _, binding := range sanitized {
		if !sandboxSecurityCapabilityProjectionCredentialBindingCanAcceptProof(binding) {
			continue
		}
		if binding.PlanID != planContext.ID || binding.SessionID != sessionContext.ID {
			continue
		}
		out[binding.ID] = binding
	}
	return out
}

func sandboxSecurityCapabilityProjectionCredentialProofPlan(plan *SandboxCredentialProxyPlanMetadata) SandboxCredentialProxyPlanMetadata {
	if plan == nil {
		return SandboxCredentialProxyPlanMetadata{}
	}
	sanitized := SanitizeSandboxCredentialProxyPlanMetadata(*plan)
	if sanitized.ID == "" || sanitized.SecretBrokerSessionID == "" {
		return SandboxCredentialProxyPlanMetadata{}
	}
	switch sanitized.Mode {
	case SandboxCredentialProxyModeSecretBrokerReference,
		SandboxCredentialProxyModeBrokeredNetworkReference:
	default:
		return SandboxCredentialProxyPlanMetadata{}
	}
	if !sandboxSecurityCapabilityProjectionCredentialProxyStatusCanProveDelivery(sanitized.Status) {
		return SandboxCredentialProxyPlanMetadata{}
	}
	return sanitized
}

func sandboxSecurityCapabilityProjectionCredentialProofSession(session *SandboxCredentialProxySessionMetadata, plan SandboxCredentialProxyPlanMetadata) SandboxCredentialProxySessionMetadata {
	if session == nil || plan.ID == "" {
		return SandboxCredentialProxySessionMetadata{}
	}
	sanitized := SanitizeSandboxCredentialProxySessionMetadata(*session)
	if sanitized.ID == "" ||
		sanitized.PlanID != plan.ID ||
		sanitized.SecretBrokerSessionID == "" ||
		sanitized.SecretBrokerSessionID != plan.SecretBrokerSessionID ||
		sanitized.WarningCode != "" ||
		!sandboxSecurityCapabilityProjectionCredentialProxyStatusCanProveDelivery(sanitized.Status) {
		return SandboxCredentialProxySessionMetadata{}
	}
	if plan.NetworkProxySessionID != "" && sanitized.NetworkProxySessionID != "" && sanitized.NetworkProxySessionID != plan.NetworkProxySessionID {
		return SandboxCredentialProxySessionMetadata{}
	}
	if plan.Mode == SandboxCredentialProxyModeBrokeredNetworkReference && (plan.NetworkProxySessionID == "" || sanitized.NetworkProxySessionID == "") {
		return SandboxCredentialProxySessionMetadata{}
	}
	return sanitized
}

func sandboxSecurityCapabilityProjectionCredentialBindingCanAcceptProof(binding SandboxCredentialProxyBindingMetadata) bool {
	if binding.ID == "" {
		return false
	}
	if _, _, _, ok := sandboxSecurityCapabilityProjectionSecretMode(string(binding.DeliveryMode)); !ok {
		return false
	}
	switch binding.Status {
	case SandboxCredentialProxyStatusReady, SandboxCredentialProxyStatusActive, SandboxCredentialProxyStatusCompleted:
	default:
		return false
	}
	switch binding.Outcome {
	case SandboxCredentialProxyBindingOutcomeBound:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityProjectionCredentialProxyStatusCanProveDelivery(status SandboxCredentialProxyStatus) bool {
	switch status {
	case SandboxCredentialProxyStatusReady,
		SandboxCredentialProxyStatusActive,
		SandboxCredentialProxyStatusCompleted:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityProjectionCredentialProofSourceAllowed(proof SandboxCredentialDeliveryProofSummary) bool {
	switch proof.DeliveryMode {
	case SandboxSecretModeHTTPProxy:
		switch proof.Source {
		case "broker", "secret_broker", "credential_proxy", "network_proxy":
			return true
		}
	case SandboxSecretModeSSHAgent:
		switch proof.Source {
		case "broker", "secret_broker", "handoff":
			return true
		}
	case SandboxSecretModeFileTmpfs:
		switch proof.Source {
		case "broker", "secret_broker", "simulation":
			return true
		}
	}
	return false
}

func sandboxSecurityCapabilityProjectionRequestedCredentialBindings(records []SandboxSecurityCapabilityMetadata, bindings []SandboxCredentialProxyBindingMetadata) []SandboxSecurityCapabilityMetadata {
	for _, binding := range SanitizeSandboxCredentialProxyBindingMetadataRecords(bindings) {
		family, capability, mode, ok := sandboxSecurityCapabilityProjectionCredentialBindingSecretMode(string(binding.DeliveryMode))
		if !ok {
			continue
		}
		records = sandboxSecurityCapabilityProjectionAppendUnique(records, SandboxSecurityCapabilityMetadata{
			ID:         binding.ID,
			Family:     family,
			Capability: capability,
			Mode:       mode,
			Source:     SandboxSecurityCapabilitySourceRequested,
		})
	}
	return records
}

func sandboxSecurityCapabilityProjectionAppendWorkspaceProof(records []SandboxSecurityCapabilityMetadata, workspace *SandboxWorkspace) []SandboxSecurityCapabilityMetadata {
	if workspace == nil {
		return records
	}
	switch workspace.Mode {
	case SandboxWorkspaceModeClone:
		switch workspace.InputSource {
		case SandboxWorkspaceInputSourceRemoteRef, SandboxWorkspaceInputSourceGitBundle:
			return sandboxSecurityCapabilityProjectionAppendWorkspaceEvidence(records, SandboxSecurityCapabilityReadinessReady, SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed)
		default:
			return records
		}
	case SandboxWorkspaceModeCopy:
		return sandboxSecurityCapabilityProjectionAppendWorkspaceEvidence(records, SandboxSecurityCapabilityReadinessReady, SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed)
	case SandboxWorkspaceModeDirect:
		return sandboxSecurityCapabilityProjectionAppendWorkspaceEvidence(records, SandboxSecurityCapabilityReadinessBlocked, SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree)
	default:
		return records
	}
}

func sandboxSecurityCapabilityProjectionAppendWorkspaceEvidence(records []SandboxSecurityCapabilityMetadata, status SandboxSecurityCapabilityReadinessState, reason SandboxSecurityCapabilityReasonCode) []SandboxSecurityCapabilityMetadata {
	return sandboxSecurityCapabilityProjectionAppendSafeEvidence(records,
		SandboxSecurityCapabilityFamilyWorkspace,
		SandboxSecurityCapabilityIsolatedWorkspace,
		"",
		SandboxSecurityCapabilitySourceWorker,
		status,
		reason,
	)
}

func sandboxSecurityCapabilityProjectionTemplateLock(explicit *SandboxTemplateLockMetadata, runtime *SandboxRuntimeState) *SandboxTemplateLockMetadata {
	if explicit != nil {
		return SanitizeSandboxTemplateLockMetadata(explicit)
	}
	if runtime != nil {
		return SanitizeSandboxTemplateLockMetadata(runtime.TemplateLock)
	}
	return nil
}

func sandboxSecurityCapabilityProjectionAppendTemplateLockProof(records []SandboxSecurityCapabilityMetadata, lock *SandboxTemplateLockMetadata) []SandboxSecurityCapabilityMetadata {
	lock = SanitizeSandboxTemplateLockMetadata(lock)
	if lock == nil {
		return records
	}
	status := SandboxSecurityCapabilityReadinessMetadataOnly
	reason := SandboxSecurityCapabilityReasonTemplateLockDigestMissing
	if sandboxSecurityCapabilityProjectionTemplateLockComplete(lock) {
		status = SandboxSecurityCapabilityReadinessReady
		reason = SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed
		if sandboxSecurityCapabilityTemplateLockWarningBearing(lock) {
			status = SandboxSecurityCapabilityReadinessUnsupported
			reason = SandboxSecurityCapabilityReasonWarningBearing
		}
	}
	records = sandboxSecurityCapabilityProjectionAppendSafeEvidence(records,
		SandboxSecurityCapabilityFamilyTemplate,
		SandboxSecurityCapabilityTemplateLockDigest,
		"",
		SandboxSecurityCapabilitySourceRuntime,
		status,
		reason,
	)
	trustStatus, trustReason := sandboxSecurityCapabilityProjectionSelectedTemplateTrustReadiness(lock)
	return sandboxSecurityCapabilityProjectionAppendSafeEvidence(records,
		SandboxSecurityCapabilityFamilyTemplate,
		SandboxSecurityCapabilitySelectedTemplateTrust,
		"",
		SandboxSecurityCapabilitySourceRuntime,
		trustStatus,
		trustReason,
	)
}

func sandboxSecurityCapabilityProjectionSelectedTemplateTrustReadiness(lock *SandboxTemplateLockMetadata) (SandboxSecurityCapabilityReadinessState, SandboxSecurityCapabilityReasonCode) {
	lock = SanitizeSandboxTemplateLockMetadata(lock)
	if lock == nil {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing
	}
	if sandboxSecurityCapabilityTemplateTrustHasPolicyCode(lock, SandboxTemplateTrustPolicyCodeLockProvenanceMismatch) {
		return SandboxSecurityCapabilityReadinessBlocked, SandboxSecurityCapabilityReasonSelectedTemplateProvenanceMismatch
	}
	if sandboxSecurityCapabilityTemplateLockHasUnresolvedProvenance(lock) {
		return SandboxSecurityCapabilityReadinessBlocked, SandboxSecurityCapabilityReasonSelectedTemplateProvenanceUnresolved
	}
	if lock.TrustPolicy == nil {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing
	}
	if lock.TrustPolicy.Decision == SandboxTemplateTrustPolicyDecisionRejected {
		return SandboxSecurityCapabilityReadinessBlocked, SandboxSecurityCapabilityReasonSelectedTemplateTrustRejected
	}
	if lock.TrustPolicy.Decision == SandboxTemplateTrustPolicyDecisionUnavailable {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonSelectedTemplateTrustUnavailable
	}
	if lock.TrustPolicy.Mode == SandboxTemplateTrustPolicyModeAdvisory ||
		lock.TrustPolicy.Decision == SandboxTemplateTrustPolicyDecisionAdvisory {
		return SandboxSecurityCapabilityReadinessMetadataOnly, SandboxSecurityCapabilityReasonSelectedTemplateTrustAdvisoryOnly
	}
	if lock.TrustPolicy.Mode != SandboxTemplateTrustPolicyModeStrict ||
		lock.TrustPolicy.Decision != SandboxTemplateTrustPolicyDecisionTrusted {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing
	}
	if !sandboxSecurityCapabilityProjectionTemplateLockComplete(lock) ||
		!sandboxSecurityCapabilityTemplateTrustPolicyComplete(lock.TrustPolicy) {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing
	}
	if sandboxSecurityCapabilityTemplateLockWarningBearing(lock) {
		return SandboxSecurityCapabilityReadinessUnsupported, SandboxSecurityCapabilityReasonWarningBearing
	}
	return SandboxSecurityCapabilityReadinessReady, SandboxSecurityCapabilityReasonSelectedTemplateTrustConfirmed
}

func sandboxSecurityCapabilityTemplateLockWarningBearing(lock *SandboxTemplateLockMetadata) bool {
	lock = SanitizeSandboxTemplateLockMetadata(lock)
	if lock == nil {
		return false
	}
	if sandboxSecurityCapabilityTemplateTrustPolicyWarningBearing(lock.TrustPolicy) {
		return true
	}
	for _, entry := range []*SandboxTemplateLockEntryMetadata{
		lock.Document,
		lock.TemplateReference,
		lock.RuntimeImage,
		lock.SourceArtifact,
	} {
		if entry != nil && len(entry.WarningCodes) > 0 {
			return true
		}
	}
	return false
}

func sandboxSecurityCapabilityTemplateTrustPolicyWarningBearing(policy *SandboxTemplateTrustPolicyMetadata) bool {
	return policy != nil &&
		(len(policy.WarningCodes) > 0 || len(policy.ErrorCodes) > 0 || len(policy.ReasonCodes) > 0)
}

func sandboxSecurityCapabilityTemplateLockHasUnresolvedProvenance(lock *SandboxTemplateLockMetadata) bool {
	if lock == nil {
		return false
	}
	if lock.TrustPolicy != nil && lock.TrustPolicy.Status == SandboxTemplateLockStatusUnresolved {
		return true
	}
	for _, entry := range []*SandboxTemplateLockEntryMetadata{
		lock.Document,
		lock.TemplateReference,
		lock.RuntimeImage,
		lock.SourceArtifact,
	} {
		if entry != nil && entry.Status == SandboxTemplateLockStatusUnresolved {
			return true
		}
	}
	return false
}

func sandboxSecurityCapabilityTemplateTrustPolicyComplete(policy *SandboxTemplateTrustPolicyMetadata) bool {
	return policy != nil &&
		policy.Status == SandboxTemplateLockStatusLocked &&
		policy.DigestAlgorithm != "" &&
		policy.DigestValue != ""
}

func sandboxSecurityCapabilityTemplateTrustHasPolicyCode(lock *SandboxTemplateLockMetadata, code string) bool {
	if lock == nil || lock.TrustPolicy == nil {
		return false
	}
	for _, codes := range [][]string{
		lock.TrustPolicy.ReasonCodes,
		lock.TrustPolicy.ErrorCodes,
		lock.TrustPolicy.WarningCodes,
	} {
		for _, candidate := range codes {
			if candidate == code {
				return true
			}
		}
	}
	return false
}

func sandboxSecurityCapabilityProjectionTemplateLockComplete(lock *SandboxTemplateLockMetadata) bool {
	lock = SanitizeSandboxTemplateLockMetadata(lock)
	if lock == nil {
		return false
	}
	for _, entry := range []*SandboxTemplateLockEntryMetadata{
		lock.Document,
		lock.TemplateReference,
		lock.RuntimeImage,
		lock.SourceArtifact,
	} {
		if !sandboxSecurityCapabilityProjectionTemplateLockEntryComplete(entry) {
			return false
		}
	}
	return true
}

func sandboxSecurityCapabilityProjectionTemplateLockEntryComplete(entry *SandboxTemplateLockEntryMetadata) bool {
	return entry != nil &&
		entry.Status == SandboxTemplateLockStatusLocked &&
		entry.DigestAlgorithm != "" &&
		entry.DigestValue != ""
}

func sandboxSecurityCapabilityProjectionAppendMissingProofs(input SandboxSecurityCapabilityReadinessInput) SandboxSecurityCapabilityReadinessInput {
	input = SanitizeSandboxSecurityCapabilityReadinessInput(input)
	for _, requested := range input.Requested {
		if sandboxSecurityCapabilityProjectionHasEvidence(requested, input.Ready) {
			continue
		}
		input.Ready = sandboxSecurityCapabilityProjectionAppendRequestedMetadataProof(input.Ready, input, requested)
		if sandboxSecurityCapabilityProjectionHasEvidence(requested, input.Ready) {
			continue
		}
		input.Ready = sandboxSecurityCapabilityProjectionAppendMissingProof(input.Ready, requested)
	}
	return SanitizeSandboxSecurityCapabilityReadinessInput(input)
}

func sandboxSecurityCapabilityProjectionHasEvidence(requested SandboxSecurityCapabilityMetadata, records []SandboxSecurityCapabilityMetadata) bool {
	for _, record := range records {
		if !sandboxSecurityCapabilitySameRequest(requested, record) &&
			!sandboxSecurityCapabilitySameProjectedEvidenceTarget(requested, record) {
			continue
		}
		if sandboxSecurityCapabilityExplicitReadyMetadata(record) ||
			sandboxSecurityCapabilityExplicitBlockerMetadata(record) ||
			sandboxSecurityCapabilityExplicitMetadataOnlyMetadata(record) ||
			sandboxSecurityCapabilityExplicitUnsupportedMetadata(record) {
			return true
		}
	}
	return false
}

func sandboxSecurityCapabilityProjectionAppendRequestedMetadataProof(records []SandboxSecurityCapabilityMetadata, input SandboxSecurityCapabilityReadinessInput, requested SandboxSecurityCapabilityMetadata) []SandboxSecurityCapabilityMetadata {
	switch requested.Family {
	case SandboxSecurityCapabilityFamilyIsolation:
		if requested.Capability == SandboxSecurityCapabilityIsolationMicroVM &&
			sandboxSecurityCapabilityProjectionHasMicroVMMetadata(input) {
			return sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				requested.ID,
				requested.Family,
				requested.Capability,
				requested.Mode,
				SandboxSecurityCapabilitySourceMetadata,
				SandboxSecurityCapabilityReadinessUnsupported,
				SandboxSecurityCapabilityReasonMicroVMReadinessMissing,
			)
		}
	case SandboxSecurityCapabilityFamilyNetworkPolicy:
		if requested.Capability == SandboxSecurityCapabilityNetworkDenyByDefault &&
			requested.Mode != "" &&
			sandboxSecurityCapabilityProjectionHasPlannedNetworkMetadata(input, requested) {
			return sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				requested.ID,
				requested.Family,
				requested.Capability,
				requested.Mode,
				SandboxSecurityCapabilitySourceMetadata,
				SandboxSecurityCapabilityReadinessMetadataOnly,
				SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly,
			)
		}
	case SandboxSecurityCapabilityFamilySecretDelivery:
		if sandboxSecurityCapabilityProjectionHasCredentialMetadata(input) {
			return sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				requested.ID,
				requested.Family,
				requested.Capability,
				requested.Mode,
				SandboxSecurityCapabilitySourceMetadata,
				SandboxSecurityCapabilityReadinessMetadataOnly,
				SandboxSecurityCapabilityReasonCredentialActivationMissing,
			)
		}
	}
	return records
}

func sandboxSecurityCapabilityProjectionHasPlannedNetworkMetadata(input SandboxSecurityCapabilityReadinessInput, requested SandboxSecurityCapabilityMetadata) bool {
	for _, record := range input.Ready {
		if !sandboxSecurityCapabilitySameRequest(requested, record) {
			continue
		}
		if record.Status == SandboxSecurityCapabilityReadinessMetadataOnly &&
			record.ReasonCode == SandboxSecurityCapabilityReasonMetadataEnforcementUnproven {
			return true
		}
	}
	return input.NetworkProxySession != nil || len(input.NetworkPolicyDecisionLogs) > 0
}

func sandboxSecurityCapabilityProjectionHasMicroVMMetadata(input SandboxSecurityCapabilityReadinessInput) bool {
	for _, record := range input.Ready {
		if record.Family == SandboxSecurityCapabilityFamilyIsolation &&
			record.Capability == SandboxSecurityCapabilityIsolationMicroVM {
			return true
		}
	}
	for _, posture := range input.WorkerPostures {
		if posture.RuntimeDriver == SandboxRuntimeDriverMicroVM ||
			posture.IsolationLevel == SandboxIsolationLevelVM {
			return true
		}
	}
	return false
}

func sandboxSecurityCapabilityProjectionHasCredentialMetadata(input SandboxSecurityCapabilityReadinessInput) bool {
	return input.CredentialProxyPlan != nil ||
		input.CredentialProxySession != nil ||
		len(input.CredentialProxyBindings) > 0
}

func sandboxSecurityCapabilityProjectionAppendMissingProof(records []SandboxSecurityCapabilityMetadata, requested SandboxSecurityCapabilityMetadata) []SandboxSecurityCapabilityMetadata {
	switch requested.Family {
	case SandboxSecurityCapabilityFamilyIsolation:
		if requested.Capability == SandboxSecurityCapabilityIsolationMicroVM {
			return sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				requested.ID,
				requested.Family,
				requested.Capability,
				requested.Mode,
				SandboxSecurityCapabilitySourceMetadata,
				SandboxSecurityCapabilityReadinessUnsupported,
				SandboxSecurityCapabilityReasonMicroVMReadinessMissing,
			)
		}
	case SandboxSecurityCapabilityFamilyNetworkPolicy:
		if requested.Capability == SandboxSecurityCapabilityNetworkDenyByDefault && requested.Mode != "" {
			return sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				requested.ID,
				requested.Family,
				requested.Capability,
				requested.Mode,
				SandboxSecurityCapabilitySourceMetadata,
				SandboxSecurityCapabilityReadinessUnsupported,
				SandboxSecurityCapabilityReasonNetworkEnforcementMissing,
			)
		}
	case SandboxSecurityCapabilityFamilySecretDelivery:
		return records
	case SandboxSecurityCapabilityFamilyTemplate:
		if requested.Capability == SandboxSecurityCapabilityTemplateLockDigest {
			return sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				requested.ID,
				requested.Family,
				requested.Capability,
				requested.Mode,
				SandboxSecurityCapabilitySourceMetadata,
				SandboxSecurityCapabilityReadinessMetadataOnly,
				SandboxSecurityCapabilityReasonTemplateLockDigestMissing,
			)
		}
		if requested.Capability == SandboxSecurityCapabilitySelectedTemplateTrust {
			return sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				requested.ID,
				requested.Family,
				requested.Capability,
				requested.Mode,
				SandboxSecurityCapabilitySourceMetadata,
				SandboxSecurityCapabilityReadinessUnsupported,
				SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing,
			)
		}
	case SandboxSecurityCapabilityFamilyWorkspace:
		if requested.Capability == SandboxSecurityCapabilityIsolatedWorkspace {
			return sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records,
				requested.ID,
				requested.Family,
				requested.Capability,
				requested.Mode,
				SandboxSecurityCapabilitySourceMetadata,
				SandboxSecurityCapabilityReadinessUnsupported,
				SandboxSecurityCapabilityReasonWorkspaceIsolationMissing,
			)
		}
	}
	return records
}

func sandboxSecurityCapabilityProjectionWorkerRuntimePosture(host *SandboxHost, runtime *SandboxRuntimeState, routing *WorkerRoutingMetadata) SandboxSecurityCapabilityWorkerPostureMetadata {
	posture := SandboxSecurityCapabilityWorkerPostureMetadata{}
	if host != nil {
		posture.WorkerKind = sandboxSecurityCapabilityProjectionFirstSafeLabel(posture.WorkerKind, host.Kind, sanitizeSandboxSecurityCapabilityWorkerKindValue)
		posture = sandboxSecurityCapabilityProjectionApplySecurityPosture(posture, host.Security)
	}
	if runtime != nil {
		posture.RuntimeDriver = sandboxSecurityCapabilityProjectionFirstSafeLabel(posture.RuntimeDriver, runtime.Driver, sanitizeSandboxSecurityCapabilityRuntimeDriverValue)
		posture.IsolationLevel = sandboxSecurityCapabilityProjectionFirstSafeLabel(posture.IsolationLevel, runtime.IsolationLevel, sanitizeSandboxSecurityCapabilityIsolationLevelValue)
	}
	if routing != nil {
		posture.RuntimeDriver = sandboxSecurityCapabilityProjectionFirstSafeLabel(posture.RuntimeDriver, routing.RuntimeDriverID, sanitizeSandboxSecurityCapabilityRuntimeDriverValue)
		posture.IsolationLevel = sandboxSecurityCapabilityProjectionFirstSafeLabel(posture.IsolationLevel, routing.IsolationLevel, sanitizeSandboxSecurityCapabilityIsolationLevelValue)
	}
	return posture
}

func sandboxSecurityCapabilityProjectionApplySecurityPosture(posture SandboxSecurityCapabilityWorkerPostureMetadata, security *SandboxSecurity) SandboxSecurityCapabilityWorkerPostureMetadata {
	if security == nil {
		return posture
	}
	if security.Network != nil {
		posture.NetworkPolicy = sandboxSecurityCapabilityProjectionFirstSafeLabel(posture.NetworkPolicy, security.Network.PolicyEnforced, sanitizeSandboxSecurityCapabilityNetworkPolicyValue)
		posture.NetworkEnforcement = sandboxSecurityCapabilityProjectionFirstSafeLabel(posture.NetworkEnforcement, security.Network.EnforcementMode, sanitizeSandboxSecurityCapabilityNetworkEnforcementValue)
	}
	if security.Secrets != nil {
		posture.CredentialModes = sandboxSecurityCapabilityProjectionAppendSecretModes(posture.CredentialModes, security.Secrets.ActiveModes)
	}
	return posture
}

type sandboxSecurityCapabilityProjectionLabelSanitizer func(string) string

func sandboxSecurityCapabilityProjectionFirstSafeLabel(existing, candidate string, sanitize sandboxSecurityCapabilityProjectionLabelSanitizer) string {
	if sanitize(existing) != "" {
		return sanitize(existing)
	}
	return sanitize(candidate)
}

func sandboxSecurityCapabilityProjectionAppendSecretModes(existing, candidates []string) []string {
	modes := sanitizeSandboxSecurityCapabilitySecretModes(existing)
	if len(candidates) == 0 {
		return modes
	}
	for _, mode := range sanitizeSandboxSecurityCapabilitySecretModes(candidates) {
		duplicate := false
		for _, existingMode := range modes {
			if existingMode == mode {
				duplicate = true
				break
			}
		}
		if !duplicate {
			modes = append(modes, mode)
		}
	}
	if len(modes) == 0 {
		return nil
	}
	return modes
}

func sandboxSecurityCapabilityProjectionAppendWorkerPosture(records []SandboxSecurityCapabilityWorkerPostureMetadata, posture SandboxSecurityCapabilityWorkerPostureMetadata) []SandboxSecurityCapabilityWorkerPostureMetadata {
	sanitized := sanitizeSandboxSecurityCapabilityWorkerPostures([]SandboxSecurityCapabilityWorkerPostureMetadata{posture})
	if len(sanitized) == 0 {
		return records
	}
	record := sanitized[0]
	for _, existing := range records {
		if sandboxSecurityCapabilityProjectionSameWorkerPosture(existing, record) {
			return records
		}
	}
	return append(records, record)
}

func sandboxSecurityCapabilityProjectionSameWorkerPosture(a, b SandboxSecurityCapabilityWorkerPostureMetadata) bool {
	return a.WorkerKind == b.WorkerKind &&
		a.RuntimeDriver == b.RuntimeDriver &&
		a.IsolationLevel == b.IsolationLevel &&
		a.NetworkPolicy == b.NetworkPolicy &&
		a.NetworkEnforcement == b.NetworkEnforcement &&
		a.CredentialProxyMode == b.CredentialProxyMode &&
		sandboxSecurityCapabilityProjectionSameStrings(a.CredentialModes, b.CredentialModes)
}

func sandboxSecurityCapabilityProjectionSameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sandboxSecurityCapabilityProjectionAppendMetadataOnly(records []SandboxSecurityCapabilityMetadata, family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, mode string, reason SandboxSecurityCapabilityReasonCode) []SandboxSecurityCapabilityMetadata {
	return sandboxSecurityCapabilityProjectionAppendUnique(records, SandboxSecurityCapabilityMetadata{
		Family:       family,
		Capability:   capability,
		Mode:         mode,
		Source:       SandboxSecurityCapabilitySourceMetadata,
		Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
		ReasonCode:   reason,
		WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
	})
}

func sandboxSecurityCapabilityProjectionAppendSafeEvidence(records []SandboxSecurityCapabilityMetadata, family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, mode string, source SandboxSecurityCapabilitySource, status SandboxSecurityCapabilityReadinessState, reason SandboxSecurityCapabilityReasonCode) []SandboxSecurityCapabilityMetadata {
	return sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records, "", family, capability, mode, source, status, reason)
}

func sandboxSecurityCapabilityProjectionAppendSafeEvidenceWithID(records []SandboxSecurityCapabilityMetadata, id string, family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, mode string, source SandboxSecurityCapabilitySource, status SandboxSecurityCapabilityReadinessState, reason SandboxSecurityCapabilityReasonCode) []SandboxSecurityCapabilityMetadata {
	record, ok := sanitizeSandboxSecurityCapabilityInputMetadata(SandboxSecurityCapabilityMetadata{
		ID:         id,
		Family:     family,
		Capability: capability,
		Mode:       mode,
		Source:     source,
		Status:     status,
		ReasonCode: reason,
	}, false)
	if !ok {
		return records
	}
	return sandboxSecurityCapabilityProjectionAppendUnique(records, record)
}

func sandboxSecurityCapabilityProjectionAppendUnique(records []SandboxSecurityCapabilityMetadata, record SandboxSecurityCapabilityMetadata) []SandboxSecurityCapabilityMetadata {
	for _, existing := range records {
		if sandboxSecurityCapabilityProjectionSameMetadata(existing, record) {
			return records
		}
	}
	return append(records, record)
}

func sandboxSecurityCapabilityProjectionSameMetadata(a, b SandboxSecurityCapabilityMetadata) bool {
	return a.ID == b.ID &&
		a.Family == b.Family &&
		a.Capability == b.Capability &&
		a.Mode == b.Mode &&
		a.Source == b.Source &&
		a.Status == b.Status &&
		a.ReasonCode == b.ReasonCode
}
