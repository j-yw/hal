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
	Host           *SandboxHost
	Runtime        *SandboxRuntimeState
	WorkerRouting  *WorkerRoutingMetadata
	WorkerPostures []SandboxSecurityCapabilityWorkerPostureMetadata
	Ready          []SandboxSecurityCapabilityMetadata
}

// ProjectSandboxWorkerRuntimeCapabilityReadinessInput maps durable
// worker/runtime metadata into readiness evaluator input.
func ProjectSandboxWorkerRuntimeCapabilityReadinessInput(projection SandboxWorkerRuntimeCapabilityReadinessProjection) SandboxSecurityCapabilityReadinessInput {
	input := SandboxSecurityCapabilityReadinessInput{}
	input.WorkerPostures = sandboxSecurityCapabilityProjectionAppendWorkerPosture(
		input.WorkerPostures,
		sandboxSecurityCapabilityProjectionWorkerRuntimePosture(projection.Host, projection.Runtime, projection.WorkerRouting),
	)
	for _, posture := range projection.WorkerPostures {
		input.WorkerPostures = sandboxSecurityCapabilityProjectionAppendWorkerPosture(input.WorkerPostures, posture)
	}
	for _, ready := range projection.Ready {
		input.Ready = sandboxSecurityCapabilityProjectionAppendUnique(input.Ready, ready)
	}
	return SanitizeSandboxSecurityCapabilityReadinessInput(input)
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
	switch mode {
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

func sandboxSecurityCapabilityProjectionAppendUnique(records []SandboxSecurityCapabilityMetadata, record SandboxSecurityCapabilityMetadata) []SandboxSecurityCapabilityMetadata {
	for _, existing := range records {
		if sandboxSecurityCapabilityProjectionSameMetadata(existing, record) {
			return records
		}
	}
	return append(records, record)
}

func sandboxSecurityCapabilityProjectionSameMetadata(a, b SandboxSecurityCapabilityMetadata) bool {
	return a.Family == b.Family &&
		a.Capability == b.Capability &&
		a.Mode == b.Mode &&
		a.Source == b.Source &&
		a.Status == b.Status &&
		a.ReasonCode == b.ReasonCode
}
