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
