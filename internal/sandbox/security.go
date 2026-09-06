package sandbox

import "strings"

// SecurityEvaluationRequest captures the runtime policy posture inputs needed
// to produce redaction-safe sandbox security metadata.
type SecurityEvaluationRequest struct {
	RuntimeDriver                string
	RequestedNetworkPolicy       string
	RequestedNetworkPolicyIntent *SandboxNetworkPolicyIntent
	NetworkPolicyCapability      *SandboxNetworkPolicyEnforcementCapability
	RequestedSecretModes         []string
	ActiveSecretModes            []string
	CompatibilityAuthSync        bool
}

// EvaluateSandboxSecurity returns honest Sandbox Runtime v2 security metadata
// for the currently supported compatibility execution path.
func EvaluateSandboxSecurity(req SecurityEvaluationRequest) *SandboxSecurity {
	return EvaluateSSHMachineCompatibilitySecurity(req)
}

// EvaluateSSHMachineCompatibilitySecurity returns metadata for the legacy
// SSH-machine path. It records the requested posture without claiming strict
// network enforcement that the compatibility runtime does not provide.
func EvaluateSSHMachineCompatibilitySecurity(req SecurityEvaluationRequest) *SandboxSecurity {
	requestedNetworkPolicy := compatibilityRequestedNetworkPolicyLabel(req)
	networkPolicyResult := evaluateCompatibilityNetworkPolicy(req, requestedNetworkPolicy)
	activeSecretModes := normalizeSandboxSecretModes(req.ActiveSecretModes)
	if req.CompatibilityAuthSync {
		activeSecretModes = appendSandboxSecretMode(activeSecretModes, SandboxSecretModeLegacyAuthSync)
	}

	security := &SandboxSecurity{
		Network: &SandboxNetworkSecurity{
			PolicyRequested: requestedNetworkPolicy,
			PolicyEnforced:  compatibilityEnforcedNetworkPolicy(networkPolicyResult),
			EnforcementMode: networkPolicyResult.EnforcementMode,
			PolicyResult:    CloneSandboxNetworkPolicyResultPtr(&networkPolicyResult),
		},
	}
	requestedSecretModes := normalizeSandboxSecretModes(req.RequestedSecretModes)
	if len(requestedSecretModes) > 0 || len(activeSecretModes) > 0 {
		security.Secrets = &SandboxSecretSecurity{
			RequestedModes: requestedSecretModes,
			ActiveModes:    activeSecretModes,
		}
	}
	return security
}

func evaluateCompatibilityNetworkPolicy(req SecurityEvaluationRequest, requestedNetworkPolicy string) SandboxNetworkPolicyResult {
	requested := compatibilityNetworkPolicyIntent(req, requestedNetworkPolicy)
	capability := SandboxNetworkPolicyEnforcementCapability{}
	if req.NetworkPolicyCapability != nil {
		capability = CloneSandboxNetworkPolicyEnforcementCapability(*req.NetworkPolicyCapability)
	}
	return EvaluateSandboxNetworkPolicy(requested, capability)
}

func compatibilityRequestedNetworkPolicyLabel(req SecurityEvaluationRequest) string {
	if req.RequestedNetworkPolicyIntent != nil {
		return compatibilityNetworkPolicyLabelForIntent(*req.RequestedNetworkPolicyIntent)
	}
	return normalizeSandboxNetworkPolicy(req.RequestedNetworkPolicy)
}

func compatibilityNetworkPolicyIntent(req SecurityEvaluationRequest, requestedNetworkPolicy string) SandboxNetworkPolicyIntent {
	if req.RequestedNetworkPolicyIntent != nil {
		return CloneSandboxNetworkPolicyIntent(*req.RequestedNetworkPolicyIntent)
	}
	switch requestedNetworkPolicy {
	case SandboxNetworkPolicyDenyByDefault:
		return SandboxNetworkPolicyIntent{Preset: SandboxNetworkPolicyPresetDenyByDefault}
	case SandboxNetworkPolicyBestEffort:
		return SandboxNetworkPolicyIntent{Preset: SandboxNetworkPolicyPresetLegacyDefault}
	default:
		return SandboxNetworkPolicyIntent{Preset: SandboxNetworkPolicyPresetDenyByDefault}
	}
}

func compatibilityEnforcedNetworkPolicy(result SandboxNetworkPolicyResult) string {
	if result.EnforcementMode == SandboxNetworkEnforcementModeNone ||
		result.EnforcementMode == SandboxNetworkEnforcementModeBestEffort {
		return SandboxNetworkPolicyBestEffort
	}
	if result.Effective.Preset == SandboxNetworkPolicyPresetDenyByDefault ||
		result.Effective.Preset == SandboxNetworkPolicyPresetAllowListed {
		return SandboxNetworkPolicyDenyByDefault
	}
	return SandboxNetworkPolicyBestEffort
}

func normalizeSandboxNetworkPolicy(policy string) string {
	switch strings.TrimSpace(policy) {
	case SandboxNetworkPolicyDenyByDefault:
		return SandboxNetworkPolicyDenyByDefault
	case SandboxNetworkPolicyBestEffort:
		return SandboxNetworkPolicyBestEffort
	default:
		return SandboxNetworkPolicyDenyByDefault
	}
}

func normalizeSandboxSecretModes(modes []string) []string {
	if len(modes) == 0 {
		return nil
	}
	out := make([]string, 0, len(modes))
	for _, mode := range modes {
		out = appendSandboxSecretMode(out, strings.TrimSpace(mode))
	}
	return out
}

func appendSandboxSecretMode(modes []string, mode string) []string {
	if !validSandboxSecretMode(mode) {
		return modes
	}
	for _, existing := range modes {
		if existing == mode {
			return modes
		}
	}
	return append(modes, mode)
}

func validSandboxSecretMode(mode string) bool {
	switch mode {
	case SandboxSecretModeEnv,
		SandboxSecretModeFileTmpfs,
		SandboxSecretModeSSHAgent,
		SandboxSecretModeHTTPProxy,
		SandboxSecretModeLegacyAuthSync:
		return true
	default:
		return false
	}
}
