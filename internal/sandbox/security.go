package sandbox

import "strings"

// SecurityEvaluationRequest captures the runtime policy posture inputs needed
// to produce redaction-safe sandbox security metadata.
type SecurityEvaluationRequest struct {
	RuntimeDriver          string
	RequestedNetworkPolicy string
	RequestedSecretModes   []string
	ActiveSecretModes      []string
	CompatibilityAuthSync  bool
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
	requestedNetworkPolicy := normalizeSandboxNetworkPolicy(req.RequestedNetworkPolicy)
	activeSecretModes := normalizeSandboxSecretModes(req.ActiveSecretModes)
	if req.CompatibilityAuthSync {
		activeSecretModes = appendSandboxSecretMode(activeSecretModes, SandboxSecretModeLegacyAuthSync)
	}

	security := &SandboxSecurity{
		Network: &SandboxNetworkSecurity{
			PolicyRequested: requestedNetworkPolicy,
			PolicyEnforced:  SandboxNetworkPolicyBestEffort,
			EnforcementMode: SandboxNetworkEnforcementModeNone,
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
