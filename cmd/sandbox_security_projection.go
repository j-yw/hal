package cmd

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
)

func sanitizeCommandSandboxSecurity(security *sandbox.SandboxSecurity) *sandbox.SandboxSecurity {
	if security == nil {
		return nil
	}
	capabilityReadiness := sandbox.CloneSandboxSecurityCapabilityReadinessOutputPtr(security.CapabilityReadiness)
	capabilityReadinessDiagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummaryPtr(capabilityReadiness)
	if capabilityReadinessDiagnostics == nil {
		capabilityReadinessDiagnostics = cloneCommandSandboxSecurityCapabilityReadinessDiagnostics(security.CapabilityReadinessDiagnostics)
	}
	clone := &sandbox.SandboxSecurity{
		CapabilityReadiness:            capabilityReadiness,
		CapabilityReadinessDiagnostics: capabilityReadinessDiagnostics,
		SecurityReadinessGate:          sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(security.SecurityReadinessGate),
		Network:                        sanitizeCommandSandboxNetworkSecurity(security.Network),
	}
	if security.Secrets != nil {
		secrets := *security.Secrets
		secrets.RequestedModes = append([]string(nil), security.Secrets.RequestedModes...)
		secrets.ActiveModes = append([]string(nil), security.Secrets.ActiveModes...)
		clone.Secrets = &secrets
	}
	if clone.Network == nil && clone.Secrets == nil && clone.CapabilityReadiness == nil && clone.SecurityReadinessGate == nil {
		return nil
	}
	return clone
}

func cloneCommandSandboxSecurityCapabilityReadinessDiagnostics(diagnostics *sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary) *sandbox.SandboxSecurityCapabilityReadinessDiagnosticSummary {
	if diagnostics == nil {
		return nil
	}
	clone := *diagnostics
	clone.Items = append([]sandbox.SandboxSecurityCapabilityReadinessDiagnosticItem(nil), diagnostics.Items...)
	for i := range clone.Items {
		clone.Items[i].WarningCodes = append([]sandbox.SandboxSecurityCapabilityWarningCode(nil), diagnostics.Items[i].WarningCodes...)
	}
	return &clone
}

func applyCommandSandboxSecurityReadinessGate(security *sandbox.SandboxSecurity, mode sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode, explicitDecision *sandbox.SandboxSecurityCapabilityReadinessGateDecision) *sandbox.SandboxSecurity {
	if explicitDecision != nil {
		if security == nil {
			security = &sandbox.SandboxSecurity{}
		}
		security.SecurityReadinessGate = sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(explicitDecision)
		return sanitizeCommandSandboxSecurity(security)
	}

	effectiveMode := commandSandboxSecurityReadinessGateMode(mode)
	if effectiveMode == sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff {
		return security
	}
	if security == nil || security.CapabilityReadinessDiagnostics == nil {
		if !commandSandboxSecurityReadinessGateModeHasExplicitMissingDiagnostics(mode) &&
			effectiveMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict {
			return security
		}
		if security == nil {
			security = &sandbox.SandboxSecurity{}
		}
		if commandSandboxSecurityReadinessGateModeHasExplicitMissingDiagnostics(mode) {
			diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(sandbox.SandboxSecurityCapabilityReadinessOutput{})
			security.CapabilityReadinessDiagnostics = &diagnostics
		}
		decision := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(effectiveMode, security.CapabilityReadinessDiagnostics)
		security.SecurityReadinessGate = sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(&decision)
		return sanitizeCommandSandboxSecurity(security)
	}

	decision := sandbox.EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(effectiveMode, security.CapabilityReadinessDiagnostics)
	security.SecurityReadinessGate = sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(&decision)
	return sanitizeCommandSandboxSecurity(security)
}

func commandSandboxSecurityReadinessGateModeHasExplicitMissingDiagnostics(mode sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode) bool {
	switch mode {
	case sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory,
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility:
		return true
	default:
		return false
	}
}

func commandSandboxSecurityReadinessGateMode(mode sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode) sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode {
	switch mode {
	case sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory,
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff:
		return mode
	default:
		return sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility
	}
}

func sanitizeCommandSandboxNetworkSecurity(network *sandbox.SandboxNetworkSecurity) *sandbox.SandboxNetworkSecurity {
	if network == nil {
		return nil
	}
	result := sandbox.CloneSandboxNetworkPolicyResultPtr(network.PolicyResult)
	out := &sandbox.SandboxNetworkSecurity{
		PolicyRequested: commandSandboxNetworkPolicyLabel(network.PolicyRequested),
		PolicyEnforced:  commandSandboxNetworkPolicyLabel(network.PolicyEnforced),
		EnforcementMode: commandSandboxNetworkEnforcementModeLabel(network.EnforcementMode),
		PolicyResult:    result,
	}
	if out.PolicyRequested == "" && result != nil {
		out.PolicyRequested = commandSandboxNetworkPolicyLabelFromIntent(result.Requested)
	}
	if commandSandboxNetworkSecurityHasActiveResult(out) {
		out.EnforcementMode = commandSandboxNetworkEnforcementModeLabel(result.EnforcementMode)
		out.PolicyEnforced = commandSandboxNetworkPolicyLabelFromIntent(result.Effective)
	} else if commandSandboxNetworkSecurityHasAnyMetadata(out) {
		partialMode := commandSandboxNetworkPartialEnforcementMode(out.EnforcementMode)
		out.PolicyEnforced = sandbox.SandboxNetworkPolicyBestEffort
		out.EnforcementMode = partialMode
	}
	if !commandSandboxNetworkSecurityHasAnyMetadata(out) {
		return nil
	}
	return out
}

func commandSandboxNetworkPartialEnforcementMode(mode string) string {
	switch commandSandboxNetworkEnforcementModeLabel(mode) {
	case sandbox.SandboxNetworkEnforcementModeProxy:
		return sandbox.SandboxNetworkEnforcementModeProxy
	default:
		return sandbox.SandboxNetworkEnforcementModeNone
	}
}

func commandSandboxNetworkSecurityHasAnyMetadata(network *sandbox.SandboxNetworkSecurity) bool {
	if network == nil {
		return false
	}
	return network.PolicyRequested != "" ||
		network.PolicyEnforced != "" ||
		network.EnforcementMode != "" ||
		network.PolicyResult != nil
}

func commandSandboxNetworkSecurityHasActiveResult(network *sandbox.SandboxNetworkSecurity) bool {
	if network == nil || network.PolicyResult == nil {
		return false
	}
	result := network.PolicyResult
	mode := commandSandboxNetworkEnforcementModeLabel(result.EnforcementMode)
	if !commandSandboxNetworkEnforcementModeCanEnforce(mode) {
		return false
	}
	if len(result.Warnings) > 0 {
		return false
	}
	if !result.Capability.Supported || !commandSandboxNetworkCapabilityHasMode(result.Capability, mode) {
		return false
	}
	if commandSandboxNetworkPolicyIntentNeedsDefaultDeny(result.Effective) && !result.Capability.SupportsDefaultDenyPosture {
		return false
	}
	return commandSandboxNetworkPolicyLabelFromIntent(result.Effective) == sandbox.SandboxNetworkPolicyDenyByDefault
}

func commandSandboxNetworkPolicyLabel(value string) string {
	switch strings.TrimSpace(value) {
	case sandbox.SandboxNetworkPolicyDenyByDefault:
		return sandbox.SandboxNetworkPolicyDenyByDefault
	case sandbox.SandboxNetworkPolicyBestEffort:
		return sandbox.SandboxNetworkPolicyBestEffort
	default:
		return ""
	}
}

func commandSandboxNetworkPolicyLabelFromIntent(intent sandbox.SandboxNetworkPolicyIntent) string {
	switch intent.Preset {
	case sandbox.SandboxNetworkPolicyPresetDisabled,
		sandbox.SandboxNetworkPolicyPresetNoPolicy,
		sandbox.SandboxNetworkPolicyPresetLegacyDefault:
		return sandbox.SandboxNetworkPolicyBestEffort
	case sandbox.SandboxNetworkPolicyPresetAllowListed,
		sandbox.SandboxNetworkPolicyPresetDenyByDefault:
		return sandbox.SandboxNetworkPolicyDenyByDefault
	default:
		if len(intent.Rules) > 0 {
			return sandbox.SandboxNetworkPolicyDenyByDefault
		}
		return ""
	}
}

func commandSandboxNetworkEnforcementModeLabel(value string) string {
	switch strings.TrimSpace(value) {
	case sandbox.SandboxNetworkEnforcementModeNone:
		return sandbox.SandboxNetworkEnforcementModeNone
	case sandbox.SandboxNetworkEnforcementModeBestEffort:
		return sandbox.SandboxNetworkEnforcementModeBestEffort
	case sandbox.SandboxNetworkEnforcementModeProxy:
		return sandbox.SandboxNetworkEnforcementModeProxy
	case sandbox.SandboxNetworkEnforcementModeFirewall:
		return sandbox.SandboxNetworkEnforcementModeFirewall
	case sandbox.SandboxNetworkEnforcementModeRuntime:
		return sandbox.SandboxNetworkEnforcementModeRuntime
	case sandbox.SandboxNetworkEnforcementModeProxyFirewall:
		return sandbox.SandboxNetworkEnforcementModeProxyFirewall
	default:
		return ""
	}
}

func commandSandboxNetworkEnforcementModeCanEnforce(mode string) bool {
	switch mode {
	case sandbox.SandboxNetworkEnforcementModeProxy,
		sandbox.SandboxNetworkEnforcementModeFirewall,
		sandbox.SandboxNetworkEnforcementModeRuntime,
		sandbox.SandboxNetworkEnforcementModeProxyFirewall:
		return true
	default:
		return false
	}
}

func commandSandboxNetworkCapabilityHasMode(capability sandbox.SandboxNetworkPolicyEnforcementCapability, mode string) bool {
	for _, candidate := range capability.Modes {
		if commandSandboxNetworkEnforcementModeLabel(candidate) == mode {
			return true
		}
	}
	return false
}

func commandSandboxNetworkPolicyIntentNeedsDefaultDeny(intent sandbox.SandboxNetworkPolicyIntent) bool {
	switch intent.Preset {
	case sandbox.SandboxNetworkPolicyPresetAllowListed,
		sandbox.SandboxNetworkPolicyPresetDenyByDefault:
		return true
	default:
		return len(intent.Rules) > 0
	}
}
