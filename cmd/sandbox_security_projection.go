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
	clone := &sandbox.SandboxSecurity{
		CapabilityReadiness:            capabilityReadiness,
		CapabilityReadinessDiagnostics: sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummaryPtr(capabilityReadiness),
		Network:                        sanitizeCommandSandboxNetworkSecurity(security.Network),
	}
	if security.Secrets != nil {
		secrets := *security.Secrets
		secrets.RequestedModes = append([]string(nil), security.Secrets.RequestedModes...)
		secrets.ActiveModes = append([]string(nil), security.Secrets.ActiveModes...)
		clone.Secrets = &secrets
	}
	if clone.Network == nil && clone.Secrets == nil && clone.CapabilityReadiness == nil {
		return nil
	}
	return clone
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
		out.PolicyEnforced = sandbox.SandboxNetworkPolicyBestEffort
		out.EnforcementMode = sandbox.SandboxNetworkEnforcementModeNone
	}
	if !commandSandboxNetworkSecurityHasAnyMetadata(out) {
		return nil
	}
	return out
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
