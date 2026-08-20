package cmd

import (
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func sanitizeCommandSandboxSecurity(security *sandbox.SandboxSecurity) *sandbox.SandboxSecurity {
	return sanitizeCommandSandboxSecurityWithNetworkProof(security, nil)
}

func sanitizeCommandSandboxSecurityWithNetworkProof(security *sandbox.SandboxSecurity, proof *sandbox.SandboxNetworkEnforcementProofMetadata) *sandbox.SandboxSecurity {
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
		StrictComposition:              sandbox.ProjectSandboxStrictCompositionDecisionPtr(security.StrictComposition, time.Now().UTC()),
		Network:                        sanitizeCommandSandboxNetworkSecurityWithProof(security.Network, proof),
	}
	clone.Secrets = sanitizeCommandSandboxSecretSecurity(security.Secrets)
	if clone.Network == nil && clone.Secrets == nil && clone.CapabilityReadiness == nil && clone.SecurityReadinessGate == nil && clone.StrictComposition == nil {
		return nil
	}
	return clone
}

func sanitizeCommandSandboxSecretSecurity(secrets *sandbox.SandboxSecretSecurity) *sandbox.SandboxSecretSecurity {
	if secrets == nil {
		return nil
	}
	out := &sandbox.SandboxSecretSecurity{
		RequestedModes: sanitizeCommandSandboxSecretModes(secrets.RequestedModes),
		ActiveModes:    sanitizeCommandSandboxSecretModes(secrets.ActiveModes),
	}
	if len(out.RequestedModes) == 0 && len(out.ActiveModes) == 0 {
		return nil
	}
	return out
}

func sanitizeCommandSandboxSecretModes(modes []string) []string {
	if len(modes) == 0 {
		return nil
	}
	out := make([]string, 0, len(modes))
	seen := make(map[string]struct{}, len(modes))
	for _, mode := range modes {
		mode = strings.TrimSpace(mode)
		switch mode {
		case sandbox.SandboxSecretModeEnv,
			sandbox.SandboxSecretModeFileTmpfs,
			sandbox.SandboxSecretModeSSHAgent,
			sandbox.SandboxSecretModeHTTPProxy,
			sandbox.SandboxSecretModeLegacyAuthSync:
		default:
			continue
		}
		if _, ok := seen[mode]; ok {
			continue
		}
		seen[mode] = struct{}{}
		out = append(out, mode)
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
	return sanitizeCommandSandboxNetworkSecurityWithProof(network, nil)
}

func sanitizeCommandSandboxNetworkSecurityWithProof(network *sandbox.SandboxNetworkSecurity, proof *sandbox.SandboxNetworkEnforcementProofMetadata) *sandbox.SandboxNetworkSecurity {
	if network == nil {
		return nil
	}
	proof = commandSandboxSanitizedNetworkEnforcementProof(proof)
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
	if commandSandboxNetworkSecurityHasActiveResult(out, proof) {
		out.EnforcementMode = commandSandboxNetworkEnforcementModeLabel(result.EnforcementMode)
		out.PolicyEnforced = commandSandboxNetworkPolicyLabelFromIntent(result.Effective)
	} else if commandSandboxNetworkSecurityHasAnyMetadata(out) {
		partialMode := commandSandboxNetworkPartialEnforcementMode(out.EnforcementMode, proof)
		out.PolicyEnforced = sandbox.SandboxNetworkPolicyBestEffort
		out.EnforcementMode = partialMode
		out.PolicyResult = commandSandboxNetworkBestEffortPolicyResult(out.PolicyResult, out.PolicyRequested)
	}
	if !commandSandboxNetworkSecurityHasAnyMetadata(out) {
		return nil
	}
	return out
}

func commandSandboxSanitizedNetworkEnforcementProof(proof *sandbox.SandboxNetworkEnforcementProofMetadata) *sandbox.SandboxNetworkEnforcementProofMetadata {
	if proof == nil {
		return nil
	}
	sanitized := sandbox.SanitizeSandboxNetworkEnforcementProofMetadata(*proof)
	if sanitized.NetworkProxySessionID == "" &&
		sanitized.PolicySnapshotID == "" &&
		sanitized.NetworkEnforcementPlanID == "" &&
		sanitized.ProxyLifecycleStatus == "" &&
		sanitized.ProxyLifecycleReasonCode == "" &&
		sanitized.FirewallLifecycleStatus == "" &&
		sanitized.FirewallLifecycleReasonCode == "" &&
		sanitized.ResultOutcome == "" &&
		sanitized.ResultEnforcementMode == "" &&
		!sanitized.ResultSupported {
		return nil
	}
	return &sanitized
}

func commandSandboxNetworkPartialEnforcementMode(mode string, proof *sandbox.SandboxNetworkEnforcementProofMetadata) string {
	switch commandSandboxNetworkEnforcementModeLabel(mode) {
	case sandbox.SandboxNetworkEnforcementModeProxy:
		if proof != nil && sandbox.SandboxNetworkEnforcementProofProvesActiveHTTPProxy(*proof) {
			return sandbox.SandboxNetworkEnforcementModeProxy
		}
		return sandbox.SandboxNetworkEnforcementModeNone
	case sandbox.SandboxNetworkEnforcementModeProxyFirewall:
		if proof != nil &&
			proof.ResultEnforcementMode == sandbox.SandboxNetworkEnforcementModeProxy &&
			sandbox.SandboxNetworkEnforcementProofProvesActiveHTTPProxy(*proof) {
			return sandbox.SandboxNetworkEnforcementModeProxy
		}
		return sandbox.SandboxNetworkEnforcementModeNone
	default:
		return sandbox.SandboxNetworkEnforcementModeNone
	}
}

func commandSandboxNetworkBestEffortPolicyResult(result *sandbox.SandboxNetworkPolicyResult, requestedPolicy string) *sandbox.SandboxNetworkPolicyResult {
	if result == nil {
		return nil
	}
	cloned := sandbox.CloneSandboxNetworkPolicyResult(*result)
	requested := cloned.Requested
	if requested.Preset == "" && len(requested.Rules) == 0 {
		switch commandSandboxNetworkPolicyLabel(requestedPolicy) {
		case sandbox.SandboxNetworkPolicyDenyByDefault:
			requested = sandbox.SandboxNetworkPolicyIntent{Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault}
		case sandbox.SandboxNetworkPolicyBestEffort:
			requested = sandbox.SandboxNetworkPolicyIntent{Preset: sandbox.SandboxNetworkPolicyPresetLegacyDefault}
		}
	}
	capability := cloned.Capability
	capability.SupportsDefaultDenyPosture = false
	downgraded := sandbox.EvaluateSandboxNetworkPolicy(requested, capability)
	return sandbox.CloneSandboxNetworkPolicyResultPtr(&downgraded)
}

func commandSandboxNetworkResultModeCanClaimActiveDefaultDeny(mode string) bool {
	switch mode {
	case sandbox.SandboxNetworkEnforcementModeFirewall,
		sandbox.SandboxNetworkEnforcementModeRuntime,
		sandbox.SandboxNetworkEnforcementModeProxyFirewall:
		return true
	default:
		return false
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

func commandSandboxNetworkSecurityHasActiveResult(network *sandbox.SandboxNetworkSecurity, proof *sandbox.SandboxNetworkEnforcementProofMetadata) bool {
	if network == nil || network.PolicyResult == nil {
		return false
	}
	result := network.PolicyResult
	mode := commandSandboxNetworkEnforcementModeLabel(result.EnforcementMode)
	if !commandSandboxNetworkEnforcementModeCanEnforce(mode) {
		return false
	}
	if !commandSandboxNetworkResultModeCanClaimActiveDefaultDeny(mode) {
		return false
	}
	if mode == sandbox.SandboxNetworkEnforcementModeProxyFirewall &&
		(proof == nil || !sandbox.SandboxNetworkEnforcementProofProvesActiveProxyFirewall(*proof)) {
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
