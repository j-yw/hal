package sandbox

import "strings"

// EvaluateSandboxNetworkPolicy computes effective policy metadata from
// requested intent and runtime capability. It does not perform enforcement.
func EvaluateSandboxNetworkPolicy(requested SandboxNetworkPolicyIntent, capability SandboxNetworkPolicyEnforcementCapability) SandboxNetworkPolicyResult {
	result := SandboxNetworkPolicyResult{
		Requested:  cloneSandboxNetworkPolicyIntent(requested),
		Capability: cloneSandboxNetworkPolicyEnforcementCapability(capability),
	}

	effective := cloneSandboxNetworkPolicyIntent(requested)
	if !validRequestedSandboxNetworkPolicyPreset(requested.Preset) {
		result.Effective = sandboxNetworkPolicyLegacyDowngrade()
		result.EnforcementMode = SandboxNetworkEnforcementModeNone
		result.Warnings = append(result.Warnings, newSandboxNetworkPolicyWarning(
			SandboxNetworkPolicyWarningReasonPresetUnsupported,
			"preset",
		))
		return result
	}
	if !sandboxNetworkPolicyIntentNeedsEnforcement(requested) {
		result.Effective = effective
		result.EnforcementMode = SandboxNetworkEnforcementModeNone
		return result
	}

	mode := selectSandboxNetworkPolicyEnforcementMode(capability)
	if !sandboxNetworkPolicyModeCanEnforce(mode) {
		result.Effective = sandboxNetworkPolicyLegacyDowngrade()
		result.EnforcementMode = SandboxNetworkEnforcementModeNone
		result.Warnings = append(result.Warnings, newSandboxNetworkPolicyWarning(
			sandboxNetworkPolicyModeDowngradeReason(capability, mode),
			sandboxNetworkPolicyIntentIdentifier(requested),
		))
		return result
	}

	if sandboxNetworkPolicyPresetNeedsDefaultDeny(requested.Preset) && !capability.SupportsDefaultDenyPosture {
		result.Effective = sandboxNetworkPolicyLegacyDowngrade()
		result.EnforcementMode = SandboxNetworkEnforcementModeNone
		result.Warnings = append(result.Warnings, newSandboxNetworkPolicyWarning(
			SandboxNetworkPolicyWarningReasonDefaultDenyUnsupported,
			string(requested.Preset),
		))
		return result
	}

	effective.Rules = supportedSandboxNetworkPolicyRules(requested.Rules, capability, &result.Warnings)
	if !sandboxNetworkPolicyIntentNeedsEnforcement(effective) {
		mode = SandboxNetworkEnforcementModeNone
	}

	result.Effective = effective
	result.EnforcementMode = mode
	return result
}

func supportedSandboxNetworkPolicyRules(rules []SandboxNetworkPolicyRule, capability SandboxNetworkPolicyEnforcementCapability, warnings *[]SandboxNetworkPolicyWarning) []SandboxNetworkPolicyRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]SandboxNetworkPolicyRule, 0, len(rules))
	for _, rule := range rules {
		if sandboxNetworkPolicyRuleSupported(rule.Kind, capability) {
			out = append(out, rule)
			continue
		}
		*warnings = append(*warnings, newSandboxNetworkPolicyWarning(
			SandboxNetworkPolicyWarningReasonRuleKindUnsupported,
			"rule:"+sandboxNetworkPolicyRuleKindIdentifier(rule.Kind),
		))
	}
	return out
}

func selectSandboxNetworkPolicyEnforcementMode(capability SandboxNetworkPolicyEnforcementCapability) string {
	if !capability.Supported {
		return SandboxNetworkEnforcementModeNone
	}
	for _, mode := range []string{
		SandboxNetworkEnforcementModeProxyFirewall,
		SandboxNetworkEnforcementModeFirewall,
		SandboxNetworkEnforcementModeProxy,
		SandboxNetworkEnforcementModeRuntime,
		SandboxNetworkEnforcementModeBestEffort,
		SandboxNetworkEnforcementModeNone,
	} {
		if sandboxNetworkPolicyCapabilityHasMode(capability, mode) {
			return mode
		}
	}
	return SandboxNetworkEnforcementModeNone
}

func sandboxNetworkPolicyCapabilityHasMode(capability SandboxNetworkPolicyEnforcementCapability, mode string) bool {
	for _, candidate := range capability.Modes {
		if strings.TrimSpace(candidate) == mode {
			return true
		}
	}
	return false
}

func sandboxNetworkPolicyModeCanEnforce(mode string) bool {
	switch mode {
	case SandboxNetworkEnforcementModeProxyFirewall,
		SandboxNetworkEnforcementModeFirewall,
		SandboxNetworkEnforcementModeProxy,
		SandboxNetworkEnforcementModeRuntime:
		return true
	default:
		return false
	}
}

func sandboxNetworkPolicyModeDowngradeReason(capability SandboxNetworkPolicyEnforcementCapability, mode string) SandboxNetworkPolicyWarningReason {
	if !capability.Supported {
		return SandboxNetworkPolicyWarningReasonEnforcementUnsupported
	}
	if mode == SandboxNetworkEnforcementModeNone || mode == SandboxNetworkEnforcementModeBestEffort {
		return SandboxNetworkPolicyWarningReasonModeUnavailable
	}
	return SandboxNetworkPolicyWarningReasonEnforcementUnsupported
}

func sandboxNetworkPolicyIntentNeedsEnforcement(intent SandboxNetworkPolicyIntent) bool {
	switch intent.Preset {
	case SandboxNetworkPolicyPresetDisabled, SandboxNetworkPolicyPresetNoPolicy:
		return false
	case SandboxNetworkPolicyPresetAllowListed, SandboxNetworkPolicyPresetDenyByDefault:
		return true
	}
	return len(intent.Rules) > 0
}

func sandboxNetworkPolicyRuleSupported(kind SandboxNetworkPolicyRuleKind, capability SandboxNetworkPolicyEnforcementCapability) bool {
	switch kind {
	case SandboxNetworkPolicyRuleKindDomain:
		return capability.SupportsDomainRules
	case SandboxNetworkPolicyRuleKindEndpoint:
		return capability.SupportsEndpointRules
	case SandboxNetworkPolicyRuleKindPrivateRange:
		return capability.SupportsPrivateRangeRules
	case SandboxNetworkPolicyRuleKindMetadataEndpoint:
		return capability.SupportsMetadataEndpoint
	case SandboxNetworkPolicyRuleKindLoopback:
		return capability.SupportsLoopbackRules
	case SandboxNetworkPolicyRuleKindLinkLocal:
		return capability.SupportsLinkLocalRules
	default:
		return false
	}
}

func validRequestedSandboxNetworkPolicyPreset(preset SandboxNetworkPolicyPreset) bool {
	return preset == "" || validSandboxNetworkPolicyPreset(preset)
}

func sandboxNetworkPolicyLegacyDowngrade() SandboxNetworkPolicyIntent {
	return SandboxNetworkPolicyIntent{Preset: SandboxNetworkPolicyPresetLegacyDefault}
}

func sandboxNetworkPolicyIntentIdentifier(intent SandboxNetworkPolicyIntent) string {
	if intent.Preset != "" {
		return string(intent.Preset)
	}
	if len(intent.Rules) > 0 {
		return "rules"
	}
	return "unspecified"
}

func sandboxNetworkPolicyRuleKindIdentifier(kind SandboxNetworkPolicyRuleKind) string {
	if validSandboxNetworkPolicyRuleKind(kind) {
		return string(kind)
	}
	return "unsupported"
}

func newSandboxNetworkPolicyWarning(reason SandboxNetworkPolicyWarningReason, policy string) SandboxNetworkPolicyWarning {
	return SandboxNetworkPolicyWarning{
		Code:    SandboxNetworkPolicyWarningUnsupportedEnforcement,
		Policy:  policy,
		Reason:  reason,
		Message: sandboxNetworkPolicyWarningMessage(reason),
	}
}

func sandboxNetworkPolicyWarningMessage(reason SandboxNetworkPolicyWarningReason) string {
	switch reason {
	case SandboxNetworkPolicyWarningReasonEnforcementUnsupported:
		return "network policy enforcement is unsupported by this runtime"
	case SandboxNetworkPolicyWarningReasonModeUnavailable:
		return "network policy enforcement mode is unavailable for this runtime"
	case SandboxNetworkPolicyWarningReasonDefaultDenyUnsupported:
		return "network policy default-deny posture is unsupported by this runtime"
	case SandboxNetworkPolicyWarningReasonRuleKindUnsupported:
		return "network policy rule kind is unsupported by this runtime"
	case SandboxNetworkPolicyWarningReasonPresetUnsupported:
		return "network policy preset is unsupported"
	default:
		return "network policy was downgraded"
	}
}

// CloneSandboxNetworkPolicyResult returns a redaction-safe deep copy of network
// policy result metadata so callers can persist or attach it without sharing
// mutable slices. Rule values are intentionally omitted from durable result
// metadata; the result records rule kind/decision shape without storing raw
// domains, endpoints, local addresses, or credential-bearing strings.
func CloneSandboxNetworkPolicyResult(result SandboxNetworkPolicyResult) SandboxNetworkPolicyResult {
	out := result
	out.Requested = cloneSandboxNetworkPolicyIntentWithoutRuleValues(result.Requested)
	out.Effective = cloneSandboxNetworkPolicyIntentWithoutRuleValues(result.Effective)
	out.EnforcementMode = sanitizeSandboxNetworkPolicyEnforcementMode(result.EnforcementMode)
	out.Capability = CloneSandboxNetworkPolicyEnforcementCapability(result.Capability)
	if len(result.Warnings) > 0 {
		out.Warnings = sanitizeSandboxNetworkPolicyWarnings(result.Warnings)
	}
	return out
}

// CloneSandboxNetworkPolicyResultPtr returns nil for nil input or a deep copy
// for optional policy result metadata.
func CloneSandboxNetworkPolicyResultPtr(result *SandboxNetworkPolicyResult) *SandboxNetworkPolicyResult {
	if result == nil {
		return nil
	}
	cloned := CloneSandboxNetworkPolicyResult(*result)
	return &cloned
}

// CloneSandboxNetworkPolicyIntent returns a deep copy of policy intent
// metadata.
func CloneSandboxNetworkPolicyIntent(intent SandboxNetworkPolicyIntent) SandboxNetworkPolicyIntent {
	return cloneSandboxNetworkPolicyIntent(intent)
}

// CloneSandboxNetworkPolicyEnforcementCapability returns a deep copy of
// runtime network policy capability metadata.
func CloneSandboxNetworkPolicyEnforcementCapability(capability SandboxNetworkPolicyEnforcementCapability) SandboxNetworkPolicyEnforcementCapability {
	return cloneSandboxNetworkPolicyEnforcementCapability(capability)
}

func cloneSandboxNetworkPolicyIntent(intent SandboxNetworkPolicyIntent) SandboxNetworkPolicyIntent {
	out := SandboxNetworkPolicyIntent{Preset: intent.Preset}
	if len(intent.Rules) > 0 {
		out.Rules = append([]SandboxNetworkPolicyRule(nil), intent.Rules...)
	}
	return out
}

func cloneSandboxNetworkPolicyIntentWithoutRuleValues(intent SandboxNetworkPolicyIntent) SandboxNetworkPolicyIntent {
	out := SandboxNetworkPolicyIntent{Preset: intent.Preset}
	if len(intent.Rules) == 0 {
		return out
	}
	out.Rules = make([]SandboxNetworkPolicyRule, 0, len(intent.Rules))
	for _, rule := range intent.Rules {
		out.Rules = append(out.Rules, SandboxNetworkPolicyRule{
			Kind:     rule.Kind,
			Decision: rule.Decision,
		})
	}
	return out
}

func cloneSandboxNetworkPolicyEnforcementCapability(capability SandboxNetworkPolicyEnforcementCapability) SandboxNetworkPolicyEnforcementCapability {
	out := capability
	if len(capability.Modes) > 0 {
		out.Modes = make([]string, 0, len(capability.Modes))
		seen := make(map[string]struct{}, len(capability.Modes))
		for _, mode := range capability.Modes {
			safeMode := sanitizeSandboxNetworkPolicyEnforcementMode(mode)
			if safeMode == "" {
				continue
			}
			if _, ok := seen[safeMode]; ok {
				continue
			}
			seen[safeMode] = struct{}{}
			out.Modes = append(out.Modes, safeMode)
		}
		if len(out.Modes) == 0 {
			out.Modes = nil
		}
	}
	return out
}

func sanitizeSandboxNetworkPolicyEnforcementMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case SandboxNetworkEnforcementModeNone,
		SandboxNetworkEnforcementModeBestEffort,
		SandboxNetworkEnforcementModeProxy,
		SandboxNetworkEnforcementModeFirewall,
		SandboxNetworkEnforcementModeRuntime,
		SandboxNetworkEnforcementModeProxyFirewall:
		return strings.TrimSpace(mode)
	default:
		return ""
	}
}

func sanitizeSandboxNetworkPolicyWarnings(warnings []SandboxNetworkPolicyWarning) []SandboxNetworkPolicyWarning {
	if len(warnings) == 0 {
		return nil
	}
	out := make([]SandboxNetworkPolicyWarning, 0, len(warnings))
	for _, warning := range warnings {
		safeWarning, ok := sanitizeSandboxNetworkPolicyWarning(warning)
		if ok {
			out = append(out, safeWarning)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeSandboxNetworkPolicyWarning(warning SandboxNetworkPolicyWarning) (SandboxNetworkPolicyWarning, bool) {
	reason := warning.Reason
	if !validSandboxNetworkPolicyWarningReason(reason) {
		reason = ""
	}
	code := warning.Code
	if !validSandboxNetworkPolicyWarningCode(code) {
		code = ""
	}
	if code == "" && reason == "" {
		return SandboxNetworkPolicyWarning{}, false
	}
	safe := SandboxNetworkPolicyWarning{
		Code:   code,
		Reason: reason,
	}
	if validSandboxNetworkPolicyPreset(SandboxNetworkPolicyPreset(warning.Policy)) {
		safe.Policy = strings.TrimSpace(warning.Policy)
	}
	if safe.Reason != "" {
		safe.Message = sandboxNetworkPolicyWarningMessage(safe.Reason)
	}
	return safe, true
}

func validSandboxNetworkPolicyWarningCode(code SandboxNetworkPolicyWarningCode) bool {
	switch code {
	case SandboxNetworkPolicyWarningUnsupportedEnforcement:
		return true
	default:
		return false
	}
}

func validSandboxNetworkPolicyWarningReason(reason SandboxNetworkPolicyWarningReason) bool {
	switch reason {
	case SandboxNetworkPolicyWarningReasonEnforcementUnsupported,
		SandboxNetworkPolicyWarningReasonModeUnavailable,
		SandboxNetworkPolicyWarningReasonDefaultDenyUnsupported,
		SandboxNetworkPolicyWarningReasonRuleKindUnsupported,
		SandboxNetworkPolicyWarningReasonPresetUnsupported:
		return true
	default:
		return false
	}
}
