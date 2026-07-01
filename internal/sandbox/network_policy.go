package sandbox

// SandboxNetworkPolicyPreset is a stable durable identifier for requested
// sandbox network policy intent.
type SandboxNetworkPolicyPreset string

const (
	// SandboxNetworkPolicyPresetLegacyDefault captures the existing SSH-machine
	// compatibility posture: request restrictive intent without claiming strict
	// network enforcement.
	SandboxNetworkPolicyPresetLegacyDefault SandboxNetworkPolicyPreset = "legacy_default"
	SandboxNetworkPolicyPresetDefault       SandboxNetworkPolicyPreset = SandboxNetworkPolicyPresetLegacyDefault
	SandboxNetworkPolicyPresetAllowListed   SandboxNetworkPolicyPreset = "allow_listed"
	SandboxNetworkPolicyPresetDenyByDefault SandboxNetworkPolicyPreset = SandboxNetworkPolicyPreset(SandboxNetworkPolicyDenyByDefault)
	SandboxNetworkPolicyPresetDisabled      SandboxNetworkPolicyPreset = "disabled"
	SandboxNetworkPolicyPresetNoPolicy      SandboxNetworkPolicyPreset = "no_policy"
)

// SandboxNetworkPolicyRuleKind identifies the data-only type of a network
// policy rule. Validation and enforcement are intentionally separate concerns.
type SandboxNetworkPolicyRuleKind string

const (
	SandboxNetworkPolicyRuleKindDomain           SandboxNetworkPolicyRuleKind = "domain"
	SandboxNetworkPolicyRuleKindEndpoint         SandboxNetworkPolicyRuleKind = "endpoint"
	SandboxNetworkPolicyRuleKindPrivateRange     SandboxNetworkPolicyRuleKind = "private_range"
	SandboxNetworkPolicyRuleKindMetadataEndpoint SandboxNetworkPolicyRuleKind = "metadata_endpoint"
	SandboxNetworkPolicyRuleKindLoopback         SandboxNetworkPolicyRuleKind = "loopback"
	SandboxNetworkPolicyRuleKindLinkLocal        SandboxNetworkPolicyRuleKind = "link_local"
)

// SandboxNetworkPolicyDecision records policy intent for a rule without
// implying that a runtime can enforce it.
type SandboxNetworkPolicyDecision string

const (
	SandboxNetworkPolicyDecisionAllow SandboxNetworkPolicyDecision = "allow"
	SandboxNetworkPolicyDecisionDeny  SandboxNetworkPolicyDecision = "deny"
)

// SandboxNetworkPolicyRule is a data-only representation of requested network
// policy intent. Rule values are validated by later policy validation code.
type SandboxNetworkPolicyRule struct {
	Kind     SandboxNetworkPolicyRuleKind `json:"kind"`
	Value    string                       `json:"value,omitempty"`
	Decision SandboxNetworkPolicyDecision `json:"decision"`
}

// SandboxNetworkPolicyIntent captures requested or effective policy shape
// without carrying runtime enforcement capability.
type SandboxNetworkPolicyIntent struct {
	Preset SandboxNetworkPolicyPreset `json:"preset,omitempty"`
	Rules  []SandboxNetworkPolicyRule `json:"rules,omitempty"`
}

// SandboxNetworkPolicyEnforcementCapability describes what a runtime reports
// it can enforce. It is separate from requested intent and effective result.
type SandboxNetworkPolicyEnforcementCapability struct {
	Supported                  bool     `json:"supported"`
	Modes                      []string `json:"modes,omitempty"`
	SupportsDomainRules        bool     `json:"supportsDomainRules"`
	SupportsEndpointRules      bool     `json:"supportsEndpointRules"`
	SupportsPrivateRangeRules  bool     `json:"supportsPrivateRangeRules"`
	SupportsMetadataEndpoint   bool     `json:"supportsMetadataEndpoint"`
	SupportsLoopbackRules      bool     `json:"supportsLoopbackRules"`
	SupportsLinkLocalRules     bool     `json:"supportsLinkLocalRules"`
	SupportsDefaultDenyPosture bool     `json:"supportsDefaultDenyPosture"`
}

// SandboxNetworkPolicyWarningCode is a redaction-safe policy warning code.
type SandboxNetworkPolicyWarningCode string

const (
	SandboxNetworkPolicyWarningUnsupportedEnforcement SandboxNetworkPolicyWarningCode = "unsupported_enforcement"
)

// SandboxNetworkPolicyWarningReason is a redaction-safe downgrade reason.
type SandboxNetworkPolicyWarningReason string

const (
	SandboxNetworkPolicyWarningReasonEnforcementUnsupported SandboxNetworkPolicyWarningReason = "enforcement_unsupported"
	SandboxNetworkPolicyWarningReasonModeUnavailable        SandboxNetworkPolicyWarningReason = "enforcement_mode_unavailable"
	SandboxNetworkPolicyWarningReasonDefaultDenyUnsupported SandboxNetworkPolicyWarningReason = "default_deny_unsupported"
	SandboxNetworkPolicyWarningReasonRuleKindUnsupported    SandboxNetworkPolicyWarningReason = "rule_kind_unsupported"
	SandboxNetworkPolicyWarningReasonPresetUnsupported      SandboxNetworkPolicyWarningReason = "preset_unsupported"
)

// SandboxNetworkPolicyWarning contains safe metadata about policy downgrades or
// ignored data. It must not include endpoints, credentials, or raw rule values.
type SandboxNetworkPolicyWarning struct {
	Code    SandboxNetworkPolicyWarningCode   `json:"code"`
	Policy  string                            `json:"policy,omitempty"`
	Reason  SandboxNetworkPolicyWarningReason `json:"reason,omitempty"`
	Message string                            `json:"message,omitempty"`
}

// SandboxNetworkPolicyResult separates requested intent, effective intent,
// runtime capability, and the selected enforcement mode.
type SandboxNetworkPolicyResult struct {
	Requested       SandboxNetworkPolicyIntent                `json:"requested"`
	Effective       SandboxNetworkPolicyIntent                `json:"effective"`
	EnforcementMode string                                    `json:"enforcementMode,omitempty"`
	Capability      SandboxNetworkPolicyEnforcementCapability `json:"capability"`
	Warnings        []SandboxNetworkPolicyWarning             `json:"warnings,omitempty"`
}

func sandboxNetworkPolicyPresetNeedsDefaultDeny(preset SandboxNetworkPolicyPreset) bool {
	switch preset {
	case SandboxNetworkPolicyPresetAllowListed, SandboxNetworkPolicyPresetDenyByDefault:
		return true
	default:
		return false
	}
}
