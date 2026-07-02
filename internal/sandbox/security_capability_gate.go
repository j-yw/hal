package sandbox

// SandboxSecurityCapabilityReadinessGatePolicyMode is the opt-in policy mode
// for readiness gate decisions.
type SandboxSecurityCapabilityReadinessGatePolicyMode string

const (
	SandboxSecurityCapabilityReadinessGatePolicyModeOff      SandboxSecurityCapabilityReadinessGatePolicyMode = "off"
	SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory SandboxSecurityCapabilityReadinessGatePolicyMode = "advisory"
	SandboxSecurityCapabilityReadinessGatePolicyModeStrict   SandboxSecurityCapabilityReadinessGatePolicyMode = "strict"
)

// SandboxSecurityCapabilityReadinessGateOutcome is the stable machine result
// of applying a readiness gate policy.
type SandboxSecurityCapabilityReadinessGateOutcome string

const (
	SandboxSecurityCapabilityReadinessGateOutcomeAllowed  SandboxSecurityCapabilityReadinessGateOutcome = "allowed"
	SandboxSecurityCapabilityReadinessGateOutcomeAdvisory SandboxSecurityCapabilityReadinessGateOutcome = "advisory"
	SandboxSecurityCapabilityReadinessGateOutcomeBlocked  SandboxSecurityCapabilityReadinessGateOutcome = "blocked"
)

// SandboxSecurityCapabilityReadinessGateCode is a redaction-safe decision
// code for readiness gate metadata.
type SandboxSecurityCapabilityReadinessGateCode string

const (
	SandboxSecurityCapabilityReadinessGateCodeAllowed  SandboxSecurityCapabilityReadinessGateCode = "security_readiness_gate_allowed"
	SandboxSecurityCapabilityReadinessGateCodeAdvisory SandboxSecurityCapabilityReadinessGateCode = "security_readiness_gate_advisory"
	SandboxSecurityCapabilityReadinessGateCodeBlocked  SandboxSecurityCapabilityReadinessGateCode = "security_readiness_gate_blocked"
)

// SandboxSecurityCapabilityReadinessGateReasonCode is a redaction-safe
// explanation label for a readiness gate decision.
type SandboxSecurityCapabilityReadinessGateReasonCode string

const (
	SandboxSecurityCapabilityReadinessGateReasonPolicyOff             SandboxSecurityCapabilityReadinessGateReasonCode = "policy_off"
	SandboxSecurityCapabilityReadinessGateReasonPolicyAdvisory        SandboxSecurityCapabilityReadinessGateReasonCode = "policy_advisory"
	SandboxSecurityCapabilityReadinessGateReasonReadinessReady        SandboxSecurityCapabilityReadinessGateReasonCode = "readiness_ready"
	SandboxSecurityCapabilityReadinessGateReasonReadinessMissing      SandboxSecurityCapabilityReadinessGateReasonCode = "readiness_missing"
	SandboxSecurityCapabilityReadinessGateReasonMetadataOnly          SandboxSecurityCapabilityReadinessGateReasonCode = "metadata_only"
	SandboxSecurityCapabilityReadinessGateReasonCapabilityUnsupported SandboxSecurityCapabilityReadinessGateReasonCode = "capability_unsupported"
	SandboxSecurityCapabilityReadinessGateReasonCapabilityBlocked     SandboxSecurityCapabilityReadinessGateReasonCode = "capability_blocked"
	SandboxSecurityCapabilityReadinessGateReasonStrictBlockRequired   SandboxSecurityCapabilityReadinessGateReasonCode = "strict_block_required"
	SandboxSecurityCapabilityReadinessGateReasonUnknown               SandboxSecurityCapabilityReadinessGateReasonCode = "unknown"
)

// SandboxSecurityCapabilityReadinessGateCounts carries aggregate diagnostic
// counts only. It must not include raw policy values or runtime metadata.
type SandboxSecurityCapabilityReadinessGateCounts struct {
	Total          int `json:"total,omitempty"`
	Ready          int `json:"ready,omitempty"`
	Advisory       int `json:"advisory,omitempty"`
	Blocked        int `json:"blocked,omitempty"`
	Missing        int `json:"missing,omitempty"`
	MetadataOnly   int `json:"metadataOnly,omitempty"`
	Unsupported    int `json:"unsupported,omitempty"`
	StrictBlocking int `json:"strictBlocking,omitempty"`
}

// SandboxSecurityCapabilityReadinessGateDecision is the additive,
// redaction-safe readiness gate metadata surface.
type SandboxSecurityCapabilityReadinessGateDecision struct {
	Code       SandboxSecurityCapabilityReadinessGateCode       `json:"code,omitempty"`
	Outcome    SandboxSecurityCapabilityReadinessGateOutcome    `json:"outcome,omitempty"`
	PolicyMode SandboxSecurityCapabilityReadinessGatePolicyMode `json:"policyMode,omitempty"`
	Reason     SandboxSecurityCapabilityReadinessGateReasonCode `json:"reason,omitempty"`
	Counts     *SandboxSecurityCapabilityReadinessGateCounts    `json:"counts,omitempty"`
}
