package sandbox

// SandboxNetworkPolicyDecisionSource identifies where a durable network policy
// decision record originated without importing command, factory, or worker
// packages.
type SandboxNetworkPolicyDecisionSource string

const (
	SandboxNetworkPolicyDecisionSourceRun     SandboxNetworkPolicyDecisionSource = "run"
	SandboxNetworkPolicyDecisionSourceAuto    SandboxNetworkPolicyDecisionSource = "auto"
	SandboxNetworkPolicyDecisionSourceFactory SandboxNetworkPolicyDecisionSource = "factory"
	SandboxNetworkPolicyDecisionSourceWorker  SandboxNetworkPolicyDecisionSource = "worker"
)

// SandboxNetworkPolicyDecisionOutcome is the durable result of a network policy
// decision. It records metadata only and does not imply live enforcement.
type SandboxNetworkPolicyDecisionOutcome string

const (
	SandboxNetworkPolicyDecisionOutcomeAllowed    SandboxNetworkPolicyDecisionOutcome = "allowed"
	SandboxNetworkPolicyDecisionOutcomeDenied     SandboxNetworkPolicyDecisionOutcome = "denied"
	SandboxNetworkPolicyDecisionOutcomeDowngraded SandboxNetworkPolicyDecisionOutcome = "downgraded"
	SandboxNetworkPolicyDecisionOutcomeAuditOnly  SandboxNetworkPolicyDecisionOutcome = "audit_only"
)

// SandboxNetworkPolicyDecisionReasonCode is a redaction-safe explanation for a
// policy decision.
type SandboxNetworkPolicyDecisionReasonCode string

const (
	SandboxNetworkPolicyDecisionReasonUnknown                SandboxNetworkPolicyDecisionReasonCode = "unknown"
	SandboxNetworkPolicyDecisionReasonMatchedAllowRule       SandboxNetworkPolicyDecisionReasonCode = "matched_allow_rule"
	SandboxNetworkPolicyDecisionReasonMatchedDenyRule        SandboxNetworkPolicyDecisionReasonCode = "matched_deny_rule"
	SandboxNetworkPolicyDecisionReasonDefaultAllow           SandboxNetworkPolicyDecisionReasonCode = "default_allow"
	SandboxNetworkPolicyDecisionReasonDefaultDeny            SandboxNetworkPolicyDecisionReasonCode = "default_deny"
	SandboxNetworkPolicyDecisionReasonPolicyDisabled         SandboxNetworkPolicyDecisionReasonCode = "policy_disabled"
	SandboxNetworkPolicyDecisionReasonPolicyDowngraded       SandboxNetworkPolicyDecisionReasonCode = "policy_downgraded"
	SandboxNetworkPolicyDecisionReasonEnforcementUnsupported SandboxNetworkPolicyDecisionReasonCode = "enforcement_unsupported"
	SandboxNetworkPolicyDecisionReasonAuditOnly              SandboxNetworkPolicyDecisionReasonCode = "audit_only"
)

// SandboxNetworkPolicyDestinationCategory is a safe destination class for
// request and decision metadata. It intentionally excludes raw hosts, IPs,
// ports, URLs, paths, and socket names.
type SandboxNetworkPolicyDestinationCategory string

const (
	SandboxNetworkPolicyDestinationPublicInternet  SandboxNetworkPolicyDestinationCategory = "public_internet"
	SandboxNetworkPolicyDestinationPrivateNetwork  SandboxNetworkPolicyDestinationCategory = "private_network"
	SandboxNetworkPolicyDestinationMetadataService SandboxNetworkPolicyDestinationCategory = "metadata_service"
	SandboxNetworkPolicyDestinationLoopback        SandboxNetworkPolicyDestinationCategory = "loopback"
	SandboxNetworkPolicyDestinationUnixSocket      SandboxNetworkPolicyDestinationCategory = "unix_socket"
	SandboxNetworkPolicyDestinationUnknown         SandboxNetworkPolicyDestinationCategory = "unknown"
)

// SandboxNetworkPolicySnapshotIdentity identifies the policy snapshot used for
// proxy and decision-log metadata using safe durable identifiers only.
type SandboxNetworkPolicySnapshotIdentity struct {
	ID        string                     `json:"id"`
	Version   string                     `json:"version,omitempty"`
	Preset    SandboxNetworkPolicyPreset `json:"preset,omitempty"`
	RuleSetID string                     `json:"ruleSetId,omitempty"`
}

// SandboxNetworkProxySessionMetadata captures durable proxy-session metadata
// without carrying listener endpoints, socket paths, or request details.
type SandboxNetworkProxySessionMetadata struct {
	ID              string                                `json:"id"`
	Source          SandboxNetworkPolicyDecisionSource    `json:"source"`
	PolicySnapshot  *SandboxNetworkPolicySnapshotIdentity `json:"policySnapshot,omitempty"`
	EnforcementMode string                                `json:"enforcementMode,omitempty"`
}

// SandboxNetworkPolicyRequestSummary is the sanitized request surface available
// to policy decision logs.
type SandboxNetworkPolicyRequestSummary struct {
	ID                  string                                  `json:"id,omitempty"`
	Operation           string                                  `json:"operation,omitempty"`
	DestinationCategory SandboxNetworkPolicyDestinationCategory `json:"destinationCategory,omitempty"`
}

// SandboxNetworkPolicyDecisionLogRecord is one durable, redaction-safe network
// policy decision entry.
type SandboxNetworkPolicyDecisionLogRecord struct {
	ID              string                                 `json:"id,omitempty"`
	Source          SandboxNetworkPolicyDecisionSource     `json:"source"`
	ProxySessionID  string                                 `json:"proxySessionId,omitempty"`
	PolicySnapshot  *SandboxNetworkPolicySnapshotIdentity  `json:"policySnapshot,omitempty"`
	Request         *SandboxNetworkPolicyRequestSummary    `json:"request,omitempty"`
	Outcome         SandboxNetworkPolicyDecisionOutcome    `json:"outcome"`
	ReasonCode      SandboxNetworkPolicyDecisionReasonCode `json:"reasonCode,omitempty"`
	RuleKind        SandboxNetworkPolicyRuleKind           `json:"ruleKind,omitempty"`
	PolicyPreset    SandboxNetworkPolicyPreset             `json:"policyPreset,omitempty"`
	EnforcementMode string                                 `json:"enforcementMode,omitempty"`
	Enforced        *bool                                  `json:"enforced,omitempty"`
}
