package networkenforcement

// PlanSource identifies the component that prepared a network enforcement
// plan without importing command, factory, or worker packages.
type PlanSource string

const (
	PlanSourceRuntime PlanSource = "runtime"
	PlanSourceWorker  PlanSource = "worker"
	PlanSourceMicroVM PlanSource = "microvm"
)

// PolicyPreset identifies the policy shape requested by configuration using a
// safe durable value only.
type PolicyPreset string

const (
	PolicyPresetDenyByDefault PolicyPreset = "deny_by_default"
	PolicyPresetAllowListed   PolicyPreset = "allow_listed"
	PolicyPresetLegacyDefault PolicyPreset = "legacy_default"
	PolicyPresetDisabled      PolicyPreset = "disabled"
	PolicyPresetNoPolicy      PolicyPreset = "no_policy"
)

// AllowlistMode records how allowlist policy participates in the plan without
// carrying destination values.
type AllowlistMode string

const (
	AllowlistModeDisabled AllowlistMode = "disabled"
	AllowlistModeAudit    AllowlistMode = "audit"
	AllowlistModeEnforce  AllowlistMode = "enforce"
)

// AllowlistRuleCategory is a safe class of allowlist rule.
type AllowlistRuleCategory string

const (
	AllowlistRuleCategoryDomain           AllowlistRuleCategory = "domain"
	AllowlistRuleCategoryEndpoint         AllowlistRuleCategory = "endpoint"
	AllowlistRuleCategoryPrivateRange     AllowlistRuleCategory = "private_range"
	AllowlistRuleCategoryMetadataEndpoint AllowlistRuleCategory = "metadata_endpoint"
	AllowlistRuleCategoryLoopback         AllowlistRuleCategory = "loopback"
	AllowlistRuleCategoryLinkLocal        AllowlistRuleCategory = "link_local"
)

// Posture is a sanitized disposition for a network category or protocol.
type Posture string

const (
	PostureUnspecified Posture = "unspecified"
	PostureAllow       Posture = "allow"
	PostureBlock       Posture = "block"
	PostureAudit       Posture = "audit"
)

// DefaultPosture names the plan's fallback network posture.
type DefaultPosture string

const (
	DefaultPostureDenyByDefault  DefaultPosture = "deny_by_default"
	DefaultPostureAllowByDefault DefaultPosture = "allow_by_default"
	DefaultPostureNoPolicy       DefaultPosture = "no_policy"
)

// EnforcementMechanism identifies a planned enforcement mechanism without
// claiming that it has run.
type EnforcementMechanism string

const (
	EnforcementMechanismNone     EnforcementMechanism = "none"
	EnforcementMechanismProxy    EnforcementMechanism = "proxy"
	EnforcementMechanismFirewall EnforcementMechanism = "firewall"
	EnforcementMechanismRuntime  EnforcementMechanism = "runtime"
)

// ProxyRoutingMode identifies sanitized HTTP/HTTPS routing intent.
type ProxyRoutingMode string

const (
	ProxyRoutingModeNone          ProxyRoutingMode = "none"
	ProxyRoutingModeRouteViaProxy ProxyRoutingMode = "route_via_proxy"
	ProxyRoutingModeBypassProxy   ProxyRoutingMode = "bypass_proxy"
	ProxyRoutingModeBlock         ProxyRoutingMode = "block"
)

// FirewallIntentMode identifies sanitized firewall setup intent.
type FirewallIntentMode string

const (
	FirewallIntentModeNone      FirewallIntentMode = "none"
	FirewallIntentModePrepare   FirewallIntentMode = "prepare"
	FirewallIntentModeApply     FirewallIntentMode = "apply"
	FirewallIntentModeAuditOnly FirewallIntentMode = "audit_only"
)

// PolicySnapshotIdentity identifies the policy snapshot used to prepare a
// plan using safe durable identifiers only.
type PolicySnapshotIdentity struct {
	ID        string       `json:"id,omitempty"`
	Version   string       `json:"version,omitempty"`
	Preset    PolicyPreset `json:"preset,omitempty"`
	RuleSetID string       `json:"ruleSetId,omitempty"`
}

// Plan is the public network enforcement plan contract shared by runtime and
// worker code. It intentionally carries only identifiers, enum-like posture
// labels, operation names, policy snapshot identity, and proxy/firewall intent.
type Plan struct {
	ID             string                  `json:"id,omitempty"`
	Source         PlanSource              `json:"source,omitempty"`
	Operation      string                  `json:"operation,omitempty"`
	PolicySnapshot *PolicySnapshotIdentity `json:"policySnapshot,omitempty"`
	DefaultPosture DefaultPosture          `json:"defaultPosture,omitempty"`
	Allowlist      *AllowlistPlan          `json:"allowlist,omitempty"`
	Category       *CategoryPosturePlan    `json:"category,omitempty"`
	RawProtocols   *RawProtocolPlan        `json:"rawProtocols,omitempty"`
	Proxy          *ProxyRoutingIntent     `json:"proxy,omitempty"`
	Firewall       *FirewallIntent         `json:"firewall,omitempty"`
}

// AllowlistPlan represents allowlist policy by safe identifiers and categories
// only. It never carries destination values.
type AllowlistPlan struct {
	Mode           AllowlistMode           `json:"mode,omitempty"`
	RuleSetID      string                  `json:"ruleSetId,omitempty"`
	RuleIDs        []string                `json:"ruleIds,omitempty"`
	RuleCategories []AllowlistRuleCategory `json:"ruleCategories,omitempty"`
	Operations     []string                `json:"operations,omitempty"`
}

// CategoryPosturePlan captures special destination-class posture without raw
// destinations.
type CategoryPosturePlan struct {
	PrivateNetwork   Posture `json:"privateNetwork,omitempty"`
	MetadataEndpoint Posture `json:"metadataEndpoint,omitempty"`
}

// RawProtocolPlan records posture for raw transport protocols without exposing
// packets, peers, addresses, or ports.
type RawProtocolPlan struct {
	TCP  Posture `json:"tcp,omitempty"`
	UDP  Posture `json:"udp,omitempty"`
	ICMP Posture `json:"icmp,omitempty"`
}

// ProxyRoutingIntent captures HTTP/HTTPS proxy routing intent without listener
// addresses, socket names, or destination details.
type ProxyRoutingIntent struct {
	HTTP           ProxyRoutingMode     `json:"http,omitempty"`
	HTTPS          ProxyRoutingMode     `json:"https,omitempty"`
	ProxySessionID string               `json:"proxySessionId,omitempty"`
	Mechanism      EnforcementMechanism `json:"mechanism,omitempty"`
	Operations     []string             `json:"operations,omitempty"`
}

// FirewallIntent captures firewall setup intent without firewall commands,
// rule bodies, interface names, addresses, or ports.
type FirewallIntent struct {
	Mode       FirewallIntentMode   `json:"mode,omitempty"`
	Mechanism  EnforcementMechanism `json:"mechanism,omitempty"`
	Operations []string             `json:"operations,omitempty"`
}
