package networkenforcement

const (
	planOperationDefaultDeny           = "default_deny"
	planOperationAllowlist             = "allowlist"
	planOperationAllowlistDomain       = "allowlist_domain"
	planOperationAllowlistEndpoint     = "allowlist_endpoint"
	planOperationAllowlistPrivateRange = "allowlist_private_range"
	planOperationAllowlistMetadata     = "allowlist_metadata_endpoint"
	planOperationAllowlistLoopback     = "allowlist_loopback"
	planOperationAllowlistLinkLocal    = "allowlist_link_local"
	planOperationBlockPrivateNetwork   = "block_private_network"
	planOperationBlockMetadataEndpoint = "block_metadata_endpoint"
	planOperationBlockRawProtocols     = "block_raw_protocols"
	planOperationHTTPConnect           = "http_connect"
	planOperationHTTPSConnect          = "https_connect"
)

// PlanRequest contains inputs for pure network enforcement plan construction.
// AllowlistRules may carry validation-only raw policy values, but BuildPlan
// never copies those values into the public Plan. The request intentionally
// omits sockets, processes, host runtime handles, and adapter state.
type PlanRequest struct {
	ID              string
	Source          PlanSource
	Operation       string
	PolicySnapshot  *PolicySnapshotIdentity
	RequestedPolicy RequestedNetworkPosture
}

// RequestedNetworkPosture describes the network posture requested by policy
// data. Except for validation-only AllowlistRules values, fields are
// redaction-safe identifiers and enums.
type RequestedNetworkPosture struct {
	Preset            PolicyPreset
	DefaultPosture    DefaultPosture
	AllowlistMode     AllowlistMode
	RuleSetID         string
	RuleIDs           []string
	RuleCategories    []AllowlistRuleCategory
	AllowlistRules    []AllowlistRule
	PrivateNetwork    Posture
	MetadataEndpoint  Posture
	TCP               Posture
	UDP               Posture
	ICMP              Posture
	HTTP              ProxyRoutingMode
	HTTPS             ProxyRoutingMode
	ProxySessionID    string
	ProxyMechanism    EnforcementMechanism
	FirewallMode      FirewallIntentMode
	FirewallMechanism EnforcementMechanism
}

// AllowlistRule is validation-only requested policy input. Value may contain
// raw policy data and is never copied into a public Plan.
type AllowlistRule struct {
	ID       string
	Category AllowlistRuleCategory
	Value    string
}

// BuildPlan derives a sanitized network enforcement plan from requested policy
// metadata only. It performs no network, firewall, runtime, worker, process, or
// privilege operations.
func BuildPlan(request PlanRequest) Plan {
	requested := request.RequestedPolicy
	plan := Plan{
		ID:             request.ID,
		Source:         request.Source,
		Operation:      request.Operation,
		PolicySnapshot: buildPolicySnapshot(request.PolicySnapshot, requested),
		DefaultPosture: buildDefaultPosture(requested),
		Allowlist:      buildAllowlistPlan(requested),
		Category:       buildCategoryPosturePlan(requested),
		RawProtocols:   buildRawProtocolPlan(requested),
		Proxy:          buildProxyRoutingIntent(requested),
		Firewall:       buildFirewallIntent(requested),
	}
	return SanitizePlan(plan)
}

func buildPolicySnapshot(snapshot *PolicySnapshotIdentity, requested RequestedNetworkPosture) *PolicySnapshotIdentity {
	if snapshot == nil {
		return nil
	}
	out := *snapshot
	if out.Preset == "" {
		out.Preset = requested.Preset
	}
	if out.RuleSetID == "" {
		out.RuleSetID = requested.RuleSetID
	}
	return &out
}

func buildDefaultPosture(requested RequestedNetworkPosture) DefaultPosture {
	if posture := sanitizeDefaultPosture(requested.DefaultPosture); posture != "" {
		return posture
	}
	switch sanitizePolicyPreset(requested.Preset) {
	case PolicyPresetDenyByDefault, PolicyPresetAllowListed:
		return DefaultPostureDenyByDefault
	case PolicyPresetLegacyDefault:
		return DefaultPostureAllowByDefault
	case PolicyPresetDisabled, PolicyPresetNoPolicy:
		return DefaultPostureNoPolicy
	default:
		return ""
	}
}

func buildAllowlistPlan(requested RequestedNetworkPosture) *AllowlistPlan {
	mode := sanitizeAllowlistMode(requested.AllowlistMode)
	if mode == "" && sanitizePolicyPreset(requested.Preset) == PolicyPresetAllowListed {
		mode = AllowlistModeEnforce
	}

	ruleSetID := sanitizeIdentifier(requested.RuleSetID)
	normalizedRules := NormalizeAllowlistRules(requested.AllowlistRules)
	ruleIDs := appendSanitizedIdentifiers(sanitizeIdentifierList(requested.RuleIDs), normalizedRules.RuleIDs...)
	ruleCategories := mergeAllowlistRuleCategories(requested.RuleCategories, normalizedRules.RuleCategories)
	if mode == "" && ruleSetID == "" && len(ruleIDs) == 0 && len(ruleCategories) == 0 {
		return nil
	}

	operations := []string(nil)
	if mode == AllowlistModeEnforce || mode == AllowlistModeAudit || len(ruleIDs) > 0 || len(ruleCategories) > 0 {
		operations = append(operations, planOperationAllowlist)
	}
	operations = append(operations, operationsForAllowlistRuleCategories(ruleCategories)...)
	return &AllowlistPlan{
		Mode:           mode,
		RuleSetID:      ruleSetID,
		RuleIDs:        ruleIDs,
		RuleCategories: ruleCategories,
		Operations:     operations,
	}
}

func buildCategoryPosturePlan(requested RequestedNetworkPosture) *CategoryPosturePlan {
	privateNetwork := requestedCategoryPosture(requested.PrivateNetwork, requested.Preset)
	metadataEndpoint := requestedCategoryPosture(requested.MetadataEndpoint, requested.Preset)
	if privateNetwork == "" && metadataEndpoint == "" {
		return nil
	}
	return &CategoryPosturePlan{
		PrivateNetwork:   privateNetwork,
		MetadataEndpoint: metadataEndpoint,
	}
}

func requestedCategoryPosture(posture Posture, preset PolicyPreset) Posture {
	if sanitized := sanitizePosture(posture); sanitized != "" {
		return sanitized
	}
	if policyPresetRequestsDefaultDeny(preset) {
		return PostureBlock
	}
	return ""
}

func buildRawProtocolPlan(requested RequestedNetworkPosture) *RawProtocolPlan {
	tcp := sanitizePosture(requested.TCP)
	udp := sanitizePosture(requested.UDP)
	icmp := sanitizePosture(requested.ICMP)
	if tcp == "" && udp == "" && icmp == "" {
		return nil
	}
	return &RawProtocolPlan{TCP: tcp, UDP: udp, ICMP: icmp}
}

func buildProxyRoutingIntent(requested RequestedNetworkPosture) *ProxyRoutingIntent {
	http := sanitizeProxyRoutingMode(requested.HTTP)
	https := sanitizeProxyRoutingMode(requested.HTTPS)
	proxySessionID := sanitizeIdentifier(requested.ProxySessionID)
	mechanism := sanitizeEnforcementMechanism(requested.ProxyMechanism)
	if mechanism == "" && (http == ProxyRoutingModeRouteViaProxy || https == ProxyRoutingModeRouteViaProxy) {
		mechanism = EnforcementMechanismProxy
	}

	operations := []string(nil)
	if http == ProxyRoutingModeRouteViaProxy || http == ProxyRoutingModeBlock {
		operations = append(operations, planOperationHTTPConnect)
	}
	if https == ProxyRoutingModeRouteViaProxy || https == ProxyRoutingModeBlock {
		operations = append(operations, planOperationHTTPSConnect)
	}
	if http == "" && https == "" && proxySessionID == "" && mechanism == "" && len(operations) == 0 {
		return nil
	}
	return &ProxyRoutingIntent{
		HTTP:           http,
		HTTPS:          https,
		ProxySessionID: proxySessionID,
		Mechanism:      mechanism,
		Operations:     operations,
	}
}

func buildFirewallIntent(requested RequestedNetworkPosture) *FirewallIntent {
	mode := sanitizeFirewallIntentMode(requested.FirewallMode)
	mechanism := sanitizeEnforcementMechanism(requested.FirewallMechanism)
	operations := buildFirewallOperations(requested)
	if mode == "" && len(operations) > 0 {
		mode = FirewallIntentModePrepare
	}
	if mechanism == "" && len(operations) > 0 {
		mechanism = EnforcementMechanismFirewall
	}
	if mode == "" && mechanism == "" && len(operations) == 0 {
		return nil
	}
	return &FirewallIntent{
		Mode:       mode,
		Mechanism:  mechanism,
		Operations: operations,
	}
}

func buildFirewallOperations(requested RequestedNetworkPosture) []string {
	operations := []string(nil)
	if buildDefaultPosture(requested) == DefaultPostureDenyByDefault {
		operations = append(operations, planOperationDefaultDeny)
	}

	privateNetwork := requestedCategoryPosture(requested.PrivateNetwork, requested.Preset)
	if privateNetwork == PostureBlock {
		operations = append(operations, planOperationBlockPrivateNetwork)
	}
	metadataEndpoint := requestedCategoryPosture(requested.MetadataEndpoint, requested.Preset)
	if metadataEndpoint == PostureBlock {
		operations = append(operations, planOperationBlockMetadataEndpoint)
	}
	if sanitizePosture(requested.TCP) == PostureBlock ||
		sanitizePosture(requested.UDP) == PostureBlock ||
		sanitizePosture(requested.ICMP) == PostureBlock {
		operations = append(operations, planOperationBlockRawProtocols)
	}
	return operations
}

func policyPresetRequestsDefaultDeny(preset PolicyPreset) bool {
	switch sanitizePolicyPreset(preset) {
	case PolicyPresetDenyByDefault, PolicyPresetAllowListed:
		return true
	default:
		return false
	}
}
