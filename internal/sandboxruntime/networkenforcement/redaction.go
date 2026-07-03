package networkenforcement

import (
	"encoding/json"
	"strings"
)

// SanitizePlan returns a redaction-safe copy of the public enforcement plan.
// Unsafe dynamic identifiers and labels are cleared so omitempty removes them
// from durable JSON.
func SanitizePlan(plan Plan) Plan {
	sanitized := Plan{
		ID:             sanitizeIdentifier(plan.ID),
		Source:         sanitizePlanSource(plan.Source),
		Operation:      sanitizeIdentifier(plan.Operation),
		DefaultPosture: sanitizeDefaultPosture(plan.DefaultPosture),
		PolicySnapshot: sanitizePolicySnapshotIdentityPtr(plan.PolicySnapshot),
		Allowlist:      sanitizeAllowlistPlanPtr(plan.Allowlist),
		Category:       sanitizeCategoryPosturePlanPtr(plan.Category),
		RawProtocols:   sanitizeRawProtocolPlanPtr(plan.RawProtocols),
		Proxy:          sanitizeProxyRoutingIntentPtr(plan.Proxy),
		Firewall:       sanitizeFirewallIntentPtr(plan.Firewall),
	}
	return sanitized
}

// MarshalJSON keeps the public plan JSON redaction-safe even when callers pass
// unsanitized contract values directly to encoding/json.
func (p Plan) MarshalJSON() ([]byte, error) {
	type planJSON Plan
	sanitized := SanitizePlan(p)
	return json.Marshal(planJSON(sanitized))
}

func (p PolicySnapshotIdentity) MarshalJSON() ([]byte, error) {
	type policySnapshotIdentityJSON PolicySnapshotIdentity
	sanitized := sanitizePolicySnapshotIdentity(p)
	return json.Marshal(policySnapshotIdentityJSON(sanitized))
}

func (p AllowlistPlan) MarshalJSON() ([]byte, error) {
	type allowlistPlanJSON AllowlistPlan
	sanitized := sanitizeAllowlistPlan(p)
	return json.Marshal(allowlistPlanJSON(sanitized))
}

func (p CategoryPosturePlan) MarshalJSON() ([]byte, error) {
	type categoryPosturePlanJSON CategoryPosturePlan
	sanitized := sanitizeCategoryPosturePlan(p)
	return json.Marshal(categoryPosturePlanJSON(sanitized))
}

func (p RawProtocolPlan) MarshalJSON() ([]byte, error) {
	type rawProtocolPlanJSON RawProtocolPlan
	sanitized := sanitizeRawProtocolPlan(p)
	return json.Marshal(rawProtocolPlanJSON(sanitized))
}

func (p ProxyRoutingIntent) MarshalJSON() ([]byte, error) {
	type proxyRoutingIntentJSON ProxyRoutingIntent
	sanitized := sanitizeProxyRoutingIntent(p)
	return json.Marshal(proxyRoutingIntentJSON(sanitized))
}

func (p FirewallIntent) MarshalJSON() ([]byte, error) {
	type firewallIntentJSON FirewallIntent
	sanitized := sanitizeFirewallIntent(p)
	return json.Marshal(firewallIntentJSON(sanitized))
}

func sanitizePolicySnapshotIdentityPtr(snapshot *PolicySnapshotIdentity) *PolicySnapshotIdentity {
	if snapshot == nil {
		return nil
	}
	sanitized := sanitizePolicySnapshotIdentity(*snapshot)
	if sanitized.ID == "" {
		return nil
	}
	return &sanitized
}

func sanitizePolicySnapshotIdentity(snapshot PolicySnapshotIdentity) PolicySnapshotIdentity {
	return PolicySnapshotIdentity{
		ID:        sanitizeIdentifier(snapshot.ID),
		Version:   sanitizeIdentifier(snapshot.Version),
		Preset:    sanitizePolicyPreset(snapshot.Preset),
		RuleSetID: sanitizeIdentifier(snapshot.RuleSetID),
	}
}

func sanitizeAllowlistPlanPtr(plan *AllowlistPlan) *AllowlistPlan {
	if plan == nil {
		return nil
	}
	sanitized := sanitizeAllowlistPlan(*plan)
	if sanitized.Mode == "" &&
		sanitized.RuleSetID == "" &&
		len(sanitized.RuleIDs) == 0 &&
		len(sanitized.RuleCategories) == 0 &&
		len(sanitized.Operations) == 0 {
		return nil
	}
	return &sanitized
}

func sanitizeAllowlistPlan(plan AllowlistPlan) AllowlistPlan {
	return AllowlistPlan{
		Mode:           sanitizeAllowlistMode(plan.Mode),
		RuleSetID:      sanitizeIdentifier(plan.RuleSetID),
		RuleIDs:        sanitizeIdentifierList(plan.RuleIDs),
		RuleCategories: sanitizeAllowlistRuleCategoryList(plan.RuleCategories),
		Operations:     sanitizeIdentifierList(plan.Operations),
	}
}

func sanitizeCategoryPosturePlanPtr(plan *CategoryPosturePlan) *CategoryPosturePlan {
	if plan == nil {
		return nil
	}
	sanitized := sanitizeCategoryPosturePlan(*plan)
	if sanitized.PrivateNetwork == "" && sanitized.MetadataEndpoint == "" {
		return nil
	}
	return &sanitized
}

func sanitizeCategoryPosturePlan(plan CategoryPosturePlan) CategoryPosturePlan {
	return CategoryPosturePlan{
		PrivateNetwork:   sanitizePosture(plan.PrivateNetwork),
		MetadataEndpoint: sanitizePosture(plan.MetadataEndpoint),
	}
}

func sanitizeRawProtocolPlanPtr(plan *RawProtocolPlan) *RawProtocolPlan {
	if plan == nil {
		return nil
	}
	sanitized := sanitizeRawProtocolPlan(*plan)
	if sanitized.TCP == "" && sanitized.UDP == "" && sanitized.ICMP == "" {
		return nil
	}
	return &sanitized
}

func sanitizeRawProtocolPlan(plan RawProtocolPlan) RawProtocolPlan {
	return RawProtocolPlan{
		TCP:  sanitizePosture(plan.TCP),
		UDP:  sanitizePosture(plan.UDP),
		ICMP: sanitizePosture(plan.ICMP),
	}
}

func sanitizeProxyRoutingIntentPtr(intent *ProxyRoutingIntent) *ProxyRoutingIntent {
	if intent == nil {
		return nil
	}
	sanitized := sanitizeProxyRoutingIntent(*intent)
	if sanitized.HTTP == "" &&
		sanitized.HTTPS == "" &&
		sanitized.ProxySessionID == "" &&
		sanitized.Mechanism == "" &&
		len(sanitized.Operations) == 0 {
		return nil
	}
	return &sanitized
}

func sanitizeProxyRoutingIntent(intent ProxyRoutingIntent) ProxyRoutingIntent {
	return ProxyRoutingIntent{
		HTTP:           sanitizeProxyRoutingMode(intent.HTTP),
		HTTPS:          sanitizeProxyRoutingMode(intent.HTTPS),
		ProxySessionID: sanitizeIdentifier(intent.ProxySessionID),
		Mechanism:      sanitizeEnforcementMechanism(intent.Mechanism),
		Operations:     sanitizeIdentifierList(intent.Operations),
	}
}

func sanitizeFirewallIntentPtr(intent *FirewallIntent) *FirewallIntent {
	if intent == nil {
		return nil
	}
	sanitized := sanitizeFirewallIntent(*intent)
	if sanitized.Mode == "" && sanitized.Mechanism == "" && len(sanitized.Operations) == 0 {
		return nil
	}
	return &sanitized
}

func sanitizeFirewallIntent(intent FirewallIntent) FirewallIntent {
	return FirewallIntent{
		Mode:       sanitizeFirewallIntentMode(intent.Mode),
		Mechanism:  sanitizeEnforcementMechanism(intent.Mechanism),
		Operations: sanitizeIdentifierList(intent.Operations),
	}
}

func sanitizeIdentifierList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(values))
	for _, value := range values {
		if current := sanitizeIdentifier(value); current != "" {
			sanitized = append(sanitized, current)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeAllowlistRuleCategoryList(values []AllowlistRuleCategory) []AllowlistRuleCategory {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]AllowlistRuleCategory, 0, len(values))
	for _, value := range values {
		if current := sanitizeAllowlistRuleCategory(value); current != "" {
			sanitized = append(sanitized, current)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || unsafeFreeformMetadata(value) {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return ""
		}
	}
	return value
}

func unsafeFreeformMetadata(value string) bool {
	if allDigits(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"@",
		"authorization",
		"bearer",
		"cookie",
		"header",
		"token",
		"secret",
		"credential",
		"password",
		"api-key",
		"api_key",
		"apikey",
		"access-key",
		"access_key",
		"private-key",
		"private_key",
		"process",
		"command",
		"iptables",
		"nftables",
		"pfctl",
		"firewall-cmd",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.Contains(value, ".") ||
		strings.ContainsAny(value, "/\\?#\r\n\t \"'`{}[]()<>|;&=$:~")
}

func allDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func sanitizePlanSource(value PlanSource) PlanSource {
	normalized := PlanSource(normalizeEnum(string(value)))
	switch normalized {
	case PlanSourceRuntime, PlanSourceWorker, PlanSourceMicroVM:
		return normalized
	default:
		return ""
	}
}

func sanitizePolicyPreset(value PolicyPreset) PolicyPreset {
	normalized := PolicyPreset(normalizeEnum(string(value)))
	switch normalized {
	case PolicyPresetDenyByDefault,
		PolicyPresetAllowListed,
		PolicyPresetLegacyDefault,
		PolicyPresetDisabled,
		PolicyPresetNoPolicy:
		return normalized
	default:
		return ""
	}
}

func sanitizeAllowlistMode(value AllowlistMode) AllowlistMode {
	normalized := AllowlistMode(normalizeEnum(string(value)))
	switch normalized {
	case AllowlistModeDisabled, AllowlistModeAudit, AllowlistModeEnforce:
		return normalized
	default:
		return ""
	}
}

func sanitizeAllowlistRuleCategory(value AllowlistRuleCategory) AllowlistRuleCategory {
	normalized := AllowlistRuleCategory(normalizeEnum(string(value)))
	switch normalized {
	case AllowlistRuleCategoryDomain,
		AllowlistRuleCategoryEndpoint,
		AllowlistRuleCategoryPrivateRange,
		AllowlistRuleCategoryMetadataEndpoint,
		AllowlistRuleCategoryLoopback,
		AllowlistRuleCategoryLinkLocal:
		return normalized
	default:
		return ""
	}
}

func sanitizePosture(value Posture) Posture {
	normalized := Posture(normalizeEnum(string(value)))
	switch normalized {
	case PostureUnspecified, PostureAllow, PostureBlock, PostureAudit:
		return normalized
	default:
		return ""
	}
}

func sanitizeDefaultPosture(value DefaultPosture) DefaultPosture {
	normalized := DefaultPosture(normalizeEnum(string(value)))
	switch normalized {
	case DefaultPostureDenyByDefault, DefaultPostureAllowByDefault, DefaultPostureNoPolicy:
		return normalized
	default:
		return ""
	}
}

func sanitizeEnforcementMechanism(value EnforcementMechanism) EnforcementMechanism {
	normalized := EnforcementMechanism(normalizeEnum(string(value)))
	switch normalized {
	case EnforcementMechanismNone,
		EnforcementMechanismProxy,
		EnforcementMechanismFirewall,
		EnforcementMechanismRuntime:
		return normalized
	default:
		return ""
	}
}

func sanitizeProxyRoutingMode(value ProxyRoutingMode) ProxyRoutingMode {
	normalized := ProxyRoutingMode(normalizeEnum(string(value)))
	switch normalized {
	case ProxyRoutingModeNone,
		ProxyRoutingModeRouteViaProxy,
		ProxyRoutingModeBypassProxy,
		ProxyRoutingModeBlock:
		return normalized
	default:
		return ""
	}
}

func sanitizeFirewallIntentMode(value FirewallIntentMode) FirewallIntentMode {
	normalized := FirewallIntentMode(normalizeEnum(string(value)))
	switch normalized {
	case FirewallIntentModeNone,
		FirewallIntentModePrepare,
		FirewallIntentModeApply,
		FirewallIntentModeAuditOnly:
		return normalized
	default:
		return ""
	}
}

func normalizeEnum(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
