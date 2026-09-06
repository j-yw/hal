package networkenforcement

import (
	"encoding/json"
	"net/netip"
	"strings"
)

// PolicyProxyRequestKind identifies the sanitized request class evaluated at
// the policy proxy boundary.
type PolicyProxyRequestKind string

const (
	PolicyProxyRequestKindHTTPConnect     PolicyProxyRequestKind = "http_connect"
	PolicyProxyRequestKindHTTPRequestHost PolicyProxyRequestKind = "http_request_host"
)

// PolicyProxyDecisionAction identifies the sanitized proxy policy decision.
type PolicyProxyDecisionAction string

const (
	PolicyProxyDecisionActionAllow PolicyProxyDecisionAction = "allow"
	PolicyProxyDecisionActionDeny  PolicyProxyDecisionAction = "deny"
)

// PolicyProxyDecisionReasonCode is a redaction-safe reason label for policy
// proxy allow/deny decisions.
type PolicyProxyDecisionReasonCode string

const (
	PolicyProxyDecisionReasonAllowRuleMatched            PolicyProxyDecisionReasonCode = "allow_rule_matched"
	PolicyProxyDecisionReasonDefaultDenyNoAllowRule      PolicyProxyDecisionReasonCode = "default_deny_no_allow_rule"
	PolicyProxyDecisionReasonUnsafeDestinationBlocked    PolicyProxyDecisionReasonCode = "unsafe_destination_blocked"
	PolicyProxyDecisionReasonResolvedDestinationBlocked  PolicyProxyDecisionReasonCode = "resolved_destination_blocked"
	PolicyProxyDecisionReasonDestinationResolutionFailed PolicyProxyDecisionReasonCode = "destination_resolution_failed"
	PolicyProxyDecisionReasonRequestBoundsExceeded       PolicyProxyDecisionReasonCode = "request_bounds_exceeded"
	PolicyProxyDecisionReasonResponseBoundsExceeded      PolicyProxyDecisionReasonCode = "response_bounds_exceeded"
	PolicyProxyDecisionReasonUpstreamUnavailable         PolicyProxyDecisionReasonCode = "upstream_unavailable"
	PolicyProxyDecisionReasonProxyUnsupported            PolicyProxyDecisionReasonCode = "policy_proxy_unsupported"
)

// PolicyProxyDecisionPolicy carries the sanitized plan plus validation-only
// allowlist rules needed by the future in-memory proxy matcher. Raw rule values
// must never be copied into PolicyProxyDecision metadata.
type PolicyProxyDecisionPolicy struct {
	Plan           Plan
	AllowlistRules []AllowlistRule
}

// PolicyProxyDecisionRequest contains raw request data used only for an
// in-memory proxy decision. It is intentionally not durable metadata.
type PolicyProxyDecisionRequest struct {
	Kind      PolicyProxyRequestKind
	Authority string
	Host      string
}

// PolicyProxyDecision records only sanitized proxy policy decision metadata.
type PolicyProxyDecision struct {
	Action         PolicyProxyDecisionAction     `json:"action,omitempty"`
	RequestKind    PolicyProxyRequestKind        `json:"requestKind,omitempty"`
	PolicySnapshot *PolicySnapshotIdentity       `json:"policySnapshot,omitempty"`
	RuleSetID      string                        `json:"ruleSetId,omitempty"`
	RuleID         string                        `json:"ruleId,omitempty"`
	RuleCategory   AllowlistRuleCategory         `json:"ruleCategory,omitempty"`
	ReasonCode     PolicyProxyDecisionReasonCode `json:"reasonCode,omitempty"`
}

// EvaluatePolicyProxyDecision evaluates one HTTP(S) policy proxy request
// against the sanitized enforcement plan's allowlist metadata. Raw rule values
// and request destinations are used only for in-memory matching and are never
// copied into the returned decision.
func EvaluatePolicyProxyDecision(policy PolicyProxyDecisionPolicy, request PolicyProxyDecisionRequest) PolicyProxyDecision {
	plan := SanitizePlan(policy.Plan)
	requestKind := sanitizePolicyProxyRequestKind(request.Kind)
	decision := PolicyProxyDecision{
		Action:         PolicyProxyDecisionActionDeny,
		RequestKind:    requestKind,
		PolicySnapshot: sanitizePolicySnapshotIdentityPtr(plan.PolicySnapshot),
		RuleSetID:      policyProxyDecisionRuleSetID(plan),
		ReasonCode:     PolicyProxyDecisionReasonDefaultDenyNoAllowRule,
	}
	if requestKind == "" {
		decision.ReasonCode = PolicyProxyDecisionReasonProxyUnsupported
		return SanitizePolicyProxyDecision(decision)
	}

	target := policyProxyRequestTargetFromRequest(request)
	if !target.valid {
		return SanitizePolicyProxyDecision(decision)
	}

	if category := policyProxyBlockedUnsafeDestinationCategory(plan, target); category != "" {
		decision.RuleCategory = category
		decision.ReasonCode = PolicyProxyDecisionReasonUnsafeDestinationBlocked
		return SanitizePolicyProxyDecision(decision)
	}

	if !policyProxyDecisionAllowlistEnabled(plan) {
		return SanitizePolicyProxyDecision(decision)
	}

	for _, rule := range policy.AllowlistRules {
		if !policyProxyPlanSupportsRule(plan, rule) || !policyProxyRuleMatchesTarget(rule, target) {
			continue
		}
		decision.Action = PolicyProxyDecisionActionAllow
		decision.RuleID = sanitizeIdentifier(rule.ID)
		decision.RuleCategory = sanitizeAllowlistRuleCategory(rule.Category)
		decision.ReasonCode = PolicyProxyDecisionReasonAllowRuleMatched
		break
	}
	return SanitizePolicyProxyDecision(decision)
}

// SanitizePolicyProxyDecision returns a redaction-safe copy of decision
// metadata before it is reported or persisted.
func SanitizePolicyProxyDecision(decision PolicyProxyDecision) PolicyProxyDecision {
	return PolicyProxyDecision{
		Action:         sanitizePolicyProxyDecisionAction(decision.Action),
		RequestKind:    sanitizePolicyProxyRequestKind(decision.RequestKind),
		PolicySnapshot: sanitizePolicySnapshotIdentityPtr(decision.PolicySnapshot),
		RuleSetID:      sanitizeIdentifier(decision.RuleSetID),
		RuleID:         sanitizeIdentifier(decision.RuleID),
		RuleCategory:   sanitizeAllowlistRuleCategory(decision.RuleCategory),
		ReasonCode:     sanitizePolicyProxyDecisionReasonCode(decision.ReasonCode),
	}
}

// MarshalJSON keeps public decision JSON sanitized even when callers pass
// unsanitized contract values directly to encoding/json.
func (d PolicyProxyDecision) MarshalJSON() ([]byte, error) {
	type decisionJSON PolicyProxyDecision
	sanitized := SanitizePolicyProxyDecision(d)
	return json.Marshal(decisionJSON(sanitized))
}

func sanitizePolicyProxyRequestKind(value PolicyProxyRequestKind) PolicyProxyRequestKind {
	normalized := PolicyProxyRequestKind(normalizeEnum(string(value)))
	switch normalized {
	case PolicyProxyRequestKindHTTPConnect,
		PolicyProxyRequestKindHTTPRequestHost:
		return normalized
	default:
		return ""
	}
}

func sanitizePolicyProxyDecisionAction(value PolicyProxyDecisionAction) PolicyProxyDecisionAction {
	normalized := PolicyProxyDecisionAction(normalizeEnum(string(value)))
	switch normalized {
	case PolicyProxyDecisionActionAllow,
		PolicyProxyDecisionActionDeny:
		return normalized
	default:
		return ""
	}
}

func sanitizePolicyProxyDecisionReasonCode(value PolicyProxyDecisionReasonCode) PolicyProxyDecisionReasonCode {
	normalized := PolicyProxyDecisionReasonCode(normalizeEnum(string(value)))
	switch normalized {
	case PolicyProxyDecisionReasonAllowRuleMatched,
		PolicyProxyDecisionReasonDefaultDenyNoAllowRule,
		PolicyProxyDecisionReasonUnsafeDestinationBlocked,
		PolicyProxyDecisionReasonResolvedDestinationBlocked,
		PolicyProxyDecisionReasonDestinationResolutionFailed,
		PolicyProxyDecisionReasonRequestBoundsExceeded,
		PolicyProxyDecisionReasonResponseBoundsExceeded,
		PolicyProxyDecisionReasonUpstreamUnavailable,
		PolicyProxyDecisionReasonProxyUnsupported:
		return normalized
	default:
		return ""
	}
}

type policyProxyRequestTarget struct {
	host    string
	port    string
	hasPort bool
	valid   bool
}

func policyProxyRequestTargetFromRequest(request PolicyProxyDecisionRequest) policyProxyRequestTarget {
	switch sanitizePolicyProxyRequestKind(request.Kind) {
	case PolicyProxyRequestKindHTTPConnect:
		return parsePolicyProxyRequestTarget(request.Authority)
	case PolicyProxyRequestKindHTTPRequestHost:
		return parsePolicyProxyRequestTarget(request.Host)
	default:
		return policyProxyRequestTarget{}
	}
}

func parsePolicyProxyRequestTarget(value string) policyProxyRequestTarget {
	value = strings.TrimSpace(value)
	if value == "" || unsafeAllowlistRuleValue(value) {
		return policyProxyRequestTarget{}
	}
	host, port, hasPort := splitPolicyProxyRequestTarget(value)
	host = normalizePolicyProxyHost(host)
	if host == "" {
		return policyProxyRequestTarget{}
	}
	return policyProxyRequestTarget{
		host:    host,
		port:    port,
		hasPort: hasPort,
		valid:   true,
	}
}

func splitPolicyProxyRequestTarget(value string) (host string, port string, hasPort bool) {
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end <= 1 {
			return value, "", false
		}
		host = value[1:end]
		if len(value) > end+1 && value[end+1] == ':' {
			port = strings.TrimSpace(value[end+2:])
			return host, port, port != ""
		}
		return host, "", false
	}

	if strings.Count(value, ":") != 1 {
		return value, "", false
	}
	parts := strings.SplitN(value, ":", 2)
	host = strings.TrimSpace(parts[0])
	port = strings.TrimSpace(parts[1])
	if host == "" || port == "" {
		return value, "", false
	}
	return host, port, true
}

func normalizePolicyProxyHost(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func policyProxyDecisionAllowlistEnabled(plan Plan) bool {
	return plan.Allowlist != nil && plan.Allowlist.Mode == AllowlistModeEnforce
}

func policyProxyDecisionRuleSetID(plan Plan) string {
	if plan.Allowlist != nil && plan.Allowlist.RuleSetID != "" {
		return plan.Allowlist.RuleSetID
	}
	if plan.PolicySnapshot != nil {
		return plan.PolicySnapshot.RuleSetID
	}
	return ""
}

func policyProxyPlanSupportsRule(plan Plan, rule AllowlistRule) bool {
	if !policyProxyDecisionAllowlistEnabled(plan) || plan.Allowlist == nil {
		return false
	}
	category := sanitizeAllowlistRuleCategory(rule.Category)
	if category == "" || !policyProxyAllowlistHasCategory(plan.Allowlist.RuleCategories, category) {
		return false
	}
	if code, _ := validateAllowlistRuleValue(category, rule.Value); code != "" {
		return false
	}
	ruleID := sanitizeIdentifier(rule.ID)
	if ruleID == "" || !policyProxyAllowlistHasRuleID(plan.Allowlist.RuleIDs, ruleID) {
		return false
	}
	return true
}

func policyProxyAllowlistHasCategory(categories []AllowlistRuleCategory, want AllowlistRuleCategory) bool {
	for _, category := range categories {
		if sanitizeAllowlistRuleCategory(category) == want {
			return true
		}
	}
	return false
}

func policyProxyAllowlistHasRuleID(ruleIDs []string, want string) bool {
	for _, ruleID := range ruleIDs {
		if sanitizeIdentifier(ruleID) == want {
			return true
		}
	}
	return false
}

func policyProxyRuleMatchesTarget(rule AllowlistRule, target policyProxyRequestTarget) bool {
	switch sanitizeAllowlistRuleCategory(rule.Category) {
	case AllowlistRuleCategoryDomain:
		return policyProxyDomainRuleMatchesTarget(rule.Value, target)
	case AllowlistRuleCategoryEndpoint:
		return policyProxyEndpointRuleMatchesTarget(rule.Value, target)
	default:
		return false
	}
}

func policyProxyDomainRuleMatchesTarget(value string, target policyProxyRequestTarget) bool {
	if code, _ := validateAllowlistDomainRuleValue(value); code != "" {
		return false
	}
	return target.host == normalizePolicyProxyHost(value)
}

func policyProxyEndpointRuleMatchesTarget(value string, target policyProxyRequestTarget) bool {
	if code, _ := validateAllowlistEndpointRuleValue(value); code != "" || !target.hasPort {
		return false
	}
	host, port, ok := splitAllowlistEndpoint(value)
	if !ok {
		return false
	}
	return target.host == normalizePolicyProxyHost(host) && target.port == strings.TrimSpace(port)
}

func policyProxyBlockedUnsafeDestinationCategory(plan Plan, target policyProxyRequestTarget) AllowlistRuleCategory {
	if !target.valid {
		return ""
	}
	category := policyProxyUnsafeDestinationCategory(target)
	if category == "" || !policyProxyPlanBlocksUnsafeDestinationCategory(plan, category) {
		return ""
	}
	return category
}

func policyProxyUnsafeDestinationCategory(target policyProxyRequestTarget) AllowlistRuleCategory {
	host := normalizePolicyProxyHost(target.host)
	if host == "" {
		return ""
	}
	if policyProxyHostIsMetadataEndpoint(host) {
		return AllowlistRuleCategoryMetadataEndpoint
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	switch {
	case addr.IsLoopback():
		return AllowlistRuleCategoryLoopback
	case addr.IsLinkLocalUnicast():
		return AllowlistRuleCategoryLinkLocal
	case addr.IsPrivate():
		return AllowlistRuleCategoryPrivateRange
	default:
		return ""
	}
}

func policyProxyHostIsMetadataEndpoint(host string) bool {
	if isAllowlistMetadataEndpointValue(host) {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, metadataAddr := range allowlistMetadataAddrs() {
		if addr == metadataAddr {
			return true
		}
	}
	return false
}

func policyProxyPlanBlocksUnsafeDestinationCategory(plan Plan, category AllowlistRuleCategory) bool {
	if plan.Category == nil {
		return false
	}
	switch sanitizeAllowlistRuleCategory(category) {
	case AllowlistRuleCategoryMetadataEndpoint:
		return sanitizePosture(plan.Category.MetadataEndpoint) == PostureBlock
	case AllowlistRuleCategoryPrivateRange,
		AllowlistRuleCategoryLoopback,
		AllowlistRuleCategoryLinkLocal:
		return sanitizePosture(plan.Category.PrivateNetwork) == PostureBlock
	default:
		return false
	}
}
