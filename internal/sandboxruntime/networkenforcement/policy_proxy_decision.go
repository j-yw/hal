package networkenforcement

import "encoding/json"

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
	PolicyProxyDecisionReasonAllowRuleMatched       PolicyProxyDecisionReasonCode = "allow_rule_matched"
	PolicyProxyDecisionReasonDefaultDenyNoAllowRule PolicyProxyDecisionReasonCode = "default_deny_no_allow_rule"
	PolicyProxyDecisionReasonProxyUnsupported       PolicyProxyDecisionReasonCode = "policy_proxy_unsupported"
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

// EvaluatePolicyProxyDecision is a fail-closed placeholder for the policy
// proxy decision engine. Later implementation must replace this unsupported
// result with allowlist/default-deny evaluation while preserving sanitized
// decision metadata.
func EvaluatePolicyProxyDecision(policy PolicyProxyDecisionPolicy, request PolicyProxyDecisionRequest) PolicyProxyDecision {
	plan := SanitizePlan(policy.Plan)
	decision := PolicyProxyDecision{
		Action:         PolicyProxyDecisionActionDeny,
		RequestKind:    sanitizePolicyProxyRequestKind(request.Kind),
		PolicySnapshot: sanitizePolicySnapshotIdentityPtr(plan.PolicySnapshot),
		ReasonCode:     PolicyProxyDecisionReasonProxyUnsupported,
	}
	if plan.Allowlist != nil {
		decision.RuleSetID = plan.Allowlist.RuleSetID
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
		PolicyProxyDecisionReasonProxyUnsupported:
		return normalized
	default:
		return ""
	}
}
