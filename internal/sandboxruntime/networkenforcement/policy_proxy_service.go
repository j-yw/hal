package networkenforcement

import (
	"context"
	"encoding/json"
)

// PolicyProxyService is the narrow runtime-owned boundary for future policy
// proxy activation and request evaluation. Implementations receive sanitized
// plan metadata plus validation-only request values and return sanitized
// decision or lifecycle proof metadata.
type PolicyProxyService interface {
	EvaluateConnectAuthority(context.Context, PolicyProxyConnectAuthorityRequest) (PolicyProxyServiceDecisionResult, error)
	EvaluateHTTPRequestHost(context.Context, PolicyProxyHTTPRequestHostRequest) (PolicyProxyServiceDecisionResult, error)
	StartPolicyProxy(context.Context, PolicyProxyLifecycleRequest) (PolicyProxyLifecycleProof, error)
	ActivePolicyProxy(context.Context, PolicyProxyLifecycleRequest) (PolicyProxyLifecycleProof, error)
	StopPolicyProxy(context.Context, PolicyProxyLifecycleRequest) (PolicyProxyLifecycleProof, error)
}

// PolicyProxyPolicyInput is the policy input shared by policy proxy service
// calls. Plan is always redaction-safe; allowlist rules are validation-only
// inputs and are intentionally omitted from JSON because values may contain raw
// destinations.
type PolicyProxyPolicyInput struct {
	Plan           SanitizedPlan   `json:"plan,omitempty"`
	AllowlistRules []AllowlistRule `json:"-"`
}

// NewPolicyProxyPolicyInput returns policy proxy input from an enforcement
// plan while keeping the public plan surface sanitized.
func NewPolicyProxyPolicyInput(plan Plan, allowlistRules []AllowlistRule) PolicyProxyPolicyInput {
	return PolicyProxyPolicyInput{
		Plan:           NewSanitizedPlan(plan),
		AllowlistRules: cloneAllowlistRules(allowlistRules),
	}
}

// DecisionPolicy returns the existing decision-engine policy contract backed
// by sanitized plan metadata.
func (p PolicyProxyPolicyInput) DecisionPolicy() PolicyProxyDecisionPolicy {
	return PolicyProxyDecisionPolicy{
		Plan:           p.Plan.Plan(),
		AllowlistRules: cloneAllowlistRules(p.AllowlistRules),
	}
}

// PlanMetadata returns a redaction-safe plan copy for service implementations.
func (p PolicyProxyPolicyInput) PlanMetadata() Plan {
	return p.Plan.Plan()
}

// MarshalJSON keeps policy proxy input JSON redaction-safe even when callers
// include contract values in diagnostics.
func (p PolicyProxyPolicyInput) MarshalJSON() ([]byte, error) {
	type policyProxyPolicyInputJSON struct {
		Plan Plan `json:"plan,omitempty"`
	}
	return json.Marshal(policyProxyPolicyInputJSON{
		Plan: p.Plan.Plan(),
	})
}

// PolicyProxyConnectAuthorityRequest carries raw CONNECT authority text only
// as validation input for a policy proxy implementation. The raw authority is
// never part of the JSON metadata contract.
type PolicyProxyConnectAuthorityRequest struct {
	Policy    PolicyProxyPolicyInput `json:"policy,omitempty"`
	Authority string                 `json:"-"`
}

// NewPolicyProxyConnectAuthorityRequest builds a CONNECT-authority evaluation
// request from sanitized policy input and raw validation-only authority text.
func NewPolicyProxyConnectAuthorityRequest(policy PolicyProxyPolicyInput, authority string) PolicyProxyConnectAuthorityRequest {
	return PolicyProxyConnectAuthorityRequest{
		Policy:    policy,
		Authority: authority,
	}
}

// DecisionRequest returns the existing in-memory decision request contract.
func (r PolicyProxyConnectAuthorityRequest) DecisionRequest() PolicyProxyDecisionRequest {
	return PolicyProxyDecisionRequest{
		Kind:      PolicyProxyRequestKindHTTPConnect,
		Authority: r.Authority,
	}
}

// MarshalJSON reports only safe request class and policy metadata.
func (r PolicyProxyConnectAuthorityRequest) MarshalJSON() ([]byte, error) {
	type policyProxyConnectAuthorityRequestJSON struct {
		Policy      PolicyProxyPolicyInput `json:"policy,omitempty"`
		RequestKind PolicyProxyRequestKind `json:"requestKind,omitempty"`
	}
	return json.Marshal(policyProxyConnectAuthorityRequestJSON{
		Policy:      r.Policy,
		RequestKind: PolicyProxyRequestKindHTTPConnect,
	})
}

// PolicyProxyHTTPRequestHostRequest carries raw ordinary HTTP request Host
// text only as validation input for a policy proxy implementation. The raw host
// is never part of the JSON metadata contract.
type PolicyProxyHTTPRequestHostRequest struct {
	Policy PolicyProxyPolicyInput `json:"policy,omitempty"`
	Host   string                 `json:"-"`
}

// NewPolicyProxyHTTPRequestHostRequest builds an HTTP-host evaluation request
// from sanitized policy input and raw validation-only host text.
func NewPolicyProxyHTTPRequestHostRequest(policy PolicyProxyPolicyInput, host string) PolicyProxyHTTPRequestHostRequest {
	return PolicyProxyHTTPRequestHostRequest{
		Policy: policy,
		Host:   host,
	}
}

// DecisionRequest returns the existing in-memory decision request contract.
func (r PolicyProxyHTTPRequestHostRequest) DecisionRequest() PolicyProxyDecisionRequest {
	return PolicyProxyDecisionRequest{
		Kind: PolicyProxyRequestKindHTTPRequestHost,
		Host: r.Host,
	}
}

// MarshalJSON reports only safe request class and policy metadata.
func (r PolicyProxyHTTPRequestHostRequest) MarshalJSON() ([]byte, error) {
	type policyProxyHTTPRequestHostRequestJSON struct {
		Policy      PolicyProxyPolicyInput `json:"policy,omitempty"`
		RequestKind PolicyProxyRequestKind `json:"requestKind,omitempty"`
	}
	return json.Marshal(policyProxyHTTPRequestHostRequestJSON{
		Policy:      r.Policy,
		RequestKind: PolicyProxyRequestKindHTTPRequestHost,
	})
}

// PolicyProxyServiceDecisionResult exposes only sanitized policy proxy
// decision metadata plus the sanitized plan identity used for evaluation.
type PolicyProxyServiceDecisionResult struct {
	PlanID   string              `json:"planId,omitempty"`
	Decision PolicyProxyDecision `json:"decision,omitempty"`
}

// NewPolicyProxyServiceDecisionResult joins a policy input and decision into
// sanitized service result metadata.
func NewPolicyProxyServiceDecisionResult(policy PolicyProxyPolicyInput, decision PolicyProxyDecision) PolicyProxyServiceDecisionResult {
	plan := policy.PlanMetadata()
	if decision.PolicySnapshot == nil {
		decision.PolicySnapshot = plan.PolicySnapshot
	}
	if decision.RuleSetID == "" && plan.Allowlist != nil {
		decision.RuleSetID = plan.Allowlist.RuleSetID
	}
	return SanitizePolicyProxyServiceDecisionResult(PolicyProxyServiceDecisionResult{
		PlanID:   plan.ID,
		Decision: decision,
	})
}

// SanitizePolicyProxyServiceDecisionResult returns redaction-safe policy proxy
// service decision metadata.
func SanitizePolicyProxyServiceDecisionResult(result PolicyProxyServiceDecisionResult) PolicyProxyServiceDecisionResult {
	return PolicyProxyServiceDecisionResult{
		PlanID:   sanitizeIdentifier(result.PlanID),
		Decision: SanitizePolicyProxyDecision(result.Decision),
	}
}

// MarshalJSON keeps public service decision JSON sanitized.
func (r PolicyProxyServiceDecisionResult) MarshalJSON() ([]byte, error) {
	type policyProxyServiceDecisionResultJSON PolicyProxyServiceDecisionResult
	sanitized := SanitizePolicyProxyServiceDecisionResult(r)
	return json.Marshal(policyProxyServiceDecisionResultJSON(sanitized))
}

// PolicyProxyLifecycleOperation identifies the proxy lifecycle proof step
// without carrying listener addresses, process handles, or socket paths.
type PolicyProxyLifecycleOperation string

const (
	PolicyProxyLifecycleOperationStart       PolicyProxyLifecycleOperation = "start_proxy"
	PolicyProxyLifecycleOperationActiveCheck PolicyProxyLifecycleOperation = "active_proxy"
	PolicyProxyLifecycleOperationStop        PolicyProxyLifecycleOperation = "stop_proxy"
)

// PolicyProxyLifecycleRequest carries sanitized policy proxy lifecycle input
// for runtime-owned implementations.
type PolicyProxyLifecycleRequest struct {
	Plan      SanitizedPlan             `json:"plan,omitempty"`
	Requested PolicyProxyLifecycleProof `json:"requested,omitempty"`
	Active    PolicyProxyLifecycleProof `json:"active,omitempty"`
}

// NewPolicyProxyLifecycleRequest builds a sanitized lifecycle request from a
// public plan and optional proof metadata.
func NewPolicyProxyLifecycleRequest(plan Plan, requested, active PolicyProxyLifecycleProof) PolicyProxyLifecycleRequest {
	return SanitizePolicyProxyLifecycleRequest(PolicyProxyLifecycleRequest{
		Plan:      NewSanitizedPlan(plan),
		Requested: requested,
		Active:    active,
	})
}

// PlanMetadata returns a redaction-safe plan copy for lifecycle
// implementations.
func (r PolicyProxyLifecycleRequest) PlanMetadata() Plan {
	return r.Plan.Plan()
}

// SanitizePolicyProxyLifecycleRequest returns redaction-safe lifecycle input
// metadata.
func SanitizePolicyProxyLifecycleRequest(request PolicyProxyLifecycleRequest) PolicyProxyLifecycleRequest {
	return PolicyProxyLifecycleRequest{
		Plan:      NewSanitizedPlan(request.Plan.Plan()),
		Requested: SanitizePolicyProxyLifecycleProof(request.Requested),
		Active:    SanitizePolicyProxyLifecycleProof(request.Active),
	}
}

// MarshalJSON keeps lifecycle request diagnostics redaction-safe.
func (r PolicyProxyLifecycleRequest) MarshalJSON() ([]byte, error) {
	type policyProxyLifecycleRequestJSON struct {
		Plan      Plan                      `json:"plan,omitempty"`
		Requested PolicyProxyLifecycleProof `json:"requested,omitempty"`
		Active    PolicyProxyLifecycleProof `json:"active,omitempty"`
	}
	sanitized := SanitizePolicyProxyLifecycleRequest(r)
	return json.Marshal(policyProxyLifecycleRequestJSON{
		Plan:      sanitized.Plan.Plan(),
		Requested: sanitized.Requested,
		Active:    sanitized.Active,
	})
}

// PolicyProxyLifecycleProof records safe proof for start, active-check, and
// stop operations. It carries only safe identifiers, enum-like status,
// operation labels, policy identity, capability labels, and reason/warning
// codes.
type PolicyProxyLifecycleProof struct {
	PlanID           string                          `json:"planId,omitempty"`
	ProxySessionID   string                          `json:"proxySessionId,omitempty"`
	AdapterID        string                          `json:"adapterId,omitempty"`
	Operation        PolicyProxyLifecycleOperation   `json:"operation,omitempty"`
	Status           LifecycleStatus                 `json:"status,omitempty"`
	Mechanisms       []EnforcementMechanism          `json:"mechanisms,omitempty"`
	Operations       []PolicyProxyLifecycleOperation `json:"operations,omitempty"`
	PolicySnapshot   *PolicySnapshotIdentity         `json:"policySnapshot,omitempty"`
	CapabilityLabels []string                        `json:"capabilityLabels,omitempty"`
	ReasonCode       LifecycleReasonCode             `json:"reasonCode,omitempty"`
	WarningCodes     []LifecycleWarningCode          `json:"warningCodes,omitempty"`
}

// NewPolicyProxyLifecycleProof builds lifecycle proof metadata from sanitized
// plan input and one of the supported proxy lifecycle operations.
func NewPolicyProxyLifecycleProof(plan SanitizedPlan, operation PolicyProxyLifecycleOperation, status LifecycleStatus, reason LifecycleReasonCode) PolicyProxyLifecycleProof {
	input := plan.Plan()
	proof := PolicyProxyLifecycleProof{
		PlanID:         input.ID,
		Operation:      operation,
		Status:         status,
		Mechanisms:     []EnforcementMechanism{EnforcementMechanismProxy},
		PolicySnapshot: input.PolicySnapshot,
		ReasonCode:     reason,
	}
	if operation != "" {
		proof.Operations = []PolicyProxyLifecycleOperation{operation}
	}
	if input.Proxy != nil {
		proof.ProxySessionID = input.Proxy.ProxySessionID
	}
	return SanitizePolicyProxyLifecycleProof(proof)
}

// SanitizePolicyProxyLifecycleProof returns redaction-safe lifecycle proof
// metadata and drops any raw listener-address-like fields.
func SanitizePolicyProxyLifecycleProof(proof PolicyProxyLifecycleProof) PolicyProxyLifecycleProof {
	return PolicyProxyLifecycleProof{
		PlanID:           sanitizeIdentifier(proof.PlanID),
		ProxySessionID:   sanitizeIdentifier(proof.ProxySessionID),
		AdapterID:        sanitizeIdentifier(proof.AdapterID),
		Operation:        sanitizePolicyProxyLifecycleOperation(proof.Operation),
		Status:           sanitizeLifecycleStatus(proof.Status),
		Mechanisms:       sanitizePolicyProxyLifecycleMechanisms(proof.Mechanisms),
		Operations:       sanitizePolicyProxyLifecycleOperationList(proof.Operations),
		PolicySnapshot:   sanitizePolicySnapshotIdentityPtr(proof.PolicySnapshot),
		CapabilityLabels: sanitizeProxyListenerCapabilityLabels(proof.CapabilityLabels),
		ReasonCode:       sanitizeLifecycleReasonCode(proof.ReasonCode),
		WarningCodes:     sanitizeLifecycleWarningCodeList(proof.WarningCodes),
	}
}

// MarshalJSON keeps public policy proxy lifecycle proof JSON sanitized.
func (p PolicyProxyLifecycleProof) MarshalJSON() ([]byte, error) {
	type policyProxyLifecycleProofJSON PolicyProxyLifecycleProof
	sanitized := SanitizePolicyProxyLifecycleProof(p)
	return json.Marshal(policyProxyLifecycleProofJSON(sanitized))
}

func cloneAllowlistRules(rules []AllowlistRule) []AllowlistRule {
	if len(rules) == 0 {
		return nil
	}
	return append([]AllowlistRule(nil), rules...)
}

func sanitizePolicyProxyLifecycleOperation(value PolicyProxyLifecycleOperation) PolicyProxyLifecycleOperation {
	normalized := PolicyProxyLifecycleOperation(normalizeEnum(string(value)))
	switch normalized {
	case PolicyProxyLifecycleOperationStart,
		PolicyProxyLifecycleOperationActiveCheck,
		PolicyProxyLifecycleOperationStop:
		return normalized
	default:
		return ""
	}
}

func sanitizePolicyProxyLifecycleOperationList(values []PolicyProxyLifecycleOperation) []PolicyProxyLifecycleOperation {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]PolicyProxyLifecycleOperation, 0, len(values))
	for _, value := range values {
		if current := sanitizePolicyProxyLifecycleOperation(value); current != "" {
			sanitized = append(sanitized, current)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizePolicyProxyLifecycleMechanisms(values []EnforcementMechanism) []EnforcementMechanism {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]EnforcementMechanism, 0, len(values))
	for _, value := range values {
		if sanitizeEnforcementMechanism(value) == EnforcementMechanismProxy {
			sanitized = append(sanitized, EnforcementMechanismProxy)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}
