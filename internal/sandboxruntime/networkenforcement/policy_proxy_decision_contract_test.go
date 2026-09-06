package networkenforcement

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyProxyDecisionContractEvaluatesHTTPConnectAuthority(t *testing.T) {
	policy := policyProxyDecisionContractPolicy()

	tests := []struct {
		name         string
		authority    string
		wantAction   PolicyProxyDecisionAction
		wantRuleID   string
		wantCategory AllowlistRuleCategory
		wantReason   PolicyProxyDecisionReasonCode
	}{
		{
			name:         "allowed CONNECT authority matches endpoint rule",
			authority:    "api.example.com:443",
			wantAction:   PolicyProxyDecisionActionAllow,
			wantRuleID:   "rule-api-endpoint",
			wantCategory: AllowlistRuleCategoryEndpoint,
			wantReason:   PolicyProxyDecisionReasonAllowRuleMatched,
		},
		{
			name:       "denied CONNECT authority has no allow match",
			authority:  "blocked.example.com:443",
			wantAction: PolicyProxyDecisionActionDeny,
			wantReason: PolicyProxyDecisionReasonDefaultDenyNoAllowRule,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluatePolicyProxyDecision(policy, PolicyProxyDecisionRequest{
				Kind:      PolicyProxyRequestKindHTTPConnect,
				Authority: tt.authority,
			})

			assertPolicyProxyDecision(t, got, policyProxyDecisionExpectation{
				action:       tt.wantAction,
				requestKind:  PolicyProxyRequestKindHTTPConnect,
				policyID:     "policy-snapshot-proxy-01",
				ruleSetID:    "rules-proxy-01",
				ruleID:       tt.wantRuleID,
				ruleCategory: tt.wantCategory,
				reason:       tt.wantReason,
			})
			assertPolicyProxyDecisionOmitsRawDestination(t, got, tt.authority)
		})
	}
}

func TestPolicyProxyDecisionContractEvaluatesHTTPRequestHost(t *testing.T) {
	policy := policyProxyDecisionContractPolicy()

	tests := []struct {
		name         string
		host         string
		wantAction   PolicyProxyDecisionAction
		wantRuleID   string
		wantCategory AllowlistRuleCategory
		wantReason   PolicyProxyDecisionReasonCode
	}{
		{
			name:         "allowed request host matches domain rule",
			host:         "updates.example.com",
			wantAction:   PolicyProxyDecisionActionAllow,
			wantRuleID:   "rule-updates-domain",
			wantCategory: AllowlistRuleCategoryDomain,
			wantReason:   PolicyProxyDecisionReasonAllowRuleMatched,
		},
		{
			name:       "denied request host has no allow match",
			host:       "blocked.example.com",
			wantAction: PolicyProxyDecisionActionDeny,
			wantReason: PolicyProxyDecisionReasonDefaultDenyNoAllowRule,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluatePolicyProxyDecision(policy, PolicyProxyDecisionRequest{
				Kind: PolicyProxyRequestKindHTTPRequestHost,
				Host: tt.host,
			})

			assertPolicyProxyDecision(t, got, policyProxyDecisionExpectation{
				action:       tt.wantAction,
				requestKind:  PolicyProxyRequestKindHTTPRequestHost,
				policyID:     "policy-snapshot-proxy-01",
				ruleSetID:    "rules-proxy-01",
				ruleID:       tt.wantRuleID,
				ruleCategory: tt.wantCategory,
				reason:       tt.wantReason,
			})
			assertPolicyProxyDecisionOmitsRawDestination(t, got, tt.host)
		})
	}
}

func TestPolicyProxyDecisionContractDefaultDenyWhenNoAllowRuleMatches(t *testing.T) {
	policy := policyProxyDecisionContractPolicy()

	got := EvaluatePolicyProxyDecision(policy, PolicyProxyDecisionRequest{
		Kind: PolicyProxyRequestKindHTTPRequestHost,
		Host: "unlisted.example.com",
	})

	assertPolicyProxyDecision(t, got, policyProxyDecisionExpectation{
		action:      PolicyProxyDecisionActionDeny,
		requestKind: PolicyProxyRequestKindHTTPRequestHost,
		policyID:    "policy-snapshot-proxy-01",
		ruleSetID:   "rules-proxy-01",
		reason:      PolicyProxyDecisionReasonDefaultDenyNoAllowRule,
	})
	assertPolicyProxyDecisionOmitsRawDestination(t, got, "unlisted.example.com")
}

func TestPolicyProxyDecisionContractMetadataIncludesPolicyRuleAndReasonCodes(t *testing.T) {
	policy := policyProxyDecisionContractPolicy()

	got := EvaluatePolicyProxyDecision(policy, PolicyProxyDecisionRequest{
		Kind:      PolicyProxyRequestKindHTTPConnect,
		Authority: "api.example.com:443",
	})

	assertPolicyProxyDecision(t, got, policyProxyDecisionExpectation{
		action:       PolicyProxyDecisionActionAllow,
		requestKind:  PolicyProxyRequestKindHTTPConnect,
		policyID:     "policy-snapshot-proxy-01",
		ruleSetID:    "rules-proxy-01",
		ruleID:       "rule-api-endpoint",
		ruleCategory: AllowlistRuleCategoryEndpoint,
		reason:       PolicyProxyDecisionReasonAllowRuleMatched,
	})

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal(decision) error: %v", err)
	}
	for _, want := range []string{
		`"policySnapshot":{"id":"policy-snapshot-proxy-01"`,
		`"ruleSetId":"rules-proxy-01"`,
		`"ruleId":"rule-api-endpoint"`,
		`"ruleCategory":"endpoint"`,
		`"reasonCode":"allow_rule_matched"`,
	} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("decision JSON %s missing %s", payload, want)
		}
	}
	assertPolicyProxyDecisionOmitsRawDestination(t, got, "api.example.com:443")
}

func policyProxyDecisionContractPolicy() PolicyProxyDecisionPolicy {
	request := PlanRequest{
		ID:        "network-plan-policy-proxy-01",
		Source:    PlanSourceWorker,
		Operation: "policy_proxy_decision",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-snapshot-proxy-01",
			Version:   "v1",
			Preset:    PolicyPresetAllowListed,
			RuleSetID: "rules-proxy-01",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:        PolicyPresetAllowListed,
			AllowlistMode: AllowlistModeEnforce,
			RuleSetID:     "rules-proxy-01",
			HTTP:          ProxyRoutingModeRouteViaProxy,
			HTTPS:         ProxyRoutingModeRouteViaProxy,
			AllowlistRules: []AllowlistRule{
				{ID: "rule-api-endpoint", Category: AllowlistRuleCategoryEndpoint, Value: "api.example.com:443"},
				{ID: "rule-updates-domain", Category: AllowlistRuleCategoryDomain, Value: "updates.example.com"},
			},
		},
	}

	return PolicyProxyDecisionPolicy{
		Plan:           BuildPlan(request),
		AllowlistRules: append([]AllowlistRule(nil), request.RequestedPolicy.AllowlistRules...),
	}
}

type policyProxyDecisionExpectation struct {
	action       PolicyProxyDecisionAction
	requestKind  PolicyProxyRequestKind
	policyID     string
	ruleSetID    string
	ruleID       string
	ruleCategory AllowlistRuleCategory
	reason       PolicyProxyDecisionReasonCode
}

func assertPolicyProxyDecision(t *testing.T, got PolicyProxyDecision, want policyProxyDecisionExpectation) {
	t.Helper()
	if got.Action != want.action {
		t.Fatalf("Action = %q, want %q in %#v", got.Action, want.action, got)
	}
	if got.RequestKind != want.requestKind {
		t.Fatalf("RequestKind = %q, want %q in %#v", got.RequestKind, want.requestKind, got)
	}
	if got.PolicySnapshot == nil || got.PolicySnapshot.ID != want.policyID {
		t.Fatalf("PolicySnapshot = %#v, want id %q", got.PolicySnapshot, want.policyID)
	}
	if got.RuleSetID != want.ruleSetID {
		t.Fatalf("RuleSetID = %q, want %q in %#v", got.RuleSetID, want.ruleSetID, got)
	}
	if got.RuleID != want.ruleID {
		t.Fatalf("RuleID = %q, want %q in %#v", got.RuleID, want.ruleID, got)
	}
	if got.RuleCategory != want.ruleCategory {
		t.Fatalf("RuleCategory = %q, want %q in %#v", got.RuleCategory, want.ruleCategory, got)
	}
	if got.ReasonCode != want.reason {
		t.Fatalf("ReasonCode = %q, want %q in %#v", got.ReasonCode, want.reason, got)
	}
}

func assertPolicyProxyDecisionOmitsRawDestination(t *testing.T, decision PolicyProxyDecision, rawDestination string) {
	t.Helper()
	payload, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("Marshal(decision) error: %v", err)
	}
	if strings.Contains(strings.ToLower(string(payload)), strings.ToLower(rawDestination)) {
		t.Fatalf("decision JSON leaked raw destination %q: %s", rawDestination, payload)
	}
}
