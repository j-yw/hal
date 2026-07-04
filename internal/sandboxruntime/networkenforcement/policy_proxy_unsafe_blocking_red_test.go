package networkenforcement

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyProxyDecisionContractBlocksUnsafeDestinationsByCategory(t *testing.T) {
	policy := policyProxyDecisionUnsafeBlockingPolicy()

	tests := []struct {
		name         string
		request      PolicyProxyDecisionRequest
		wantKind     PolicyProxyRequestKind
		wantCategory AllowlistRuleCategory
		rawValues    []string
	}{
		{
			name: "loopback CONNECT authority blocked",
			request: PolicyProxyDecisionRequest{
				Kind:      PolicyProxyRequestKindHTTPConnect,
				Authority: "127.0.0.1:8080",
			},
			wantKind:     PolicyProxyRequestKindHTTPConnect,
			wantCategory: AllowlistRuleCategoryLoopback,
			rawValues:    []string{"127.0.0.1:8080", "127.0.0.1"},
		},
		{
			name: "private range CONNECT authority blocked",
			request: PolicyProxyDecisionRequest{
				Kind:      PolicyProxyRequestKindHTTPConnect,
				Authority: "10.20.30.40:443",
			},
			wantKind:     PolicyProxyRequestKindHTTPConnect,
			wantCategory: AllowlistRuleCategoryPrivateRange,
			rawValues:    []string{"10.20.30.40:443", "10.20.30.40"},
		},
		{
			name: "link-local request host blocked",
			request: PolicyProxyDecisionRequest{
				Kind: PolicyProxyRequestKindHTTPRequestHost,
				Host: "169.254.10.20",
			},
			wantKind:     PolicyProxyRequestKindHTTPRequestHost,
			wantCategory: AllowlistRuleCategoryLinkLocal,
			rawValues:    []string{"169.254.10.20"},
		},
		{
			name: "metadata endpoint request host blocked",
			request: PolicyProxyDecisionRequest{
				Kind: PolicyProxyRequestKindHTTPRequestHost,
				Host: "169.254.169.254",
			},
			wantKind:     PolicyProxyRequestKindHTTPRequestHost,
			wantCategory: AllowlistRuleCategoryMetadataEndpoint,
			rawValues:    []string{"169.254.169.254"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluatePolicyProxyDecision(policy, tt.request)

			assertPolicyProxyDecision(t, got, policyProxyDecisionExpectation{
				action:       PolicyProxyDecisionActionDeny,
				requestKind:  tt.wantKind,
				policyID:     "policy-snapshot-unsafe-blocking-01",
				ruleSetID:    "rules-unsafe-blocking-01",
				ruleCategory: tt.wantCategory,
				reason:       PolicyProxyDecisionReasonUnsafeDestinationBlocked,
			})
			assertPolicyProxyDecisionOmitsRawDestinations(t, got, tt.rawValues...)
			assertPolicyProxyDecisionJSONContains(t, got,
				`"ruleCategory":"`+string(tt.wantCategory)+`"`,
				`"reasonCode":"`+string(PolicyProxyDecisionReasonUnsafeDestinationBlocked)+`"`,
			)
		})
	}
}

func policyProxyDecisionUnsafeBlockingPolicy() PolicyProxyDecisionPolicy {
	request := PlanRequest{
		ID:        "network-plan-unsafe-blocking-01",
		Source:    PlanSourceWorker,
		Operation: "policy_proxy_unsafe_blocking",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-snapshot-unsafe-blocking-01",
			Version:   "v1",
			Preset:    PolicyPresetAllowListed,
			RuleSetID: "rules-unsafe-blocking-01",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:           PolicyPresetAllowListed,
			AllowlistMode:    AllowlistModeEnforce,
			RuleSetID:        "rules-unsafe-blocking-01",
			PrivateNetwork:   PostureBlock,
			MetadataEndpoint: PostureBlock,
			HTTP:             ProxyRoutingModeRouteViaProxy,
			HTTPS:            ProxyRoutingModeRouteViaProxy,
			AllowlistRules: []AllowlistRule{
				{ID: "rule-loopback", Category: AllowlistRuleCategoryLoopback, Value: "127.0.0.1"},
				{ID: "rule-private-range", Category: AllowlistRuleCategoryPrivateRange, Value: "10.0.0.0/8"},
				{ID: "rule-link-local", Category: AllowlistRuleCategoryLinkLocal, Value: "169.254.0.0/16"},
				{ID: "rule-metadata", Category: AllowlistRuleCategoryMetadataEndpoint, Value: "169.254.169.254"},
			},
		},
	}

	return PolicyProxyDecisionPolicy{
		Plan:           BuildPlan(request),
		AllowlistRules: append([]AllowlistRule(nil), request.RequestedPolicy.AllowlistRules...),
	}
}

func assertPolicyProxyDecisionOmitsRawDestinations(t *testing.T, decision PolicyProxyDecision, rawDestinations ...string) {
	t.Helper()
	payload, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("Marshal(decision) error: %v", err)
	}
	lowerPayload := strings.ToLower(string(payload))
	for _, rawDestination := range rawDestinations {
		if rawDestination == "" {
			continue
		}
		if strings.Contains(lowerPayload, strings.ToLower(rawDestination)) {
			t.Fatalf("decision JSON leaked raw destination %q: %s", rawDestination, payload)
		}
	}
}

func assertPolicyProxyDecisionJSONContains(t *testing.T, decision PolicyProxyDecision, wantValues ...string) {
	t.Helper()
	payload, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("Marshal(decision) error: %v", err)
	}
	for _, want := range wantValues {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("decision JSON %s missing %s", payload, want)
		}
	}
}
