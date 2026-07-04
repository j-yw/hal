package networkenforcement

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

var _ PolicyProxyService = (*recordingPolicyProxyService)(nil)

type recordingPolicyProxyService struct{}

func (*recordingPolicyProxyService) EvaluateConnectAuthority(_ context.Context, request PolicyProxyConnectAuthorityRequest) (PolicyProxyServiceDecisionResult, error) {
	return EvaluatePolicyProxyServiceDecisionResult(request.Policy, request.DecisionRequest()), nil
}

func (*recordingPolicyProxyService) EvaluateHTTPRequestHost(_ context.Context, request PolicyProxyHTTPRequestHostRequest) (PolicyProxyServiceDecisionResult, error) {
	return EvaluatePolicyProxyServiceDecisionResult(request.Policy, request.DecisionRequest()), nil
}

func (*recordingPolicyProxyService) StartPolicyProxy(_ context.Context, request PolicyProxyLifecycleRequest) (PolicyProxyLifecycleProof, error) {
	return NewPolicyProxyLifecycleProof(request.Plan, PolicyProxyLifecycleOperationStart, LifecycleStatusStarting, LifecycleReasonStarted), nil
}

func (*recordingPolicyProxyService) ActivePolicyProxy(_ context.Context, request PolicyProxyLifecycleRequest) (PolicyProxyLifecycleProof, error) {
	return NewPolicyProxyLifecycleProof(request.Plan, PolicyProxyLifecycleOperationActiveCheck, LifecycleStatusActive, LifecycleReasonActive), nil
}

func (*recordingPolicyProxyService) StopPolicyProxy(_ context.Context, request PolicyProxyLifecycleRequest) (PolicyProxyLifecycleProof, error) {
	return NewPolicyProxyLifecycleProof(request.Plan, PolicyProxyLifecycleOperationStop, LifecycleStatusStopped, LifecycleReasonStopped), nil
}

func TestPolicyProxyServiceContractsSupportConnectAndHTTPRequestHostInputs(t *testing.T) {
	policy := NewPolicyProxyPolicyInput(policyProxyServicePlan(), []AllowlistRule{
		{ID: "rule-api-endpoint", Category: AllowlistRuleCategoryEndpoint, Value: "api.example.com:443"},
		{ID: "rule-updates-domain", Category: AllowlistRuleCategoryDomain, Value: "updates.example.com"},
	})

	connectRequest := NewPolicyProxyConnectAuthorityRequest(policy, "api.example.com:443")
	if got := connectRequest.DecisionRequest(); got.Kind != PolicyProxyRequestKindHTTPConnect || got.Authority != "api.example.com:443" {
		t.Fatalf("connect DecisionRequest() = %#v, want CONNECT authority request", got)
	}

	hostRequest := NewPolicyProxyHTTPRequestHostRequest(policy, "updates.example.com")
	if got := hostRequest.DecisionRequest(); got.Kind != PolicyProxyRequestKindHTTPRequestHost || got.Host != "updates.example.com" {
		t.Fatalf("host DecisionRequest() = %#v, want HTTP host request", got)
	}

	decisionPolicy := policy.DecisionPolicy()
	if decisionPolicy.Plan.ID != "network-plan-policy-proxy-service" {
		t.Fatalf("DecisionPolicy().Plan.ID = %q, want sanitized plan id", decisionPolicy.Plan.ID)
	}
	if len(decisionPolicy.AllowlistRules) != 2 || decisionPolicy.AllowlistRules[0].Value != "api.example.com:443" {
		t.Fatalf("DecisionPolicy().AllowlistRules = %#v, want validation-only rules copied", decisionPolicy.AllowlistRules)
	}

	assertPolicyProxyServiceJSONOmitsRawValues(t, connectRequest, "api.example.com:443", "updates.example.com")
	assertPolicyProxyServiceJSONOmitsRawValues(t, hostRequest, "api.example.com:443", "updates.example.com")
}

func TestPolicyProxyServiceDecisionResultMetadataIsSanitized(t *testing.T) {
	policy := NewPolicyProxyPolicyInput(policyProxyServicePlan(), nil)
	result := NewPolicyProxyServiceDecisionResult(policy, PolicyProxyDecision{
		Action:      PolicyProxyDecisionActionDeny,
		RequestKind: PolicyProxyRequestKindHTTPRequestHost,
		RuleID:      "https://raw.example.com/rules?token=secret",
		ReasonCode:  PolicyProxyDecisionReasonDefaultDenyNoAllowRule,
	})

	if result.PlanID != "network-plan-policy-proxy-service" {
		t.Fatalf("PlanID = %q, want sanitized plan id", result.PlanID)
	}
	if result.Decision.PolicySnapshot == nil || result.Decision.PolicySnapshot.ID != "policy-proxy-service" {
		t.Fatalf("Decision.PolicySnapshot = %#v, want plan policy snapshot", result.Decision.PolicySnapshot)
	}
	if result.Decision.RuleSetID != "rules-proxy-service" {
		t.Fatalf("Decision.RuleSetID = %q, want plan allowlist rule set", result.Decision.RuleSetID)
	}
	if result.Decision.RuleID != "" {
		t.Fatalf("Decision.RuleID = %q, want unsafe raw rule id removed", result.Decision.RuleID)
	}

	assertPolicyProxyServiceJSONOmitsRawValues(t, result, "raw.example.com", "token=secret")
}

func TestPolicyProxyServiceDecisionResultIncludesSanitizedDecisionLogs(t *testing.T) {
	policy := NewPolicyProxyPolicyInput(policyProxyServicePlan(), []AllowlistRule{
		{ID: "rule-api-endpoint", Category: AllowlistRuleCategoryEndpoint, Value: "api.example.com:443"},
		{ID: "rule-updates-domain", Category: AllowlistRuleCategoryDomain, Value: "updates.example.com"},
	})
	service := &recordingPolicyProxyService{}

	allowed, err := service.EvaluateConnectAuthority(context.Background(), NewPolicyProxyConnectAuthorityRequest(policy, "api.example.com:443"))
	if err != nil {
		t.Fatalf("EvaluateConnectAuthority() error = %v", err)
	}
	denied, err := service.EvaluateHTTPRequestHost(context.Background(), NewPolicyProxyHTTPRequestHostRequest(policy, "blocked.example.com"))
	if err != nil {
		t.Fatalf("EvaluateHTTPRequestHost() error = %v", err)
	}

	assertPolicyProxyServiceDecisionLog(t, allowed.DecisionLog, policyProxyServiceDecisionLogExpectation{
		action:              PolicyProxyDecisionActionAllow,
		ruleID:              "rule-api-endpoint",
		reason:              PolicyProxyDecisionReasonAllowRuleMatched,
		destinationCategory: AllowlistRuleCategoryEndpoint,
	})
	assertPolicyProxyServiceDecisionLog(t, denied.DecisionLog, policyProxyServiceDecisionLogExpectation{
		action:              PolicyProxyDecisionActionDeny,
		reason:              PolicyProxyDecisionReasonDefaultDenyNoAllowRule,
		destinationCategory: AllowlistRuleCategoryDomain,
	})

	logs := []PolicyProxyDecisionLogRecord{*allowed.DecisionLog, *denied.DecisionLog}
	counters := SummarizePolicyProxyDecisionLogRecords(logs)
	if counters.Total != 2 || counters.Allowed != 1 || counters.Denied != 1 {
		t.Fatalf("decision log counters = %#v, want total=2 allowed=1 denied=1", counters)
	}
	assertPolicyProxyServiceJSONOmitsRawValues(t, struct {
		Allowed  PolicyProxyServiceDecisionResult `json:"allowed"`
		Denied   PolicyProxyServiceDecisionResult `json:"denied"`
		Counters PolicyProxyDecisionLogCounters   `json:"counters"`
	}{Allowed: allowed, Denied: denied, Counters: counters}, "api.example.com", "blocked.example.com")
}

func TestPolicyProxyServiceDecisionResultSanitizesProvidedDecisionLog(t *testing.T) {
	policy := NewPolicyProxyPolicyInput(policyProxyServicePlan(), nil)
	result := NewPolicyProxyServiceDecisionResultWithDecisionLog(policy, PolicyProxyDecision{
		Action:      PolicyProxyDecisionActionDeny,
		RequestKind: PolicyProxyRequestKindHTTPRequestHost,
		RuleID:      "safe-rule-id",
		ReasonCode:  PolicyProxyDecisionReasonDefaultDenyNoAllowRule,
	}, PolicyProxyDecisionLogRecord{
		PolicySnapshotID:    "https://policy.example.com/snapshots?token=secret",
		RuleSetID:           "rules-proxy-service",
		RuleID:              "/Users/v/work/rescience/hal/.hal/raw-rule.json",
		Action:              PolicyProxyDecisionAction(" deny "),
		ReasonCode:          PolicyProxyDecisionReasonCode(" default_deny_no_allow_rule "),
		DestinationCategory: AllowlistRuleCategory(" domain "),
		Count:               -10,
	})

	if result.DecisionLog == nil {
		t.Fatal("DecisionLog = nil, want sanitized durable-safe record")
	}
	if result.DecisionLog.PolicySnapshotID != "policy-proxy-service" {
		t.Fatalf("DecisionLog.PolicySnapshotID = %q, want policy snapshot id defaulted from sanitized decision", result.DecisionLog.PolicySnapshotID)
	}
	if result.DecisionLog.RuleID != "safe-rule-id" {
		t.Fatalf("DecisionLog.RuleID = %q, want unsafe log rule id replaced by sanitized decision rule id", result.DecisionLog.RuleID)
	}
	if result.DecisionLog.Count != 1 {
		t.Fatalf("DecisionLog.Count = %d, want default count 1", result.DecisionLog.Count)
	}
	assertPolicyProxyServiceJSONOmitsRawValues(t, result, "policy.example.com", "token=secret", "/Users/v/work/rescience/hal/.hal/raw-rule.json")
}

func TestPolicyProxyLifecycleProofSupportsStartActiveAndStopWithoutListenerAddresses(t *testing.T) {
	request := NewPolicyProxyLifecycleRequest(policyProxyServicePlan(), PolicyProxyLifecycleProof{}, PolicyProxyLifecycleProof{})
	service := &recordingPolicyProxyService{}

	started, err := service.StartPolicyProxy(context.Background(), request)
	if err != nil {
		t.Fatalf("StartPolicyProxy() error = %v", err)
	}
	active, err := service.ActivePolicyProxy(context.Background(), request)
	if err != nil {
		t.Fatalf("ActivePolicyProxy() error = %v", err)
	}
	stopped, err := service.StopPolicyProxy(context.Background(), request)
	if err != nil {
		t.Fatalf("StopPolicyProxy() error = %v", err)
	}

	for _, tt := range []struct {
		name      string
		proof     PolicyProxyLifecycleProof
		operation PolicyProxyLifecycleOperation
		status    LifecycleStatus
		reason    LifecycleReasonCode
	}{
		{name: "start", proof: started, operation: PolicyProxyLifecycleOperationStart, status: LifecycleStatusStarting, reason: LifecycleReasonStarted},
		{name: "active", proof: active, operation: PolicyProxyLifecycleOperationActiveCheck, status: LifecycleStatusActive, reason: LifecycleReasonActive},
		{name: "stop", proof: stopped, operation: PolicyProxyLifecycleOperationStop, status: LifecycleStatusStopped, reason: LifecycleReasonStopped},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.proof.PlanID != "network-plan-policy-proxy-service" {
				t.Fatalf("PlanID = %q, want plan id", tt.proof.PlanID)
			}
			if tt.proof.ProxySessionID != "proxy-service-session" {
				t.Fatalf("ProxySessionID = %q, want sanitized proxy session id", tt.proof.ProxySessionID)
			}
			if tt.proof.Operation != tt.operation || tt.proof.Status != tt.status || tt.proof.ReasonCode != tt.reason {
				t.Fatalf("proof = %#v, want operation/status/reason %q/%q/%q", tt.proof, tt.operation, tt.status, tt.reason)
			}
			assertPlanStringArrayFromStrings(t, lifecycleOperationsToStrings(tt.proof.Operations), []string{string(tt.operation)})
			assertPlanStringArrayFromStrings(t, mechanismsToStrings(tt.proof.Mechanisms), []string{string(EnforcementMechanismProxy)})
			assertPolicyProxyServiceJSONOmitsRawValues(t, tt.proof, "127.0.0.1:8080", "/tmp/proxy.sock")
		})
	}
}

func TestPolicyProxyLifecycleProofSanitizesUnsafeAdapterMetadata(t *testing.T) {
	proof := SanitizePolicyProxyLifecycleProof(PolicyProxyLifecycleProof{
		PlanID:         "network-plan-policy-proxy-service",
		ProxySessionID: "/tmp/proxy.sock",
		AdapterID:      "adapter://127.0.0.1:8080",
		Operation:      PolicyProxyLifecycleOperation(" START_PROXY "),
		Status:         LifecycleStatus(" ACTIVE "),
		Mechanisms: []EnforcementMechanism{
			EnforcementMechanismProxy,
			EnforcementMechanismFirewall,
			EnforcementMechanism("runtime"),
		},
		Operations: []PolicyProxyLifecycleOperation{
			PolicyProxyLifecycleOperationStart,
			PolicyProxyLifecycleOperation("listen 127.0.0.1:8080"),
			PolicyProxyLifecycleOperation("/tmp/proxy.sock"),
		},
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-proxy-service",
			Version:   "https://policy.example.com/v1?token=secret",
			Preset:    PolicyPreset(" ALLOW_LISTED "),
			RuleSetID: "rules-proxy-service",
		},
		CapabilityLabels: []string{"proxy_active", "runtime_socket", "firewall_rule"},
		ReasonCode:       LifecycleReasonCode(" ACTIVE "),
		WarningCodes: []LifecycleWarningCode{
			LifecycleWarningCleanupFailed,
			LifecycleWarningCode("close /tmp/proxy.sock"),
		},
	})

	if proof.ProxySessionID != "" || proof.AdapterID != "" {
		t.Fatalf("unsafe listener identifiers survived sanitization: %#v", proof)
	}
	if proof.Operation != PolicyProxyLifecycleOperationStart {
		t.Fatalf("Operation = %q, want start_proxy", proof.Operation)
	}
	assertPlanStringArrayFromStrings(t, mechanismsToStrings(proof.Mechanisms), []string{string(EnforcementMechanismProxy)})
	assertPlanStringArrayFromStrings(t, lifecycleOperationsToStrings(proof.Operations), []string{string(PolicyProxyLifecycleOperationStart)})
	assertPlanStringArrayFromStrings(t, proof.CapabilityLabels, []string{"proxy_active"})
	if proof.PolicySnapshot == nil || proof.PolicySnapshot.Version != "" {
		t.Fatalf("PolicySnapshot = %#v, want unsafe version removed", proof.PolicySnapshot)
	}
	assertPolicyProxyServiceJSONOmitsRawValues(t, proof, "127.0.0.1:8080", "/tmp/proxy.sock", "token=secret")
}

func policyProxyServicePlan() Plan {
	return BuildPlan(PlanRequest{
		ID:        "network-plan-policy-proxy-service",
		Source:    PlanSourceRuntime,
		Operation: "policy_proxy_service",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-proxy-service",
			Version:   "v1",
			Preset:    PolicyPresetAllowListed,
			RuleSetID: "rules-proxy-service",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:         PolicyPresetAllowListed,
			AllowlistMode:  AllowlistModeEnforce,
			RuleSetID:      "rules-proxy-service",
			HTTP:           ProxyRoutingModeRouteViaProxy,
			HTTPS:          ProxyRoutingModeRouteViaProxy,
			ProxySessionID: "proxy-service-session",
			ProxyMechanism: EnforcementMechanismProxy,
			AllowlistRules: []AllowlistRule{
				{ID: "rule-api-endpoint", Category: AllowlistRuleCategoryEndpoint, Value: "api.example.com:443"},
				{ID: "rule-updates-domain", Category: AllowlistRuleCategoryDomain, Value: "updates.example.com"},
			},
		},
	})
}

func assertPolicyProxyServiceJSONOmitsRawValues(t *testing.T, value any, forbiddenValues ...string) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	lowerPayload := strings.ToLower(string(payload))
	for _, forbidden := range forbiddenValues {
		if strings.Contains(lowerPayload, strings.ToLower(forbidden)) {
			t.Fatalf("payload leaked raw value %q: %s", forbidden, payload)
		}
	}
}

type policyProxyServiceDecisionLogExpectation struct {
	action              PolicyProxyDecisionAction
	ruleID              string
	reason              PolicyProxyDecisionReasonCode
	destinationCategory AllowlistRuleCategory
}

func assertPolicyProxyServiceDecisionLog(t *testing.T, got *PolicyProxyDecisionLogRecord, want policyProxyServiceDecisionLogExpectation) {
	t.Helper()
	if got == nil {
		t.Fatal("DecisionLog = nil, want sanitized durable-safe record")
	}
	if got.PolicySnapshotID != "policy-proxy-service" {
		t.Fatalf("DecisionLog.PolicySnapshotID = %q, want policy-proxy-service in %#v", got.PolicySnapshotID, got)
	}
	if got.RuleSetID != "rules-proxy-service" {
		t.Fatalf("DecisionLog.RuleSetID = %q, want rules-proxy-service in %#v", got.RuleSetID, got)
	}
	if got.RuleID != want.ruleID {
		t.Fatalf("DecisionLog.RuleID = %q, want %q in %#v", got.RuleID, want.ruleID, got)
	}
	if got.Action != want.action {
		t.Fatalf("DecisionLog.Action = %q, want %q in %#v", got.Action, want.action, got)
	}
	if got.ReasonCode != want.reason {
		t.Fatalf("DecisionLog.ReasonCode = %q, want %q in %#v", got.ReasonCode, want.reason, got)
	}
	if got.DestinationCategory != want.destinationCategory {
		t.Fatalf("DecisionLog.DestinationCategory = %q, want %q in %#v", got.DestinationCategory, want.destinationCategory, got)
	}
	if got.Count != 1 {
		t.Fatalf("DecisionLog.Count = %d, want 1 in %#v", got.Count, got)
	}
}

func lifecycleOperationsToStrings(values []PolicyProxyLifecycleOperation) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}

func mechanismsToStrings(values []EnforcementMechanism) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	return out
}
