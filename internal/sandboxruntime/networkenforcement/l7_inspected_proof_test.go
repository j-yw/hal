package networkenforcement

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestL7AggregationRequiresFreshInspectedRuleProof(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)

	tests := []struct {
		name   string
		mutate func(*ProxyListenerLifecycleResult, *RuleLifecycleResult)
	}{
		{name: "plan or active label is not proof", mutate: func(_ *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) {
			rules.Active.Inspection = nil
		}},
		{name: "apply acknowledgement is not proof", mutate: func(_ *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) {
			rules.Active.Inspection.Status = RuleInspectionStatusApplied
		}},
		{name: "stale inspection is not proof", mutate: func(_ *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) {
			rules.Active.Inspection.Status = RuleInspectionStatusStale
		}},
		{name: "timeless inspection is not proof", mutate: func(_ *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) {
			rules.Active.Inspection.InspectedAtUnixMilli = 0
		}},
		{name: "warning-bearing inspection is not proof", mutate: func(_ *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) {
			rules.Active.Inspection.WarningCodes = []LifecycleWarningCode{LifecycleWarningProofMismatch}
		}},
		{name: "proxy identity mismatch", mutate: func(listener *ProxyListenerLifecycleResult, _ *RuleLifecycleResult) {
			listener.Active.Correlation.ProxySessionID = "proxy-session-other"
		}},
		{name: "proxy generation mismatch", mutate: func(listener *ProxyListenerLifecycleResult, _ *RuleLifecycleResult) {
			listener.Active.Correlation.ProxyGenerationID = "proxy-generation-other"
		}},
		{name: "rule generation mismatch", mutate: func(_ *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) {
			rules.Active.Inspection.Correlation.RuleGenerationID = "rule-generation-other"
		}},
		{name: "topology generation mismatch", mutate: func(_ *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) {
			rules.Active.Correlation.TopologyGenerationID = "topology-generation-other"
		}},
		{name: "policy mismatch", mutate: func(_ *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) {
			rules.Active.Inspection.Correlation.PolicySnapshotID = "policy-other"
		}},
		{name: "runtime mismatch", mutate: func(listener *ProxyListenerLifecycleResult, _ *RuleLifecycleResult) {
			listener.Active.Correlation.RuntimeID = "runtime-other"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := aggregationActiveListenerResult(plan)
			rules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
			tt.mutate(&listener, &rules)

			result := AggregateLiveEnforcementResult(plan, &listener, &rules)
			assertNoStrongAggregatedEnforcement(t, result)
		})
	}
}

func TestL7InspectedRuleProofSanitizesCorrelationAndRawLookingValues(t *testing.T) {
	proof := SanitizeInspectedRuleProof(InspectedRuleProof{
		ID:         "proof-safe",
		RuleDigest: "digest-safe",
		Status:     RuleInspectionStatusInspected,
		Correlation: &EnforcementCorrelation{
			SandboxID:            "sandbox-safe",
			ExecutionID:          "execution-safe",
			WorkerID:             "worker-safe",
			RuntimeID:            "runtime-safe",
			PlanID:               "plan-safe",
			PolicySnapshotID:     "policy-safe",
			ProxySessionID:       "http://127.0.0.1:8080",
			ProxyGenerationID:    "proxy-generation-safe",
			TopologyGenerationID: "/proc/self/ns/net",
			RuleGenerationID:     "generation-safe",
		},
		Mechanisms:           []EnforcementMechanism{EnforcementMechanismFirewall},
		InspectedAtUnixMilli: 1735689600000,
		CapabilityLabels:     []string{"default_deny"},
		ReasonCode:           LifecycleReasonRuleInspected,
	})

	if proof.Status == RuleInspectionStatusInspected {
		t.Fatalf("unsafe correlation retained inspected status: %#v", proof)
	}
	payload, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("Marshal proof: %v", err)
	}
	for _, forbidden := range []string{"127.0.0.1", "/proc/", "8080"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("proof leaked %q in %s", forbidden, payload)
		}
	}
}

func TestL7EnforcementCorrelationRequiresEveryIdentity(t *testing.T) {
	correlation := aggregationCorrelation(aggregationPlan(FirewallIntentModeApply))
	if !EnforcementCorrelationComplete(correlation) {
		t.Fatalf("complete correlation rejected: %#v", correlation)
	}
	correlation.WorkerID = ""
	if EnforcementCorrelationComplete(correlation) {
		t.Fatalf("correlation without worker identity accepted: %#v", correlation)
	}
}

func TestL7EnforcementCorrelationRequiresProxyGeneration(t *testing.T) {
	correlation := aggregationCorrelation(aggregationPlan(FirewallIntentModeApply))
	correlation.ProxyGenerationID = ""
	if EnforcementCorrelationComplete(correlation) {
		t.Fatalf("correlation without proxy generation accepted: %#v", correlation)
	}
}

func TestL7AggregationRequiresProxyPolicyCapabilities(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	for _, tt := range []struct {
		name   string
		labels []string
	}{
		{name: "missing all", labels: nil},
		{name: "missing HTTP request", labels: []string{"http_connect"}},
		{name: "missing CONNECT", labels: []string{"http_request"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listener := aggregationActiveListenerResult(plan)
			listener.Active.CapabilityLabels = tt.labels
			rules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)

			result := AggregateLiveEnforcementResult(plan, &listener, &rules)
			assertNoStrongAggregatedEnforcement(t, result)
			if !resultWarningCodesContain(result.WarningCodes, ResultWarningCapabilityDowngraded) {
				t.Fatalf("WarningCodes = %#v, want capability downgrade", result.WarningCodes)
			}
		})
	}
}
