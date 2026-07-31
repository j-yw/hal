package networkenforcement

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestLiveEnforcementAggregationRequiresBothActiveSides(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	listener := aggregationActiveListenerResult(plan)
	rules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
	rules.Active.Inspection.CapabilityLabels = aggregationDefaultDenyRuleCapabilityLabels()

	result := AggregateLiveEnforcementResult(plan, &listener, &rules)

	assertStrongAggregatedEnforcement(t, result, ResultModeProxyFirewall, []EnforcementMechanism{
		EnforcementMechanismProxy,
		EnforcementMechanismFirewall,
	})
	assertAggregationPayloadSanitized(t, result)
}

func TestLiveEnforcementAggregationRequiresDefaultDenyRuleCapabilityProof(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	listener := aggregationActiveListenerResult(plan)
	provenRules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
	provenRules.Active.Inspection.CapabilityLabels = aggregationDefaultDenyRuleCapabilityLabels()

	result := AggregateLiveEnforcementResult(plan, &listener, &provenRules)

	assertStrongAggregatedEnforcement(t, result, ResultModeProxyFirewall, []EnforcementMechanism{
		EnforcementMechanismProxy,
		EnforcementMechanismFirewall,
	})
	assertAggregationPayloadSanitized(t, result)

	for _, tt := range []struct {
		name   string
		labels []string
	}{
		{
			name:   "missing all capability proof",
			labels: nil,
		},
		{
			name:   "missing default-deny proof",
			labels: []string{"private_range_rules", "metadata_endpoint"},
		},
		{
			name:   "missing private range proof",
			labels: []string{"default_deny", "metadata_endpoint"},
		},
		{
			name:   "missing metadata endpoint proof",
			labels: []string{"default_deny", "private_range_rules"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
			rules.Active.Inspection.CapabilityLabels = tt.labels

			result := AggregateLiveEnforcementResult(plan, &listener, &rules)

			assertNoStrongAggregatedEnforcement(t, result)
			if result.ReasonCode != ResultReasonCapabilityMissing {
				t.Fatalf("ReasonCode = %q, want %q in %#v", result.ReasonCode, ResultReasonCapabilityMissing, result)
			}
			if !resultWarningCodesContain(result.WarningCodes, ResultWarningCapabilityDowngraded) {
				t.Fatalf("WarningCodes = %#v, want %q", result.WarningCodes, ResultWarningCapabilityDowngraded)
			}
			assertAggregationPayloadSanitized(t, result)
		})
	}
}

func TestLiveEnforcementAggregationDowngradesPartialAndMetadataOnlyResults(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	activeListener := aggregationActiveListenerResult(plan)
	activeRules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
	activeRules.Active.Inspection.CapabilityLabels = aggregationDefaultDenyRuleCapabilityLabels()
	failedListener := aggregationActiveListenerResult(plan)
	failedListener.Status = LifecycleStatusFailed
	failedListener.ReasonCode = LifecycleReasonAdapterFailed
	failedListener.WarningCodes = []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError}
	failedListener.Active.Status = LifecycleStatusFailed
	failedListener.Active.ReasonCode = LifecycleReasonAdapterFailed
	failedListener.Active.WarningCodes = []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError}
	failedRules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
	failedRules.Status = LifecycleStatusFailed
	failedRules.ReasonCode = LifecycleReasonAdapterFailed
	failedRules.WarningCodes = []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError}
	failedRules.Active.Status = LifecycleStatusFailed
	failedRules.Active.ReasonCode = LifecycleReasonAdapterFailed
	failedRules.Active.WarningCodes = []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError}
	activeCheckFailedRules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
	activeCheckFailedRules.Status = LifecycleStatusFailed
	activeCheckFailedRules.ReasonCode = LifecycleReasonActiveCheckFailed
	activeCheckFailedRules.WarningCodes = []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError}
	activeCheckFailedRules.Active.Status = LifecycleStatusFailed
	activeCheckFailedRules.Active.ReasonCode = LifecycleReasonActiveCheckFailed
	activeCheckFailedRules.Active.WarningCodes = []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError}
	rollbackFailedRules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
	rollbackFailedRules.Status = LifecycleStatusFailed
	rollbackFailedRules.ReasonCode = LifecycleReasonActiveCheckFailed
	rollbackFailedRules.WarningCodes = []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError, LifecycleWarningRollbackFailed}
	rollbackFailedRules.Active.Status = LifecycleStatusFailed
	rollbackFailedRules.Active.ReasonCode = LifecycleReasonActiveCheckFailed
	rollbackFailedRules.Active.WarningCodes = []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError, LifecycleWarningRollbackFailed}
	cleanupFailedRules := aggregationActiveRuleResult(plan, EnforcementMechanismFirewall)
	cleanupFailedRules.Status = LifecycleStatusStopped
	cleanupFailedRules.ReasonCode = LifecycleReasonStopped
	cleanupFailedRules.WarningCodes = []LifecycleWarningCode{LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError}
	cleanupFailedRules.Active.Status = LifecycleStatusStopped
	cleanupFailedRules.Active.ReasonCode = LifecycleReasonStopped
	cleanupFailedRules.Active.WarningCodes = []LifecycleWarningCode{LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError}

	for _, tt := range []struct {
		name     string
		plan     Plan
		listener *ProxyListenerLifecycleResult
		rules    *RuleLifecycleResult
	}{
		{
			name: "nil adapters",
			plan: aggregationPlan(FirewallIntentModeApply),
		},
		{
			name:     "listener-only success",
			plan:     aggregationPlan(FirewallIntentModeApply),
			listener: &activeListener,
		},
		{
			name:  "rule-only success",
			plan:  aggregationPlan(FirewallIntentModeApply),
			rules: &activeRules,
		},
		{
			name:     "listener failure",
			plan:     aggregationPlan(FirewallIntentModeApply),
			listener: &failedListener,
			rules:    &activeRules,
		},
		{
			name:     "rule failure",
			plan:     aggregationPlan(FirewallIntentModeApply),
			listener: &activeListener,
			rules:    &failedRules,
		},
		{
			name:     "active-check failure",
			plan:     aggregationPlan(FirewallIntentModeApply),
			listener: &activeListener,
			rules:    &activeCheckFailedRules,
		},
		{
			name:     "audit-only setup",
			plan:     aggregationPlan(FirewallIntentModeAuditOnly),
			listener: &activeListener,
			rules:    &activeRules,
		},
		{
			name:     "best-effort setup",
			plan:     aggregationPlan(FirewallIntentModePrepare),
			listener: &activeListener,
			rules:    &activeRules,
		},
		{
			name:     "rollback failure",
			plan:     aggregationPlan(FirewallIntentModeApply),
			listener: &activeListener,
			rules:    &rollbackFailedRules,
		},
		{
			name:     "cleanup failure",
			plan:     aggregationPlan(FirewallIntentModeApply),
			listener: &activeListener,
			rules:    &cleanupFailedRules,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result := AggregateLiveEnforcementResult(tt.plan, tt.listener, tt.rules)

			assertNoStrongAggregatedEnforcement(t, result)
			assertAggregationPayloadSanitized(t, result)
		})
	}
}

func TestLiveEnforcementRunnerOrchestratesBothSidesBeforeClaimingStrongMode(t *testing.T) {
	listener := aggregationListenerAdapter(aggregationPlan(FirewallIntentModeApply), nil)
	rules := aggregationRuleAdapter(aggregationPlan(FirewallIntentModeApply), nil, EnforcementMechanismFirewall)
	runner := LiveEnforcementRunner{
		Listener: ProxyListenerLifecycleRunner{Adapter: listener},
		Rules:    RuleLifecycleRunner{Adapter: rules},
	}

	result := runner.EnforceNetwork(context.Background(), NewSanitizedPlan(aggregationPlan(FirewallIntentModeApply)))

	assertProxyListenerCalls(t, listener.calls, []string{"prepare_proxy", "start_proxy", "active_proxy"})
	assertRuleLifecycleCalls(t, rules.calls, []string{"plan_rules", "apply_rules", "active_rules"})
	assertStrongAggregatedEnforcement(t, result, ResultModeProxyFirewall, []EnforcementMechanism{
		EnforcementMechanismProxy,
		EnforcementMechanismFirewall,
	})
}

func TestLiveEnforcementRunnerFailsClosedForNilAndPartialAdapters(t *testing.T) {
	for _, tt := range []struct {
		name         string
		listener     *recordingProxyListenerAdapter
		rules        *recordingRuleLifecycleAdapter
		wantListener []string
		wantRules    []string
		wantWarning  ResultWarningCode
		wantReason   ResultReasonCode
		wantOutcome  ResultOutcome
	}{
		{
			name:        "nil adapters",
			wantOutcome: ResultOutcomeUnsupported,
			wantReason:  ResultReasonAdapterUnsupported,
		},
		{
			name:         "listener failure",
			listener:     aggregationListenerAdapter(aggregationPlan(FirewallIntentModeApply), map[string]error{"active_proxy": errors.New("listener localhost:8080 token=secret")}),
			rules:        aggregationRuleAdapter(aggregationPlan(FirewallIntentModeApply), nil, EnforcementMechanismFirewall),
			wantListener: []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"},
			wantReason:   ResultReasonAdapterFailed,
			wantOutcome:  ResultOutcomeFailure,
		},
		{
			name:         "rule failure",
			listener:     aggregationListenerAdapter(aggregationPlan(FirewallIntentModeApply), nil),
			rules:        aggregationRuleAdapter(aggregationPlan(FirewallIntentModeApply), map[string]error{"apply_rules": errors.New("iptables command token=secret")}, EnforcementMechanismFirewall),
			wantListener: []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"},
			wantRules:    []string{"plan_rules", "apply_rules", "rollback_rules"},
			wantWarning:  ResultWarningPartialEnforcement,
			wantReason:   ResultReasonAdapterFailed,
			wantOutcome:  ResultOutcomeFailure,
		},
		{
			name:         "active-check failure",
			listener:     aggregationListenerAdapter(aggregationPlan(FirewallIntentModeApply), nil),
			rules:        aggregationRuleAdapter(aggregationPlan(FirewallIntentModeApply), map[string]error{"active_rules": errors.New("active check leaked api.internal.example.com:443")}, EnforcementMechanismFirewall),
			wantListener: []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"},
			wantRules:    []string{"plan_rules", "apply_rules", "active_rules", "rollback_rules"},
			wantWarning:  ResultWarningPartialEnforcement,
			wantReason:   ResultReasonAdapterFailed,
			wantOutcome:  ResultOutcomeFailure,
		},
		{
			name:         "rollback failure",
			listener:     aggregationListenerAdapter(aggregationPlan(FirewallIntentModeApply), nil),
			rules:        aggregationRuleAdapter(aggregationPlan(FirewallIntentModeApply), map[string]error{"active_rules": errors.New("active check failed"), "rollback_rules": errors.New("rollback /tmp/rules token=secret")}, EnforcementMechanismFirewall),
			wantListener: []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"},
			wantRules:    []string{"plan_rules", "apply_rules", "active_rules", "rollback_rules"},
			wantWarning:  ResultWarningPartialEnforcement,
			wantReason:   ResultReasonAdapterFailed,
			wantOutcome:  ResultOutcomeFailure,
		},
		{
			name:         "cleanup failure",
			listener:     aggregationListenerAdapter(aggregationPlan(FirewallIntentModeApply), map[string]error{"stop_proxy": errors.New("cleanup /tmp/proxy.sock token=secret")}),
			rules:        aggregationRuleAdapter(aggregationPlan(FirewallIntentModeApply), map[string]error{"active_rules": errors.New("active check failed")}, EnforcementMechanismFirewall),
			wantListener: []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"},
			wantRules:    []string{"plan_rules", "apply_rules", "active_rules", "rollback_rules"},
			wantWarning:  ResultWarningPartialEnforcement,
			wantReason:   ResultReasonAdapterFailed,
			wantOutcome:  ResultOutcomeFailure,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runner := LiveEnforcementRunner{}
			if tt.listener != nil {
				runner.Listener = ProxyListenerLifecycleRunner{Adapter: tt.listener}
			}
			if tt.rules != nil {
				runner.Rules = RuleLifecycleRunner{Adapter: tt.rules}
			}

			result := runner.EnforceNetwork(context.Background(), NewSanitizedPlan(aggregationPlan(FirewallIntentModeApply)))

			if tt.listener != nil {
				assertProxyListenerCalls(t, tt.listener.calls, tt.wantListener)
			}
			if tt.rules != nil {
				assertRuleLifecycleCalls(t, tt.rules.calls, tt.wantRules)
			}
			if result.Outcome != tt.wantOutcome {
				t.Fatalf("Outcome = %q, want %q", result.Outcome, tt.wantOutcome)
			}
			if result.ReasonCode != tt.wantReason {
				t.Fatalf("ReasonCode = %q, want %q", result.ReasonCode, tt.wantReason)
			}
			if tt.wantWarning != "" && !resultWarningCodesContain(result.WarningCodes, tt.wantWarning) {
				t.Fatalf("WarningCodes = %#v, want %q", result.WarningCodes, tt.wantWarning)
			}
			assertNoStrongAggregatedEnforcement(t, result)
			assertAggregationPayloadSanitized(t, result)
		})
	}
}

func aggregationPlan(mode FirewallIntentMode) Plan {
	return BuildPlan(PlanRequest{
		ID:        "network-plan-aggregation",
		Source:    PlanSourceRuntime,
		Operation: "aggregate_network",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-aggregation",
			Version:   "v1",
			Preset:    PolicyPresetDenyByDefault,
			RuleSetID: "rules-aggregation",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:            PolicyPresetDenyByDefault,
			RuleSetID:         "rules-aggregation",
			RuleIDs:           []string{"rule-aggregation-domain", "rule-aggregation-endpoint"},
			RuleCategories:    []AllowlistRuleCategory{AllowlistRuleCategoryDomain, AllowlistRuleCategoryEndpoint},
			PrivateNetwork:    PostureBlock,
			MetadataEndpoint:  PostureBlock,
			HTTP:              ProxyRoutingModeRouteViaProxy,
			HTTPS:             ProxyRoutingModeRouteViaProxy,
			ProxySessionID:    "proxy-session-aggregation",
			ProxyMechanism:    EnforcementMechanismProxy,
			FirewallMode:      mode,
			FirewallMechanism: EnforcementMechanismFirewall,
		},
	})
}

func aggregationListenerAdapter(plan Plan, failures map[string]error) *recordingProxyListenerAdapter {
	return &recordingProxyListenerAdapter{
		failures: failures,
		metadata: map[string]ProxyListenerLifecycleMetadata{
			"prepare_proxy": aggregationListenerMetadata(plan, LifecycleStatusPrepared, LifecycleReasonPrepared, "prepare_proxy"),
			"start_proxy":   aggregationListenerMetadata(plan, LifecycleStatusStarting, LifecycleReasonStarted, "start_proxy"),
			"active_proxy":  aggregationListenerMetadata(plan, LifecycleStatusActive, LifecycleReasonActive, "active_proxy"),
			"stop_proxy":    aggregationListenerMetadata(plan, LifecycleStatusStopped, LifecycleReasonStopped, "stop_proxy"),
		},
	}
}

func aggregationRuleAdapter(plan Plan, failures map[string]error, mechanism EnforcementMechanism) *recordingRuleLifecycleAdapter {
	return &recordingRuleLifecycleAdapter{
		failures: failures,
		metadata: map[string]RuleLifecycleMetadata{
			"plan_rules":     aggregationRuleMetadata(plan, LifecycleStatusPlanned, LifecycleReasonPrepared, "plan_rules", mechanism),
			"apply_rules":    aggregationRuleMetadata(plan, LifecycleStatusApplying, LifecycleReasonApplied, "apply_rules", mechanism),
			"active_rules":   aggregationRuleMetadata(plan, LifecycleStatusActive, LifecycleReasonActive, "active_rules", mechanism),
			"rollback_rules": aggregationRuleMetadata(plan, LifecycleStatusRollingBack, LifecycleReasonRollbackFailed, "rollback_rules", mechanism),
			"cleanup_rules":  aggregationRuleMetadata(plan, LifecycleStatusStopped, LifecycleReasonStopped, "cleanup_rules", mechanism),
		},
	}
}

func aggregationActiveListenerResult(plan Plan) ProxyListenerLifecycleResult {
	active := aggregationListenerMetadata(plan, LifecycleStatusActive, LifecycleReasonActive, "active_proxy")
	return ProxyListenerLifecycleResult{
		PlanID:     plan.ID,
		AdapterID:  active.AdapterID,
		Requested:  sanitizeProxyListenerOnlyMetadataPtr(&ProxyListenerLifecycleMetadata{PlanID: plan.ID, Status: LifecycleStatusRequested, Mechanisms: []EnforcementMechanism{EnforcementMechanismProxy}}),
		Active:     &active,
		Status:     LifecycleStatusActive,
		ReasonCode: LifecycleReasonActive,
	}
}

func aggregationActiveRuleResult(plan Plan, mechanism EnforcementMechanism) RuleLifecycleResult {
	active := aggregationRuleMetadata(plan, LifecycleStatusActive, LifecycleReasonActive, "active_rules", mechanism)
	return RuleLifecycleResult{
		PlanID:     plan.ID,
		AdapterID:  active.AdapterID,
		Requested:  sanitizeRuleLifecycleOnlyMetadataPtr(&RuleLifecycleMetadata{PlanID: plan.ID, Status: LifecycleStatusRequested, Mechanisms: []EnforcementMechanism{mechanism}}),
		Active:     &active,
		Status:     LifecycleStatusActive,
		ReasonCode: LifecycleReasonActive,
	}
}

func aggregationDefaultDenyRuleCapabilityLabels() []string {
	return []string{
		"default_deny",
		"private_range_rules",
		"metadata_endpoint",
		"loopback_rules",
		"link_local_rules",
		"raw_protocols",
	}
}

func aggregationListenerMetadata(plan Plan, status LifecycleStatus, reason LifecycleReasonCode, operation string) ProxyListenerLifecycleMetadata {
	correlation := aggregationCorrelation(plan)
	return ProxyListenerLifecycleMetadata{
		ID:               "proxy-live-aggregation",
		PlanID:           plan.ID,
		AdapterID:        "fake-aggregation-listener",
		Status:           status,
		Mechanisms:       []EnforcementMechanism{EnforcementMechanismProxy},
		Operations:       []string{operation},
		PolicySnapshot:   plan.PolicySnapshot,
		CapabilityLabels: []string{"http_request", "http_connect"},
		Correlation:      &correlation,
		ReasonCode:       reason,
	}
}

func aggregationRuleMetadata(plan Plan, status LifecycleStatus, reason LifecycleReasonCode, operation string, mechanism EnforcementMechanism) RuleLifecycleMetadata {
	correlation := aggregationCorrelation(plan)
	metadata := RuleLifecycleMetadata{
		ID:               "rules-aggregation",
		PlanID:           plan.ID,
		AdapterID:        "fake-aggregation-rules",
		Status:           status,
		Mechanisms:       []EnforcementMechanism{mechanism},
		Operations:       []string{operation},
		PolicySnapshot:   plan.PolicySnapshot,
		CapabilityLabels: aggregationDefaultDenyRuleCapabilityLabels(),
		Correlation:      &correlation,
		ReasonCode:       reason,
	}
	if status == LifecycleStatusActive {
		metadata.Inspection = &InspectedRuleProof{
			ID:                   "rule-proof-aggregation",
			RuleDigest:           "rule-digest-aggregation",
			Status:               RuleInspectionStatusInspected,
			InspectedAtUnixMilli: 1735689600000,
			Correlation:          &correlation,
			Mechanisms:           []EnforcementMechanism{mechanism},
			CapabilityLabels:     aggregationDefaultDenyRuleCapabilityLabels(),
			ReasonCode:           LifecycleReasonRuleInspected,
		}
	}
	return metadata
}

func aggregationCorrelation(plan Plan) EnforcementCorrelation {
	return EnforcementCorrelation{
		SandboxID:            "sandbox-aggregation",
		ExecutionID:          "execution-aggregation",
		WorkerID:             "worker-aggregation",
		RuntimeID:            "runtime-aggregation",
		PlanID:               plan.ID,
		PolicySnapshotID:     plan.PolicySnapshot.ID,
		ProxySessionID:       plan.Proxy.ProxySessionID,
		ProxyGenerationID:    "proxy-generation-aggregation",
		TopologyGenerationID: "topology-generation-aggregation",
		RuleGenerationID:     "rule-generation-aggregation",
	}
}

func assertStrongAggregatedEnforcement(t *testing.T, result Result, mode ResultMode, mechanisms []EnforcementMechanism) {
	t.Helper()
	if result.Outcome != ResultOutcomeSuccess {
		t.Fatalf("Outcome = %q, want success", result.Outcome)
	}
	if result.EnforcementMode != mode {
		t.Fatalf("EnforcementMode = %q, want %q", result.EnforcementMode, mode)
	}
	if !reflect.DeepEqual(result.Mechanisms, mechanisms) {
		t.Fatalf("Mechanisms = %#v, want %#v", result.Mechanisms, mechanisms)
	}
	if result.Capability == nil ||
		!result.Capability.Supported ||
		!result.Capability.SupportsDefaultDenyPosture ||
		!reflect.DeepEqual(result.Capability.Modes, []ResultMode{mode}) {
		t.Fatalf("Capability = %#v, want strong default-deny mode %q", result.Capability, mode)
	}
}

func assertNoStrongAggregatedEnforcement(t *testing.T, result Result) {
	t.Helper()
	switch result.EnforcementMode {
	case ResultModeProxy, ResultModeFirewall, ResultModeRuntime, ResultModeProxyFirewall:
		t.Fatalf("EnforcementMode = %q, want no strong enforcement claim in %#v", result.EnforcementMode, result)
	}
	if result.Capability != nil && (result.Capability.Supported ||
		len(result.Capability.Modes) > 0 ||
		result.Capability.SupportsDefaultDenyPosture) {
		t.Fatalf("Capability = %#v, want no default-deny or strong mode capability", result.Capability)
	}
}

func assertAggregationPayloadSanitized(t *testing.T, result Result) {
	t.Helper()
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(Result) error: %v", err)
	}
	assertLifecyclePayloadSanitized(t, string(payload), "aggregation result")
	lower := strings.ToLower(string(payload))
	for _, forbidden := range []string{"iptables", "nftables", "pfctl", "firewall-cmd"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("aggregation result leaked forbidden marker %q in %s", forbidden, payload)
		}
	}
}

func resultWarningCodesContain(values []ResultWarningCode, target ResultWarningCode) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
