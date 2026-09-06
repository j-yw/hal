package networkenforcement

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var _ RuleLifecycleAdapter = (*recordingRuleLifecycleAdapter)(nil)

type recordingRuleLifecycleAdapter struct {
	calls       []string
	metadata    map[string]RuleLifecycleMetadata
	failures    map[string]error
	received    []Plan
	rollbackReq []RuleLifecycleMetadata
	cleanupReq  []RuleLifecycleMetadata
}

func (a *recordingRuleLifecycleAdapter) PlanNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	return a.step(ctx, req, "plan_rules")
}

func (a *recordingRuleLifecycleAdapter) ApplyNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	return a.step(ctx, req, "apply_rules")
}

func (a *recordingRuleLifecycleAdapter) ActiveNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	return a.step(ctx, req, "active_rules")
}

func (a *recordingRuleLifecycleAdapter) RollbackNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	a.rollbackReq = append(a.rollbackReq, req.Active)
	return a.step(ctx, req, "rollback_rules")
}

func (a *recordingRuleLifecycleAdapter) CleanupNetworkRules(ctx context.Context, req RuleLifecycleRequest) (RuleLifecycleMetadata, error) {
	a.cleanupReq = append(a.cleanupReq, req.Active)
	return a.step(ctx, req, "cleanup_rules")
}

func (a *recordingRuleLifecycleAdapter) step(_ context.Context, req RuleLifecycleRequest, op string) (RuleLifecycleMetadata, error) {
	a.calls = append(a.calls, op)
	a.received = append(a.received, req.Plan.Plan())
	if err := a.failures[op]; err != nil {
		return RuleLifecycleMetadata{
			ID:           "rules-live-01",
			AdapterID:    "fake-rules",
			Status:       LifecycleStatusFailed,
			Mechanisms:   []EnforcementMechanism{EnforcementMechanismFirewall, EnforcementMechanismProxy},
			Operations:   []string{op, err.Error()},
			ReasonCode:   LifecycleReasonAdapterFailed,
			WarningCodes: []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError},
		}, err
	}
	if meta, ok := a.metadata[op]; ok {
		return meta, nil
	}
	return defaultRecordingRuleMetadata(op), nil
}

func TestRuleLifecycleRunnerApplyAndCleanupSequence(t *testing.T) {
	adapter := &recordingRuleLifecycleAdapter{}
	runner := RuleLifecycleRunner{Adapter: adapter}

	applied, err := runner.Apply(context.Background(), ruleLifecyclePlan())
	if err != nil {
		t.Fatalf("Apply() error = %v, want nil", err)
	}
	cleaned, err := runner.Cleanup(context.Background(), ruleLifecyclePlan(), applied.Active)
	if err != nil {
		t.Fatalf("Cleanup() error = %v, want nil", err)
	}

	assertRuleLifecycleCalls(t, adapter.calls, []string{"plan_rules", "apply_rules", "active_rules", "cleanup_rules"})
	if len(adapter.received) != 4 {
		t.Fatalf("adapter received %d plans, want 4", len(adapter.received))
	}
	for _, received := range adapter.received {
		if received.ID != "network-plan-rules" || received.Firewall == nil || received.Firewall.Mode != FirewallIntentModeApply {
			t.Fatalf("adapter received plan = %#v, want sanitized rule plan", received)
		}
		if received.Proxy == nil || received.Proxy.ProxySessionID != "proxy-session-rules" {
			t.Fatalf("adapter received proxy plan = %#v, want sanitized requested plan preserved for later phases", received.Proxy)
		}
	}

	if applied.Requested == nil {
		t.Fatal("Apply().Requested = nil, want requested rule lifecycle metadata")
	}
	if applied.Requested.Status != LifecycleStatusRequested {
		t.Fatalf("Apply().Requested.Status = %q, want requested", applied.Requested.Status)
	}
	if applied.Active == nil {
		t.Fatal("Apply().Active = nil, want active rule lifecycle metadata")
	}
	if applied.Active.Status != LifecycleStatusActive {
		t.Fatalf("Apply().Active.Status = %q, want active", applied.Active.Status)
	}
	if applied.Status != LifecycleStatusActive || applied.ReasonCode != LifecycleReasonActive {
		t.Fatalf("Apply() status/reason = %q/%q, want active/active", applied.Status, applied.ReasonCode)
	}
	if cleaned.Active == nil || cleaned.Active.Status != LifecycleStatusStopped {
		t.Fatalf("Cleanup().Active = %#v, want stopped rule metadata", cleaned.Active)
	}
	if cleaned.Status != LifecycleStatusStopped || cleaned.ReasonCode != LifecycleReasonStopped {
		t.Fatalf("Cleanup() status/reason = %q/%q, want stopped/stopped", cleaned.Status, cleaned.ReasonCode)
	}
	assertRuleOnlyLifecycle(t, applied)
	assertRuleOnlyLifecycle(t, cleaned)
	mustMarshalPlanObject(t, applied)
	mustMarshalPlanObject(t, cleaned)
}

func TestRuleLifecycleRunnerApplyFailureRollsBackPartialRules(t *testing.T) {
	adapter := &recordingRuleLifecycleAdapter{
		failures: map[string]error{"apply_rules": errors.New("iptables -A OUTPUT -d 10.0.0.1 --dport 443 token=secret")},
	}
	runner := RuleLifecycleRunner{Adapter: adapter}

	result, err := runner.Apply(context.Background(), ruleLifecyclePlan())
	if err == nil {
		t.Fatal("Apply() error = nil, want sanitized apply failure")
	}

	assertRuleLifecycleCalls(t, adapter.calls, []string{"plan_rules", "apply_rules", "rollback_rules"})
	if len(adapter.rollbackReq) != 1 {
		t.Fatalf("rollback requests = %d, want 1", len(adapter.rollbackReq))
	}
	if adapter.rollbackReq[0].Status != LifecycleStatusFailed || adapter.rollbackReq[0].ReasonCode != LifecycleReasonAdapterFailed {
		t.Fatalf("rollback active request = %#v, want failed apply metadata", adapter.rollbackReq[0])
	}
	if result.Active == nil || result.Active.Status != LifecycleStatusFailed {
		t.Fatalf("apply failure active = %#v, want failed metadata", result.Active)
	}
	if result.ReasonCode != LifecycleReasonAdapterFailed {
		t.Fatalf("apply failure reason = %q, want adapter_failed", result.ReasonCode)
	}
	assertPlanStringArrayFromStrings(t, result.Active.Operations, []string{"apply_rules"})
	assertRuleOnlyLifecycle(t, result)
	assertSanitizedRuleLifecycleFailure(t, err, result)
}

func TestRuleLifecycleRunnerActiveCheckFailureRollsBackAppliedRules(t *testing.T) {
	adapter := &recordingRuleLifecycleAdapter{
		failures: map[string]error{"active_rules": errors.New("nftables rule missing for 192.168.0.1:8443 secret=token")},
	}
	runner := RuleLifecycleRunner{Adapter: adapter}

	result, err := runner.Apply(context.Background(), ruleLifecyclePlan())
	if err == nil {
		t.Fatal("Apply() error = nil, want sanitized active-check failure")
	}

	assertRuleLifecycleCalls(t, adapter.calls, []string{"plan_rules", "apply_rules", "active_rules", "rollback_rules"})
	if len(adapter.rollbackReq) != 1 {
		t.Fatalf("rollback requests = %d, want 1", len(adapter.rollbackReq))
	}
	if adapter.rollbackReq[0].Status != LifecycleStatusApplying || adapter.rollbackReq[0].ReasonCode != LifecycleReasonApplied {
		t.Fatalf("rollback active request = %#v, want applied rule metadata", adapter.rollbackReq[0])
	}
	if result.ReasonCode != LifecycleReasonActiveCheckFailed || result.Active == nil || result.Active.ReasonCode != LifecycleReasonActiveCheckFailed {
		t.Fatalf("active failure result = %#v, want active_check_failed", result)
	}
	assertRuleOnlyLifecycle(t, result)
	assertSanitizedRuleLifecycleFailure(t, err, result)
}

func TestRuleLifecycleRunnerRollbackFailureIsSanitizedWarning(t *testing.T) {
	adapter := &recordingRuleLifecycleAdapter{
		failures: map[string]error{
			"active_rules":   errors.New("pfctl active check failed for /tmp/pf.rules"),
			"rollback_rules": errors.New("rollback command leaked process 1234 token=secret"),
		},
	}
	runner := RuleLifecycleRunner{Adapter: adapter}

	result, err := runner.Apply(context.Background(), ruleLifecyclePlan())
	if err == nil {
		t.Fatal("Apply() error = nil, want sanitized active-check failure")
	}

	assertRuleLifecycleCalls(t, adapter.calls, []string{"plan_rules", "apply_rules", "active_rules", "rollback_rules"})
	if !reflect.DeepEqual(result.WarningCodes, []LifecycleWarningCode{
		LifecycleWarningSanitizedAdapterError,
		LifecycleWarningRollbackFailed,
	}) {
		t.Fatalf("failure warnings = %#v, want sanitized adapter and rollback warnings", result.WarningCodes)
	}
	if result.Active == nil || !reflect.DeepEqual(result.Active.WarningCodes, []LifecycleWarningCode{
		LifecycleWarningSanitizedAdapterError,
		LifecycleWarningRollbackFailed,
	}) {
		t.Fatalf("active warnings = %#v, want sanitized rollback warning", result.Active)
	}
	if result.Status == LifecycleStatusActive || result.Active.Status == LifecycleStatusActive {
		t.Fatalf("rollback failure result overclaimed active enforcement: %#v", result)
	}
	assertSanitizedRuleLifecycleFailure(t, err, result)
}

func TestRuleLifecycleRunnerCleanupFailureIsWarningOnly(t *testing.T) {
	adapter := &recordingRuleLifecycleAdapter{
		failures: map[string]error{"cleanup_rules": errors.New("delete iptables rule in /Users/alice/fw with token=secret")},
	}
	runner := RuleLifecycleRunner{Adapter: adapter}

	applied, err := runner.Apply(context.Background(), ruleLifecyclePlan())
	if err != nil {
		t.Fatalf("Apply() error = %v, want nil", err)
	}
	cleaned, err := runner.Cleanup(context.Background(), ruleLifecyclePlan(), applied.Active)
	if err != nil {
		t.Fatalf("Cleanup() error = %v, want nil because cleanup failure is warning metadata", err)
	}

	assertRuleLifecycleCalls(t, adapter.calls, []string{"plan_rules", "apply_rules", "active_rules", "cleanup_rules"})
	if cleaned.Status != LifecycleStatusStopped {
		t.Fatalf("Cleanup() status = %q, want stopped", cleaned.Status)
	}
	if !reflect.DeepEqual(cleaned.WarningCodes, []LifecycleWarningCode{
		LifecycleWarningCleanupFailed,
		LifecycleWarningSanitizedAdapterError,
	}) {
		t.Fatalf("Cleanup() warnings = %#v, want cleanup and sanitized adapter warnings", cleaned.WarningCodes)
	}
	if cleaned.Active != nil && cleaned.Active.Status == LifecycleStatusActive {
		t.Fatalf("cleanup failure retained active enforcement claim: %#v", cleaned.Active)
	}
	assertRuleOnlyLifecycle(t, cleaned)
	payload, marshalErr := json.Marshal(cleaned)
	if marshalErr != nil {
		t.Fatalf("Marshal(Cleanup result) error: %v", marshalErr)
	}
	assertLifecyclePayloadSanitized(t, string(payload), "cleanup failure result")
}

func TestRuleLifecycleRunnerPlanFailureDoesNotApplyOrRollback(t *testing.T) {
	adapter := &recordingRuleLifecycleAdapter{
		failures: map[string]error{"plan_rules": errors.New("render firewall command for 127.0.0.1:443 with secret")},
	}
	runner := RuleLifecycleRunner{Adapter: adapter}

	result, err := runner.Apply(context.Background(), ruleLifecyclePlan())
	if err == nil {
		t.Fatal("Apply() error = nil, want sanitized plan failure")
	}

	assertRuleLifecycleCalls(t, adapter.calls, []string{"plan_rules"})
	if result.Active == nil || result.Active.Status != LifecycleStatusFailed {
		t.Fatalf("plan failure active = %#v, want failed metadata", result.Active)
	}
	if result.ReasonCode != LifecycleReasonAdapterFailed {
		t.Fatalf("plan failure reason = %q, want adapter_failed", result.ReasonCode)
	}
	assertSanitizedRuleLifecycleFailure(t, err, result)
}

func TestRuleLifecycleRunnerUsesFakeAdapterOnly(t *testing.T) {
	adapter := &recordingRuleLifecycleAdapter{
		metadata: map[string]RuleLifecycleMetadata{
			"active_rules": {
				ID:               "rules-live-01",
				PlanID:           "network-plan-rules",
				AdapterID:        "fake-rules",
				Status:           LifecycleStatusActive,
				Mechanisms:       []EnforcementMechanism{EnforcementMechanismFirewall, EnforcementMechanismRuntime},
				Operations:       []string{"active_rules", "firewall-cmd --add-rich-rule"},
				CapabilityLabels: []string{"default_deny", "runtime_rule_active", "process-handle-1234"},
				ReasonCode:       LifecycleReasonActive,
			},
		},
	}
	runner := RuleLifecycleRunner{Adapter: adapter}

	result, err := runner.Apply(context.Background(), ruleLifecyclePlan())
	if err != nil {
		t.Fatalf("Apply() error = %v, want nil", err)
	}

	assertRuleLifecycleCalls(t, adapter.calls, []string{"plan_rules", "apply_rules", "active_rules"})
	assertRuleOnlyLifecycle(t, result)
	payload, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatalf("Marshal(fake-only result) error: %v", marshalErr)
	}
	assertLifecyclePayloadSanitized(t, string(payload), "fake-only result")
	if !strings.Contains(string(payload), "fake-rules") {
		t.Fatalf("fake-only result missing fake adapter metadata: %s", payload)
	}
}

func ruleLifecyclePlan() Plan {
	return BuildPlan(PlanRequest{
		ID:        "network-plan-rules",
		Source:    PlanSourceRuntime,
		Operation: "apply_network",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-rules",
			Version:   "v1",
			Preset:    PolicyPresetDenyByDefault,
			RuleSetID: "rules-live-01",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:            PolicyPresetDenyByDefault,
			RuleSetID:         "rules-live-01",
			RuleIDs:           []string{"rule-safe-01"},
			RuleCategories:    []AllowlistRuleCategory{AllowlistRuleCategoryDomain},
			HTTP:              ProxyRoutingModeRouteViaProxy,
			HTTPS:             ProxyRoutingModeRouteViaProxy,
			ProxySessionID:    "proxy-session-rules",
			ProxyMechanism:    EnforcementMechanismProxy,
			FirewallMode:      FirewallIntentModeApply,
			FirewallMechanism: EnforcementMechanismFirewall,
		},
	})
}

func defaultRecordingRuleMetadata(op string) RuleLifecycleMetadata {
	status := LifecycleStatusPlanned
	reason := LifecycleReasonPrepared
	switch op {
	case "apply_rules":
		status = LifecycleStatusApplying
		reason = LifecycleReasonApplied
	case "active_rules":
		status = LifecycleStatusActive
		reason = LifecycleReasonActive
	case "rollback_rules":
		status = LifecycleStatusRollingBack
		reason = LifecycleReasonRollbackFailed
	case "cleanup_rules":
		status = LifecycleStatusStopped
		reason = LifecycleReasonStopped
	}
	return RuleLifecycleMetadata{
		ID:               "rules-live-01",
		PlanID:           "network-plan-rules",
		AdapterID:        "fake-rules",
		Status:           status,
		Mechanisms:       []EnforcementMechanism{EnforcementMechanismFirewall, EnforcementMechanismProxy},
		Operations:       []string{op},
		PolicySnapshot:   &PolicySnapshotIdentity{ID: "policy-rules", Preset: PolicyPresetDenyByDefault},
		CapabilityLabels: []string{"default_deny", "proxy_listener"},
		ReasonCode:       reason,
	}
}

func assertRuleLifecycleCalls(t *testing.T, got []string, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adapter calls = %#v, want %#v", got, want)
	}
}

func assertRuleOnlyLifecycle(t *testing.T, result RuleLifecycleResult) {
	t.Helper()
	for label, metadata := range map[string]*RuleLifecycleMetadata{
		"requested": result.Requested,
		"active":    result.Active,
	} {
		if metadata == nil {
			continue
		}
		for _, mechanism := range metadata.Mechanisms {
			if mechanism != EnforcementMechanismFirewall && mechanism != EnforcementMechanismRuntime {
				t.Fatalf("%s mechanisms = %#v, want firewall/runtime only", label, metadata.Mechanisms)
			}
		}
		for _, capability := range metadata.CapabilityLabels {
			lower := strings.ToLower(capability)
			if strings.Contains(lower, "proxy") || strings.Contains(lower, "process") {
				t.Fatalf("%s capability label %q implies listener/process details", label, capability)
			}
		}
	}
}

func assertSanitizedRuleLifecycleFailure(t *testing.T, err error, result RuleLifecycleResult) {
	t.Helper()
	payload, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatalf("Marshal(rule lifecycle result) error: %v", marshalErr)
	}
	assertLifecyclePayloadSanitized(t, err.Error()+" "+string(payload), "rule failure surfaces")
	for _, required := range []string{
		string(LifecycleStatusFailed),
		string(LifecycleReasonAdapterFailed),
		string(LifecycleWarningSanitizedAdapterError),
	} {
		if !strings.Contains(err.Error()+" "+string(payload), required) {
			t.Fatalf("rule failure surfaces missing safe marker %q in err=%q payload=%s", required, err.Error(), payload)
		}
	}
}
