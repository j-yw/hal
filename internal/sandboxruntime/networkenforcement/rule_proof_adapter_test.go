package networkenforcement

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type recordingRuleProofStepRunner struct {
	mechanism EnforcementMechanism
	calls     []string
	requests  []RuleProofStepRequest
	failures  map[string]error
}

func (r *recordingRuleProofStepRunner) RunRuleProofStep(_ context.Context, req RuleProofStepRequest) (RuleLifecycleMetadata, error) {
	r.calls = append(r.calls, req.Operation)
	r.requests = append(r.requests, req)
	if err := r.failures[req.Operation]; err != nil {
		return r.ruleProofMetadata(req, LifecycleStatusFailed, LifecycleReasonAdapterFailed), err
	}
	switch req.Operation {
	case ruleOperationApply:
		return r.ruleProofMetadata(req, LifecycleStatusApplying, LifecycleReasonApplied), nil
	case ruleOperationActive:
		return r.ruleProofMetadata(req, LifecycleStatusActive, LifecycleReasonActive), nil
	case ruleOperationRollback:
		return r.ruleProofMetadata(req, LifecycleStatusRollingBack, LifecycleReasonRollbackFailed), nil
	case ruleOperationCleanup:
		return r.ruleProofMetadata(req, LifecycleStatusStopped, LifecycleReasonStopped), nil
	default:
		return r.ruleProofMetadata(req, LifecycleStatusPlanned, LifecycleReasonPrepared), nil
	}
}

func (r *recordingRuleProofStepRunner) ruleProofMetadata(req RuleProofStepRequest, status LifecycleStatus, reason LifecycleReasonCode) RuleLifecycleMetadata {
	mechanism := r.mechanism
	if mechanism == "" {
		mechanism = req.Mechanism
	}
	return RuleLifecycleMetadata{
		ID:        "rules-proof-01",
		PlanID:    req.Plan.Plan().ID,
		AdapterID: "fake-proof-runner",
		Status:    status,
		Mechanisms: []EnforcementMechanism{
			mechanism,
			EnforcementMechanismProxy,
		},
		Operations: []string{
			req.Operation,
			"iptables -A OUTPUT -d 127.0.0.1 --dport 443 token=secret",
		},
		PolicySnapshot: req.Plan.Plan().PolicySnapshot,
		CapabilityLabels: []string{
			"default_deny",
			"domain_rules",
			"endpoint_rules",
			"private_range_rules",
			"metadata_endpoint",
			"proxy_listener",
			"process-handle-1234",
		},
		ReasonCode: reason,
	}
}

func TestRuleProofAdaptersRepresentFirewallAndRuntimeLifecycle(t *testing.T) {
	for _, tt := range []struct {
		name      string
		mechanism EnforcementMechanism
		adapter   func(*recordingRuleProofStepRunner) RuleLifecycleAdapter
		wantMode  ResultMode
	}{
		{
			name:      "firewall proof adapter",
			mechanism: EnforcementMechanismFirewall,
			adapter: func(runner *recordingRuleProofStepRunner) RuleLifecycleAdapter {
				return NewFirewallRuleProofAdapter(RuleProofAdapterOptions{
					AdapterID: "fake-firewall-proof",
					Enabled:   true,
					Runner:    runner,
				})
			},
			wantMode: ResultModeProxyFirewall,
		},
		{
			name:      "runtime proof adapter",
			mechanism: EnforcementMechanismRuntime,
			adapter: func(runner *recordingRuleProofStepRunner) RuleLifecycleAdapter {
				return NewRuntimeRuleProofAdapter(RuleProofAdapterOptions{
					AdapterID: "fake-runtime-proof",
					Enabled:   true,
					Runner:    runner,
				})
			},
			wantMode: ResultModeRuntime,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runner := &recordingRuleProofStepRunner{mechanism: tt.mechanism}
			lifecycle := RuleLifecycleRunner{Adapter: tt.adapter(runner)}
			plan := ruleProofPlan(tt.mechanism, FirewallIntentModeApply)

			applied, err := lifecycle.Apply(context.Background(), plan)
			if err != nil {
				t.Fatalf("Apply() error = %v, want nil", err)
			}
			cleaned, err := lifecycle.Cleanup(context.Background(), plan, applied.Active)
			if err != nil {
				t.Fatalf("Cleanup() error = %v, want nil", err)
			}

			assertRuleLifecycleCalls(t, runner.calls, []string{
				ruleOperationPlan,
				ruleOperationApply,
				ruleOperationActive,
				ruleOperationCleanup,
			})
			if len(runner.requests) != 4 {
				t.Fatalf("runner requests = %d, want 4", len(runner.requests))
			}
			for _, req := range runner.requests {
				received := req.Plan.Plan()
				if received.ID != "network-plan-rule-proof" ||
					received.Firewall == nil ||
					received.Firewall.Mechanism != tt.mechanism ||
					received.Firewall.Mode != FirewallIntentModeApply {
					t.Fatalf("runner received plan = %#v, want sanitized %s proof plan", received, tt.mechanism)
				}
				assertLifecyclePayloadSanitized(t, mustJSON(t, req), "rule proof request")
			}

			if applied.Status != LifecycleStatusActive ||
				applied.ReasonCode != LifecycleReasonActive ||
				applied.Active == nil ||
				applied.Active.Status != LifecycleStatusActive {
				t.Fatalf("Apply() = %#v, want active proof", applied)
			}
			if cleaned.Status != LifecycleStatusStopped ||
				cleaned.ReasonCode != LifecycleReasonStopped ||
				cleaned.Active == nil ||
				cleaned.Active.Status != LifecycleStatusStopped {
				t.Fatalf("Cleanup() = %#v, want stopped proof", cleaned)
			}
			assertRuleProofMechanismOnly(t, applied, tt.mechanism)
			assertRuleProofMechanismOnly(t, cleaned, tt.mechanism)
			assertRuleLifecycleHasCapabilities(t, applied, []string{
				"default_deny",
				"domain_rules",
				"endpoint_rules",
				"private_range_rules",
				"metadata_endpoint",
			})
			assertLifecyclePayloadSanitized(t, mustJSON(t, applied)+" "+mustJSON(t, cleaned), "rule proof lifecycle")

			listener := aggregationActiveListenerResult(plan)
			result := AggregateLiveEnforcementResult(plan, &listener, &applied)
			assertNoStrongAggregatedEnforcement(t, result)
			if result.ReasonCode != ResultReasonCapabilityMissing {
				t.Fatalf("plan-derived proof aggregate = %#v, want capability_missing", result)
			}
		})
	}
}

func TestRuleProofAdaptersNilDisabledDefaultBuildAndBestEffortNeverStrictReady(t *testing.T) {
	plan := ruleProofPlan(EnforcementMechanismFirewall, FirewallIntentModeApply)
	nilResult, err := RuleLifecycleRunner{}.Apply(context.Background(), plan)
	if err == nil {
		t.Fatal("nil adapter Apply() error = nil, want unsupported")
	}
	if nilResult.ReasonCode != LifecycleReasonAdapterUnsupported {
		t.Fatalf("nil adapter reason = %q, want unsupported", nilResult.ReasonCode)
	}
	assertRuleProofNotStrictReady(t, nilResult)

	disabledRunner := &recordingRuleProofStepRunner{mechanism: EnforcementMechanismFirewall}
	disabled := NewFirewallRuleProofAdapter(RuleProofAdapterOptions{
		AdapterID: "disabled-firewall-proof",
		Enabled:   false,
		Runner:    disabledRunner,
	})
	disabledResult, err := RuleLifecycleRunner{Adapter: disabled}.Apply(context.Background(), plan)
	if err == nil {
		t.Fatal("disabled adapter Apply() error = nil, want unsupported")
	}
	if len(disabledRunner.calls) != 0 {
		t.Fatalf("disabled adapter runner calls = %#v, want none", disabledRunner.calls)
	}
	if disabledResult.ReasonCode != LifecycleReasonAdapterUnsupported {
		t.Fatalf("disabled adapter reason = %q, want unsupported", disabledResult.ReasonCode)
	}
	assertRuleProofNotStrictReady(t, disabledResult)
	assertLifecyclePayloadSanitized(t, err.Error()+" "+mustJSON(t, disabledResult), "disabled adapter result")

	if !RuleProofLiveBuildTagEnabled() {
		defaultRunner := &recordingRuleProofStepRunner{mechanism: EnforcementMechanismFirewall}
		defaultBuild := NewLiveFirewallRuleProofAdapter(RuleProofLiveAdapterInput{
			AdapterID: "default-live-firewall-proof",
			Runner:    defaultRunner,
			Gate: RuleProofLiveGateInput{
				BuildTagEnabled: true,
				NetworkEnabled:  true,
				FirewallEnabled: true,
			},
		})
		defaultResult, err := RuleLifecycleRunner{Adapter: defaultBuild}.Apply(context.Background(), plan)
		if err == nil {
			t.Fatal("default live adapter Apply() error = nil, want unsupported")
		}
		if len(defaultRunner.calls) != 0 {
			t.Fatalf("default live adapter runner calls = %#v, want none", defaultRunner.calls)
		}
		if defaultResult.ReasonCode != LifecycleReasonAdapterUnsupported {
			t.Fatalf("default live adapter reason = %q, want unsupported", defaultResult.ReasonCode)
		}
		assertRuleProofNotStrictReady(t, defaultResult)
	}

	bestEffortRunner := &recordingRuleProofStepRunner{mechanism: EnforcementMechanismFirewall}
	bestEffortPlan := ruleProofPlan(EnforcementMechanismFirewall, FirewallIntentModePrepare)
	bestEffortRules, err := RuleLifecycleRunner{Adapter: NewFirewallRuleProofAdapter(RuleProofAdapterOptions{
		AdapterID: "fake-firewall-proof",
		Enabled:   true,
		Runner:    bestEffortRunner,
	})}.Apply(context.Background(), bestEffortPlan)
	if err != nil {
		t.Fatalf("best-effort Apply() error = %v, want nil", err)
	}
	aggregate := AggregateLiveEnforcementResult(bestEffortPlan, ptrProxyListenerLifecycleResult(aggregationActiveListenerResult(bestEffortPlan)), &bestEffortRules)
	if aggregate.Outcome != ResultOutcomeBestEffort || aggregate.EnforcementMode != ResultModeBestEffort {
		t.Fatalf("best-effort aggregate = %#v, want best_effort without strict readiness", aggregate)
	}
	assertNoStrongAggregatedEnforcement(t, aggregate)
}

func TestRuleProofAdapterErrorsAreSanitizedReasonAndWarningCodes(t *testing.T) {
	runner := &recordingRuleProofStepRunner{
		mechanism: EnforcementMechanismFirewall,
		failures: map[string]error{
			ruleOperationApply: errors.New("pfctl -f /Users/alice/pf.rules 127.0.0.1:443 token=secret"),
		},
	}
	lifecycle := RuleLifecycleRunner{Adapter: NewFirewallRuleProofAdapter(RuleProofAdapterOptions{
		AdapterID: "fake-firewall-proof",
		Enabled:   true,
		Runner:    runner,
	})}

	result, err := lifecycle.Apply(context.Background(), ruleProofPlan(EnforcementMechanismFirewall, FirewallIntentModeApply))
	if err == nil {
		t.Fatal("Apply() error = nil, want sanitized failure")
	}

	assertRuleLifecycleCalls(t, runner.calls, []string{
		ruleOperationPlan,
		ruleOperationApply,
		ruleOperationRollback,
	})
	if result.ReasonCode != LifecycleReasonAdapterFailed ||
		result.Active == nil ||
		result.Active.ReasonCode != LifecycleReasonAdapterFailed {
		t.Fatalf("result = %#v, want adapter_failed reason codes", result)
	}
	if !reflect.DeepEqual(result.WarningCodes, []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError}) {
		t.Fatalf("warnings = %#v, want sanitized adapter warning", result.WarningCodes)
	}
	assertRuleProofMechanismOnly(t, result, EnforcementMechanismFirewall)
	assertLifecyclePayloadSanitized(t, err.Error()+" "+mustJSON(t, result), "rule proof adapter failure")
	for _, required := range []string{
		string(LifecycleStatusFailed),
		string(LifecycleReasonAdapterFailed),
		string(LifecycleWarningSanitizedAdapterError),
	} {
		if !strings.Contains(err.Error()+" "+mustJSON(t, result), required) {
			t.Fatalf("sanitized failure missing marker %q in err=%q result=%s", required, err.Error(), mustJSON(t, result))
		}
	}
}

func TestRuleProofLiveGateSeamsRequireBuildTagAndEnvironmentMarkers(t *testing.T) {
	wantBuildTag := "network_enforcement_" + "live"
	wantEnv := "HAL_NETWORK_" + "ENFORCEMENT_LIVE"
	if RuleProofLiveBuildTagName != wantBuildTag ||
		RuleProofLiveEnvVarName != wantEnv ||
		RuleProofLiveFirewallEnvVarName != wantEnv+"_FIREWALL" ||
		RuleProofLiveRuntimeEnvVarName != wantEnv+"_RUNTIME" {
		t.Fatalf("live gate names changed: build=%q env=%q firewall=%q runtime=%q",
			RuleProofLiveBuildTagName,
			RuleProofLiveEnvVarName,
			RuleProofLiveFirewallEnvVarName,
			RuleProofLiveRuntimeEnvVarName,
		)
	}

	for _, tt := range []struct {
		name string
		gate RuleProofLiveGateInput
	}{
		{
			name: "missing build tag",
			gate: RuleProofLiveGateInput{NetworkEnabled: true, FirewallEnabled: true},
		},
		{
			name: "missing global environment opt-in",
			gate: RuleProofLiveGateInput{BuildTagEnabled: true, FirewallEnabled: true},
		},
		{
			name: "missing firewall environment opt-in",
			gate: RuleProofLiveGateInput{BuildTagEnabled: true, NetworkEnabled: true},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runner := &recordingRuleProofStepRunner{mechanism: EnforcementMechanismFirewall}
			adapter := NewGatedFirewallRuleProofAdapter(RuleProofLiveAdapterInput{
				AdapterID: "gated-firewall-proof",
				Runner:    runner,
				Gate:      tt.gate,
			})

			result, err := RuleLifecycleRunner{Adapter: adapter}.Apply(context.Background(), ruleProofPlan(EnforcementMechanismFirewall, FirewallIntentModeApply))
			if err == nil {
				t.Fatal("gated adapter Apply() error = nil, want unsupported")
			}
			if len(runner.calls) != 0 {
				t.Fatalf("gated adapter runner calls = %#v, want none", runner.calls)
			}
			if result.ReasonCode != LifecycleReasonAdapterUnsupported {
				t.Fatalf("gated adapter reason = %q, want unsupported", result.ReasonCode)
			}
			assertRuleProofNotStrictReady(t, result)
		})
	}

	runner := &recordingRuleProofStepRunner{mechanism: EnforcementMechanismFirewall}
	adapter := NewGatedFirewallRuleProofAdapter(RuleProofLiveAdapterInput{
		AdapterID: "gated-firewall-proof",
		Runner:    runner,
		Gate: RuleProofLiveGateInput{
			BuildTagEnabled: true,
			NetworkEnabled:  true,
			FirewallEnabled: true,
		},
	})
	result, err := RuleLifecycleRunner{Adapter: adapter}.Apply(context.Background(), ruleProofPlan(EnforcementMechanismFirewall, FirewallIntentModeApply))
	if err != nil {
		t.Fatalf("fully gated adapter Apply() error = %v, want nil", err)
	}
	if len(runner.calls) == 0 || result.Status != LifecycleStatusActive {
		t.Fatalf("fully gated adapter calls=%#v result=%#v, want active fakeable runner path", runner.calls, result)
	}
}

func ruleProofPlan(mechanism EnforcementMechanism, mode FirewallIntentMode) Plan {
	return BuildPlan(PlanRequest{
		ID:        "network-plan-rule-proof",
		Source:    PlanSourceRuntime,
		Operation: "prove_network_rules",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-rule-proof",
			Version:   "v1",
			Preset:    PolicyPresetDenyByDefault,
			RuleSetID: "rules-proof-01",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:            PolicyPresetDenyByDefault,
			RuleSetID:         "rules-proof-01",
			RuleIDs:           []string{"rule-proof-domain", "rule-proof-endpoint"},
			RuleCategories:    []AllowlistRuleCategory{AllowlistRuleCategoryDomain, AllowlistRuleCategoryEndpoint},
			PrivateNetwork:    PostureBlock,
			MetadataEndpoint:  PostureBlock,
			HTTP:              ProxyRoutingModeRouteViaProxy,
			HTTPS:             ProxyRoutingModeRouteViaProxy,
			ProxySessionID:    "proxy-session-rule-proof",
			ProxyMechanism:    EnforcementMechanismProxy,
			FirewallMode:      mode,
			FirewallMechanism: mechanism,
		},
	})
}

func assertRuleProofMechanismOnly(t *testing.T, result RuleLifecycleResult, mechanism EnforcementMechanism) {
	t.Helper()
	for label, metadata := range map[string]*RuleLifecycleMetadata{
		"requested": result.Requested,
		"active":    result.Active,
	} {
		if metadata == nil {
			continue
		}
		if !reflect.DeepEqual(metadata.Mechanisms, []EnforcementMechanism{mechanism}) {
			t.Fatalf("%s mechanisms = %#v, want %s only", label, metadata.Mechanisms, mechanism)
		}
		for _, capability := range metadata.CapabilityLabels {
			lower := strings.ToLower(capability)
			if strings.Contains(lower, "proxy") ||
				strings.Contains(lower, "listener") ||
				strings.Contains(lower, "process") {
				t.Fatalf("%s capability label %q exposes non-rule detail", label, capability)
			}
		}
	}
}

func assertRuleLifecycleHasCapabilities(t *testing.T, result RuleLifecycleResult, labels []string) {
	t.Helper()
	if result.Active == nil {
		t.Fatal("result.Active = nil, want active lifecycle metadata")
	}
	for _, label := range labels {
		if !stringSliceContains(result.Active.CapabilityLabels, label) {
			t.Fatalf("capability labels = %#v, want %q", result.Active.CapabilityLabels, label)
		}
	}
}

func assertRuleProofNotStrictReady(t *testing.T, result RuleLifecycleResult) {
	t.Helper()
	if result.Status == LifecycleStatusActive &&
		result.ReasonCode == LifecycleReasonActive &&
		result.Active != nil &&
		result.Active.Status == LifecycleStatusActive &&
		result.Active.ReasonCode == LifecycleReasonActive &&
		len(result.WarningCodes) == 0 &&
		len(result.Active.WarningCodes) == 0 {
		t.Fatalf("result unexpectedly satisfies strict rule readiness: %#v", result)
	}
}

func ptrProxyListenerLifecycleResult(result ProxyListenerLifecycleResult) *ProxyListenerLifecycleResult {
	return &result
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	return string(payload)
}
