package networkenforcement

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestPolicyProxyLifecycleProofResultProducesProxyOnlyCapability(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	proof := NewPolicyProxyLifecycleProof(NewSanitizedPlan(plan), PolicyProxyLifecycleOperationActiveCheck, LifecycleStatusActive, LifecycleReasonActive)
	proof.AdapterID = "fake-policy-proxy-adapter"
	proof.CapabilityLabels = []string{"proxy_active", "firewall_rule", "runtime_socket"}

	result := ResultFromPolicyProxyLifecycleProof(plan, proof)

	assertProxyOnlyEnforcementResult(t, result)
	if result.Capability == nil || !result.Capability.SupportsDomainRules || !result.Capability.SupportsEndpointRules {
		t.Fatalf("Capability = %#v, want proxy allowlist rule support from plan", result.Capability)
	}
	if result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("SupportsDefaultDenyPosture = true, want missing firewall/runtime rule proof to block full deny-by-default readiness")
	}
	assertPolicyProxyAdapterPayloadSanitized(t, result)
}

func TestPolicyProxyEnforcementAdapterRunsLifecycleThroughListenerBoundary(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	listener := aggregationListenerAdapter(plan, nil)
	adapter := NewPolicyProxyEnforcementAdapter(listener)

	result := RunAdapter(context.Background(), adapter, plan)

	assertProxyListenerCalls(t, listener.calls, []string{"prepare_proxy", "start_proxy", "active_proxy"})
	assertProxyOnlyEnforcementResult(t, result)
	if result.AdapterID != "fake-aggregation-listener" {
		t.Fatalf("AdapterID = %q, want active listener proof adapter id", result.AdapterID)
	}
	assertPolicyProxyAdapterPayloadSanitized(t, result)
}

func TestPolicyProxyEnforcementAdapterFailsClosedForMissingAdapter(t *testing.T) {
	result := RunAdapter(context.Background(), NewPolicyProxyEnforcementAdapter(nil), aggregationPlan(FirewallIntentModeApply))

	if result.Outcome != ResultOutcomeUnsupported {
		t.Fatalf("Outcome = %q, want unsupported", result.Outcome)
	}
	if result.ReasonCode != ResultReasonAdapterUnsupported {
		t.Fatalf("ReasonCode = %q, want adapter_unsupported", result.ReasonCode)
	}
	assertPolicyProxyAdapterFailsClosed(t, result)
	if resultWarningCodesContain(result.WarningCodes, ResultWarningPartialEnforcement) {
		t.Fatalf("WarningCodes = %#v, want no partial lifecycle warning when no adapter ran", result.WarningCodes)
	}
	if !resultWarningCodesContain(result.WarningCodes, ResultWarningSanitizedAdapterError) {
		t.Fatalf("WarningCodes = %#v, want sanitized adapter warning", result.WarningCodes)
	}
	assertPolicyProxyAdapterPayloadSanitized(t, result)
}

func TestPolicyProxyEnforcementAdapterFailsClosedForActiveCheckFailure(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	listener := aggregationListenerAdapter(plan, map[string]error{
		"active_proxy": errors.New("connect 127.0.0.1:8080 through /tmp/proxy.sock token=secret"),
	})

	result := RunAdapter(context.Background(), NewPolicyProxyEnforcementAdapter(listener), plan)

	assertProxyListenerCalls(t, listener.calls, []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"})
	if result.Outcome != ResultOutcomeFailure {
		t.Fatalf("Outcome = %q, want failure", result.Outcome)
	}
	if result.ReasonCode != ResultReasonAdapterFailed {
		t.Fatalf("ReasonCode = %q, want adapter_failed", result.ReasonCode)
	}
	assertPolicyProxyAdapterFailsClosed(t, result)
	if !resultWarningCodesContain(result.WarningCodes, ResultWarningPartialEnforcement) ||
		!resultWarningCodesContain(result.WarningCodes, ResultWarningSanitizedAdapterError) {
		t.Fatalf("WarningCodes = %#v, want partial and sanitized adapter warnings", result.WarningCodes)
	}
	assertPolicyProxyAdapterPayloadSanitized(t, result)
}

func TestPolicyProxyEnforcementAdapterCleanupWarningClearsCapability(t *testing.T) {
	plan := aggregationPlan(FirewallIntentModeApply)
	listener := aggregationListenerAdapter(plan, map[string]error{
		"active_proxy": errors.New("active check leaked api.internal.example.com:443"),
		"stop_proxy":   errors.New("close /tmp/proxy.sock bound to 127.0.0.1:8080"),
	})

	result := RunAdapter(context.Background(), NewPolicyProxyEnforcementAdapter(listener), plan)

	assertProxyListenerCalls(t, listener.calls, []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"})
	if result.Outcome != ResultOutcomeFailure {
		t.Fatalf("Outcome = %q, want failure", result.Outcome)
	}
	assertPolicyProxyAdapterFailsClosed(t, result)
	if !resultWarningCodesContain(result.WarningCodes, ResultWarningPartialEnforcement) ||
		!resultWarningCodesContain(result.WarningCodes, ResultWarningSanitizedAdapterError) {
		t.Fatalf("WarningCodes = %#v, want cleanup to remain warning-only and fail closed", result.WarningCodes)
	}
	assertPolicyProxyAdapterPayloadSanitized(t, result)
}

func assertProxyOnlyEnforcementResult(t *testing.T, result Result) {
	t.Helper()
	if result.Outcome != ResultOutcomeSuccess {
		t.Fatalf("Outcome = %q, want success in %#v", result.Outcome, result)
	}
	if result.EnforcementMode != ResultModeProxy {
		t.Fatalf("EnforcementMode = %q, want proxy in %#v", result.EnforcementMode, result)
	}
	if !reflect.DeepEqual(result.Mechanisms, []EnforcementMechanism{EnforcementMechanismProxy}) {
		t.Fatalf("Mechanisms = %#v, want proxy only", result.Mechanisms)
	}
	if result.Capability == nil || !result.Capability.Supported {
		t.Fatalf("Capability = %#v, want supported proxy capability", result.Capability)
	}
	if !reflect.DeepEqual(result.Capability.Modes, []ResultMode{ResultModeProxy}) {
		t.Fatalf("Capability.Modes = %#v, want proxy only", result.Capability.Modes)
	}
	for _, mode := range result.Capability.Modes {
		if mode == ResultModeProxyFirewall {
			t.Fatalf("Capability.Modes = %#v, want no proxy_firewall from proxy-only proof", result.Capability.Modes)
		}
	}
}

func assertPolicyProxyAdapterFailsClosed(t *testing.T, result Result) {
	t.Helper()
	if result.EnforcementMode != ResultModeNone {
		t.Fatalf("EnforcementMode = %q, want fail-closed none in %#v", result.EnforcementMode, result)
	}
	if result.Capability != nil {
		t.Fatalf("Capability = %#v, want no enforcing capability", result.Capability)
	}
}

func assertPolicyProxyAdapterPayloadSanitized(t *testing.T, result Result) {
	t.Helper()
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(Result) error: %v", err)
	}
	assertLifecyclePayloadSanitized(t, string(payload), "policy proxy adapter result")
}
