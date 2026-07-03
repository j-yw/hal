package networkenforcement

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var _ ProxyListenerAdapter = (*recordingProxyListenerAdapter)(nil)

type recordingProxyListenerAdapter struct {
	calls       []string
	metadata    map[string]ProxyListenerLifecycleMetadata
	failures    map[string]error
	received    []Plan
	stopResults []ProxyListenerLifecycleMetadata
}

func (a *recordingProxyListenerAdapter) PrepareProxyListener(ctx context.Context, req ProxyListenerLifecycleRequest) (ProxyListenerLifecycleMetadata, error) {
	return a.step(ctx, req, "prepare_proxy")
}

func (a *recordingProxyListenerAdapter) StartProxyListener(ctx context.Context, req ProxyListenerLifecycleRequest) (ProxyListenerLifecycleMetadata, error) {
	return a.step(ctx, req, "start_proxy")
}

func (a *recordingProxyListenerAdapter) ActiveProxyListener(ctx context.Context, req ProxyListenerLifecycleRequest) (ProxyListenerLifecycleMetadata, error) {
	return a.step(ctx, req, "active_proxy")
}

func (a *recordingProxyListenerAdapter) StopProxyListener(ctx context.Context, req ProxyListenerLifecycleRequest) (ProxyListenerLifecycleMetadata, error) {
	meta, err := a.step(ctx, req, "stop_proxy")
	a.stopResults = append(a.stopResults, meta)
	return meta, err
}

func (a *recordingProxyListenerAdapter) step(_ context.Context, req ProxyListenerLifecycleRequest, op string) (ProxyListenerLifecycleMetadata, error) {
	a.calls = append(a.calls, op)
	a.received = append(a.received, req.Plan.Plan())
	if err := a.failures[op]; err != nil {
		return ProxyListenerLifecycleMetadata{
			ID:           "proxy-live-01",
			AdapterID:    "fake-listener",
			Status:       LifecycleStatusFailed,
			Mechanisms:   []EnforcementMechanism{EnforcementMechanismProxy, EnforcementMechanismFirewall},
			Operations:   []string{op, err.Error()},
			ReasonCode:   LifecycleReasonAdapterFailed,
			WarningCodes: []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError},
		}, err
	}
	if meta, ok := a.metadata[op]; ok {
		return meta, nil
	}
	return defaultRecordingListenerMetadata(op), nil
}

func TestProxyListenerLifecycleRunnerStartAndStopSequence(t *testing.T) {
	adapter := &recordingProxyListenerAdapter{}
	runner := ProxyListenerLifecycleRunner{Adapter: adapter}

	started, err := runner.Start(context.Background(), listenerLifecyclePlan())
	if err != nil {
		t.Fatalf("Start() error = %v, want nil", err)
	}
	stopped, err := runner.Stop(context.Background(), listenerLifecyclePlan(), started.Active)
	if err != nil {
		t.Fatalf("Stop() error = %v, want nil", err)
	}

	assertProxyListenerCalls(t, adapter.calls, []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"})
	if len(adapter.received) != 4 {
		t.Fatalf("adapter received %d plans, want 4", len(adapter.received))
	}
	for _, received := range adapter.received {
		if received.ID != "network-plan-listener" || received.Proxy == nil || received.Proxy.ProxySessionID != "proxy-session-listener" {
			t.Fatalf("adapter received plan = %#v, want sanitized listener plan", received)
		}
		if received.Firewall == nil || received.Firewall.Mode != FirewallIntentModeApply {
			t.Fatalf("adapter received firewall plan = %#v, want sanitized requested plan preserved for later phases", received.Firewall)
		}
	}

	if started.Requested == nil {
		t.Fatal("Start().Requested = nil, want requested proxy lifecycle metadata")
	}
	if started.Requested.Status != LifecycleStatusRequested {
		t.Fatalf("Start().Requested.Status = %q, want requested", started.Requested.Status)
	}
	if started.Active == nil {
		t.Fatal("Start().Active = nil, want active proxy lifecycle metadata")
	}
	if started.Active.Status != LifecycleStatusActive {
		t.Fatalf("Start().Active.Status = %q, want active", started.Active.Status)
	}
	if started.Status != LifecycleStatusActive || started.ReasonCode != LifecycleReasonActive {
		t.Fatalf("Start() status/reason = %q/%q, want active/active", started.Status, started.ReasonCode)
	}
	if stopped.Active == nil || stopped.Active.Status != LifecycleStatusStopped {
		t.Fatalf("Stop().Active = %#v, want stopped active metadata", stopped.Active)
	}
	if stopped.Status != LifecycleStatusStopped || stopped.ReasonCode != LifecycleReasonStopped {
		t.Fatalf("Stop() status/reason = %q/%q, want stopped/stopped", stopped.Status, stopped.ReasonCode)
	}
	assertProxyOnlyLifecycle(t, started)
	assertProxyOnlyLifecycle(t, stopped)
	mustMarshalPlanObject(t, started)
	mustMarshalPlanObject(t, stopped)
}

func TestProxyListenerLifecycleRunnerFailureStopsPartialListener(t *testing.T) {
	rawFailure := errors.New("listen tcp 127.0.0.1:8080 via /tmp/proxy.sock with token=secret")
	adapter := &recordingProxyListenerAdapter{
		failures: map[string]error{"active_proxy": rawFailure},
	}
	runner := ProxyListenerLifecycleRunner{Adapter: adapter}

	result, err := runner.Start(context.Background(), listenerLifecyclePlan())
	if err == nil {
		t.Fatal("Start() error = nil, want sanitized active failure")
	}

	assertProxyListenerCalls(t, adapter.calls, []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"})
	if result.Active == nil {
		t.Fatal("Start() failure Active = nil, want failed lifecycle metadata")
	}
	if result.Status != LifecycleStatusFailed || result.Active.Status != LifecycleStatusFailed {
		t.Fatalf("failure status = %q active=%#v, want failed", result.Status, result.Active)
	}
	if result.ReasonCode != LifecycleReasonActiveCheckFailed || result.Active.ReasonCode != LifecycleReasonActiveCheckFailed {
		t.Fatalf("failure reason = %q active=%q, want active_check_failed", result.ReasonCode, result.Active.ReasonCode)
	}
	if !reflect.DeepEqual(result.WarningCodes, []LifecycleWarningCode{LifecycleWarningSanitizedAdapterError}) {
		t.Fatalf("failure warnings = %#v, want sanitized adapter warning", result.WarningCodes)
	}
	assertPlanStringArrayFromStrings(t, result.Active.Operations, []string{"active_proxy"})
	assertProxyOnlyLifecycle(t, result)
	assertSanitizedLifecycleFailure(t, err, result)
}

func TestProxyListenerLifecycleRunnerReportsCleanupFailureAsSanitizedWarning(t *testing.T) {
	adapter := &recordingProxyListenerAdapter{
		failures: map[string]error{
			"active_proxy": errors.New("connect api.internal.example.com:443 with Authorization: Bearer ghp_secret"),
			"stop_proxy":   errors.New("close /tmp/proxy.sock for listener 127.0.0.1:8080"),
		},
	}
	runner := ProxyListenerLifecycleRunner{Adapter: adapter}

	result, err := runner.Start(context.Background(), listenerLifecyclePlan())
	if err == nil {
		t.Fatal("Start() error = nil, want sanitized active failure")
	}

	assertProxyListenerCalls(t, adapter.calls, []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"})
	if !reflect.DeepEqual(result.WarningCodes, []LifecycleWarningCode{
		LifecycleWarningSanitizedAdapterError,
		LifecycleWarningCleanupFailed,
	}) {
		t.Fatalf("failure warnings = %#v, want sanitized adapter and cleanup warnings", result.WarningCodes)
	}
	if result.Active == nil || !reflect.DeepEqual(result.Active.WarningCodes, []LifecycleWarningCode{
		LifecycleWarningSanitizedAdapterError,
		LifecycleWarningCleanupFailed,
	}) {
		t.Fatalf("active warnings = %#v, want sanitized cleanup warning", result.Active)
	}
	assertSanitizedLifecycleFailure(t, err, result)
}

func TestProxyListenerLifecycleRunnerStopFailureIsWarningOnly(t *testing.T) {
	adapter := &recordingProxyListenerAdapter{
		failures: map[string]error{"stop_proxy": errors.New("close socket /tmp/proxy.sock at 127.0.0.1:8080")},
	}
	runner := ProxyListenerLifecycleRunner{Adapter: adapter}

	started, err := runner.Start(context.Background(), listenerLifecyclePlan())
	if err != nil {
		t.Fatalf("Start() error = %v, want nil", err)
	}
	stopped, err := runner.Stop(context.Background(), listenerLifecyclePlan(), started.Active)
	if err != nil {
		t.Fatalf("Stop() error = %v, want nil because cleanup failure is warning metadata", err)
	}

	assertProxyListenerCalls(t, adapter.calls, []string{"prepare_proxy", "start_proxy", "active_proxy", "stop_proxy"})
	if stopped.Status != LifecycleStatusStopped {
		t.Fatalf("Stop() status = %q, want stopped", stopped.Status)
	}
	if !reflect.DeepEqual(stopped.WarningCodes, []LifecycleWarningCode{
		LifecycleWarningCleanupFailed,
		LifecycleWarningSanitizedAdapterError,
	}) {
		t.Fatalf("Stop() warnings = %#v, want cleanup and sanitized adapter warnings", stopped.WarningCodes)
	}
	assertProxyOnlyLifecycle(t, stopped)
	payload, marshalErr := json.Marshal(stopped)
	if marshalErr != nil {
		t.Fatalf("Marshal(Stop result) error: %v", marshalErr)
	}
	assertLifecyclePayloadSanitized(t, string(payload), "stop failure result")
}

func TestProxyListenerLifecycleRunnerPrepareFailureDoesNotStartOrStop(t *testing.T) {
	adapter := &recordingProxyListenerAdapter{
		failures: map[string]error{"prepare_proxy": errors.New("bind listener localhost:8080 with secret=token")},
	}
	runner := ProxyListenerLifecycleRunner{Adapter: adapter}

	result, err := runner.Start(context.Background(), listenerLifecyclePlan())
	if err == nil {
		t.Fatal("Start() error = nil, want sanitized prepare failure")
	}

	assertProxyListenerCalls(t, adapter.calls, []string{"prepare_proxy"})
	if result.Active == nil || result.Active.Status != LifecycleStatusFailed {
		t.Fatalf("prepare failure active = %#v, want failed metadata", result.Active)
	}
	if result.ReasonCode != LifecycleReasonAdapterFailed {
		t.Fatalf("prepare failure reason = %q, want adapter_failed", result.ReasonCode)
	}
	assertSanitizedLifecycleFailure(t, err, result)
}

func listenerLifecyclePlan() Plan {
	return BuildPlan(PlanRequest{
		ID:        "network-plan-listener",
		Source:    PlanSourceRuntime,
		Operation: "prepare_network",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-listener",
			Version:   "v1",
			Preset:    PolicyPresetDenyByDefault,
			RuleSetID: "rules-listener",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:            PolicyPresetDenyByDefault,
			RuleSetID:         "rules-listener",
			HTTP:              ProxyRoutingModeRouteViaProxy,
			HTTPS:             ProxyRoutingModeRouteViaProxy,
			ProxySessionID:    "proxy-session-listener",
			ProxyMechanism:    EnforcementMechanismProxy,
			FirewallMode:      FirewallIntentModeApply,
			FirewallMechanism: EnforcementMechanismFirewall,
		},
	})
}

func defaultRecordingListenerMetadata(op string) ProxyListenerLifecycleMetadata {
	status := LifecycleStatusPrepared
	reason := LifecycleReasonPrepared
	switch op {
	case "start_proxy":
		status = LifecycleStatusStarting
		reason = LifecycleReasonStarted
	case "active_proxy":
		status = LifecycleStatusActive
		reason = LifecycleReasonActive
	case "stop_proxy":
		status = LifecycleStatusStopped
		reason = LifecycleReasonStopped
	}
	return ProxyListenerLifecycleMetadata{
		ID:               "proxy-live-01",
		PlanID:           "network-plan-listener",
		AdapterID:        "fake-listener",
		Status:           status,
		Mechanisms:       []EnforcementMechanism{EnforcementMechanismProxy, EnforcementMechanismFirewall},
		Operations:       []string{op},
		PolicySnapshot:   &PolicySnapshotIdentity{ID: "policy-listener", Preset: PolicyPresetDenyByDefault},
		CapabilityLabels: []string{"proxy_listener_active", "runtime_firewall"},
		ReasonCode:       reason,
	}
}

func assertProxyListenerCalls(t *testing.T, got []string, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("adapter calls = %#v, want %#v", got, want)
	}
}

func assertProxyOnlyLifecycle(t *testing.T, result ProxyListenerLifecycleResult) {
	t.Helper()
	for label, metadata := range map[string]*ProxyListenerLifecycleMetadata{
		"requested": result.Requested,
		"active":    result.Active,
	} {
		if metadata == nil {
			continue
		}
		if !reflect.DeepEqual(metadata.Mechanisms, []EnforcementMechanism{EnforcementMechanismProxy}) {
			t.Fatalf("%s mechanisms = %#v, want proxy only", label, metadata.Mechanisms)
		}
		for _, capability := range metadata.CapabilityLabels {
			lower := strings.ToLower(capability)
			if strings.Contains(lower, "firewall") || strings.Contains(lower, "runtime") {
				t.Fatalf("%s capability label %q implies non-listener enforcement", label, capability)
			}
		}
	}
}

func assertSanitizedLifecycleFailure(t *testing.T, err error, result ProxyListenerLifecycleResult) {
	t.Helper()
	payload, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		t.Fatalf("Marshal(lifecycle result) error: %v", marshalErr)
	}
	assertLifecyclePayloadSanitized(t, err.Error()+" "+string(payload), "failure surfaces")
	for _, required := range []string{
		string(LifecycleStatusFailed),
		string(LifecycleReasonAdapterFailed),
		string(LifecycleWarningSanitizedAdapterError),
	} {
		if !strings.Contains(err.Error()+" "+string(payload), required) {
			t.Fatalf("failure surfaces missing safe marker %q in err=%q payload=%s", required, err.Error(), payload)
		}
	}
}

func assertLifecyclePayloadSanitized(t *testing.T, value, label string) {
	t.Helper()
	lower := strings.ToLower(value)
	for _, forbidden := range forbiddenPlanPayloadFragments() {
		if strings.Contains(lower, strings.ToLower(forbidden)) {
			t.Fatalf("%s leaked forbidden fragment %q in %q", label, forbidden, value)
		}
	}
}
