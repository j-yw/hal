package microvm

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestGatedNetworkEnforcementPlanningRoutesThroughRuntimeContracts(t *testing.T) {
	listener := &recordingMicroVMLiveProxyListener{}
	rules := &recordingMicroVMLiveRuleProof{mechanism: networkenforcement.EnforcementMechanismFirewall}
	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		NetworkEnforcement: NewGatedNetworkEnforcementPlanning(NetworkEnforcementLiveOptions{
			Request:       microVMNetworkEnforcementTestPlanRequest(),
			ProxyListener: listener,
			RuleRunner:    rules,
			RuleGate: networkenforcement.RuleProofLiveGateInput{
				BuildTagEnabled: true,
				NetworkEnabled:  true,
				FirewallEnabled: true,
			},
		}),
	})

	assertMicroVMLiveProxyListenerCalls(t, listener.calls, []string{"prepare_proxy", "start_proxy", "active_proxy"})
	assertMicroVMLiveRuleProofCalls(t, rules.calls, []string{"plan_rules", "apply_rules", "active_rules"})
	metadata := driver.Metadata().NetworkEnforcement
	if metadata == nil || metadata.Plan == nil || metadata.Orchestration == nil || metadata.Result == nil {
		t.Fatalf("NetworkEnforcement = %#v, want plan, lifecycle orchestration, and result", metadata)
	}
	if metadata.Result.AdapterID != "live-enforcement-aggregation" ||
		metadata.Result.Outcome != string(networkenforcement.ResultOutcomeSuccess) ||
		metadata.Result.EnforcementMode != string(networkenforcement.ResultModeProxyFirewall) ||
		metadata.Result.Capability == nil ||
		!metadata.Result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("NetworkEnforcement.Result = %#v, want networkenforcement dual-proof result", metadata.Result)
	}
	if metadata.Orchestration.Status != string(networkenforcement.LifecycleStatusActive) ||
		metadata.Orchestration.Proxy == nil ||
		metadata.Orchestration.Proxy.Status != string(networkenforcement.LifecycleStatusActive) ||
		len(metadata.Orchestration.Rules) != 1 ||
		metadata.Orchestration.Rules[0].Status != string(networkenforcement.LifecycleStatusActive) {
		t.Fatalf("NetworkEnforcement.Orchestration = %#v, want active proxy plus active rule proof", metadata.Orchestration)
	}
	assertMicroVMLiveNetworkMetadataSanitized(t, metadata)
}

func TestGatedNetworkEnforcementPlanningMissingGateDoesNotInvokeLiveAdapters(t *testing.T) {
	for _, tt := range []struct {
		name string
		gate networkenforcement.RuleProofLiveGateInput
	}{
		{
			name: "missing build tag",
			gate: networkenforcement.RuleProofLiveGateInput{NetworkEnabled: true, FirewallEnabled: true},
		},
		{
			name: "missing network environment gate",
			gate: networkenforcement.RuleProofLiveGateInput{BuildTagEnabled: true, FirewallEnabled: true},
		},
		{
			name: "missing firewall environment gate",
			gate: networkenforcement.RuleProofLiveGateInput{BuildTagEnabled: true, NetworkEnabled: true},
		},
		{
			name: "missing live rule runner",
			gate: networkenforcement.RuleProofLiveGateInput{BuildTagEnabled: true, NetworkEnabled: true, FirewallEnabled: true},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listener := &recordingMicroVMLiveProxyListener{}
			var runner networkenforcement.RuleProofStepRunner = &recordingMicroVMLiveRuleProof{mechanism: networkenforcement.EnforcementMechanismFirewall}
			if tt.name == "missing live rule runner" {
				runner = nil
			}
			driver := NewDriver(DriverOptions{
				CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
				NetworkEnforcement: NewGatedNetworkEnforcementPlanning(NetworkEnforcementLiveOptions{
					Request:       microVMNetworkEnforcementTestPlanRequest(),
					ProxyListener: listener,
					RuleRunner:    runner,
					RuleGate:      tt.gate,
				}),
			})

			if len(listener.calls) != 0 {
				t.Fatalf("proxy listener calls = %#v, want none while live gate is incomplete", listener.calls)
			}
			metadata := driver.Metadata().NetworkEnforcement
			assertMicroVMNetworkEnforcementNotStrictReady(t, metadata)
			if metadata == nil || metadata.Result == nil ||
				metadata.Result.Outcome != string(networkenforcement.ResultOutcomeUnsupported) ||
				metadata.Result.EnforcementMode != string(networkenforcement.ResultModeNone) ||
				metadata.Result.Capability != nil {
				t.Fatalf("NetworkEnforcement = %#v, want sanitized unsupported metadata", metadata)
			}
			assertMicroVMLiveNetworkMetadataSanitized(t, metadata)
		})
	}
}

func TestGatedNetworkEnforcementPlanningDisabledRuleAdapterDoesNotSatisfyStrictReadiness(t *testing.T) {
	listener := &recordingMicroVMLiveProxyListener{}
	rules := &recordingMicroVMLiveRuleProof{mechanism: networkenforcement.EnforcementMechanismFirewall}
	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		NetworkEnforcement: NewGatedNetworkEnforcementPlanning(NetworkEnforcementLiveOptions{
			Request:       microVMNetworkEnforcementTestPlanRequest(),
			ProxyListener: listener,
			RuleRunner:    rules,
			RuleGate: networkenforcement.RuleProofLiveGateInput{
				BuildTagEnabled: true,
				NetworkEnabled:  true,
			},
		}),
	})

	if len(listener.calls) != 0 || len(rules.calls) != 0 {
		t.Fatalf("live calls = proxy:%#v rules:%#v, want none for disabled rule adapter", listener.calls, rules.calls)
	}
	metadata := driver.Metadata().NetworkEnforcement
	assertMicroVMNetworkEnforcementNotStrictReady(t, metadata)
	if metadata == nil || metadata.Result == nil ||
		metadata.Result.Outcome != string(networkenforcement.ResultOutcomeUnsupported) ||
		metadata.Result.EnforcementMode != string(networkenforcement.ResultModeNone) {
		t.Fatalf("NetworkEnforcement = %#v, want unsupported none-mode metadata", metadata)
	}
	assertMicroVMLiveNetworkMetadataSanitized(t, metadata)
}

func TestDefaultMicroVMNetworkEnforcementStatusPathDoesNotUseLiveHostCapabilities(t *testing.T) {
	listener := &recordingMicroVMLiveProxyListener{}
	rules := &recordingMicroVMLiveRuleProof{mechanism: networkenforcement.EnforcementMechanismFirewall}
	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
	})

	for i := 0; i < 2; i++ {
		metadata := driver.Metadata()
		if metadata.NetworkEnforcement != nil {
			t.Fatalf("Metadata().NetworkEnforcement = %#v, want nil without explicit planning", metadata.NetworkEnforcement)
		}
	}
	if len(listener.calls) != 0 || len(rules.calls) != 0 {
		t.Fatalf("default status path live calls = proxy:%#v rules:%#v, want none", listener.calls, rules.calls)
	}
}

type recordingMicroVMLiveProxyListener struct {
	calls []string
}

func (listener *recordingMicroVMLiveProxyListener) PrepareProxyListener(_ context.Context, req networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	listener.calls = append(listener.calls, "prepare_proxy")
	return listener.metadata(req, networkenforcement.LifecycleStatusPrepared, networkenforcement.LifecycleReasonPrepared), nil
}

func (listener *recordingMicroVMLiveProxyListener) StartProxyListener(_ context.Context, req networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	listener.calls = append(listener.calls, "start_proxy")
	return listener.metadata(req, networkenforcement.LifecycleStatusStarting, networkenforcement.LifecycleReasonStarted), nil
}

func (listener *recordingMicroVMLiveProxyListener) ActiveProxyListener(_ context.Context, req networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	listener.calls = append(listener.calls, "active_proxy")
	return listener.metadata(req, networkenforcement.LifecycleStatusActive, networkenforcement.LifecycleReasonActive), nil
}

func (listener *recordingMicroVMLiveProxyListener) StopProxyListener(_ context.Context, req networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	listener.calls = append(listener.calls, "stop_proxy")
	return listener.metadata(req, networkenforcement.LifecycleStatusStopped, networkenforcement.LifecycleReasonStopped), nil
}

func (listener *recordingMicroVMLiveProxyListener) metadata(req networkenforcement.ProxyListenerLifecycleRequest, status networkenforcement.LifecycleStatus, reason networkenforcement.LifecycleReasonCode) networkenforcement.ProxyListenerLifecycleMetadata {
	plan := req.Plan.Plan()
	return networkenforcement.ProxyListenerLifecycleMetadata{
		ID:             "microvm-live-proxy-proof",
		PlanID:         plan.ID,
		AdapterID:      "microvm-live-proxy-listener",
		Status:         status,
		Mechanisms:     []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismProxy},
		Operations:     []string{listener.calls[len(listener.calls)-1], "listen 127.0.0.1:8080", "/tmp/proxy.sock", "token=secret"},
		PolicySnapshot: plan.PolicySnapshot,
		ReasonCode:     reason,
	}
}

type recordingMicroVMLiveRuleProof struct {
	mechanism networkenforcement.EnforcementMechanism
	calls     []string
}

func (rules *recordingMicroVMLiveRuleProof) RunRuleProofStep(_ context.Context, req networkenforcement.RuleProofStepRequest) (networkenforcement.RuleLifecycleMetadata, error) {
	rules.calls = append(rules.calls, req.Operation)
	status := networkenforcement.LifecycleStatusPlanned
	reason := networkenforcement.LifecycleReasonPrepared
	switch req.Operation {
	case "apply_rules":
		status = networkenforcement.LifecycleStatusApplying
		reason = networkenforcement.LifecycleReasonApplied
	case "active_rules":
		status = networkenforcement.LifecycleStatusActive
		reason = networkenforcement.LifecycleReasonActive
	case "rollback_rules":
		status = networkenforcement.LifecycleStatusRollingBack
		reason = networkenforcement.LifecycleReasonRollbackFailed
	case "cleanup_rules":
		status = networkenforcement.LifecycleStatusStopped
		reason = networkenforcement.LifecycleReasonStopped
	}
	mechanism := rules.mechanism
	if mechanism == "" {
		mechanism = req.Mechanism
	}
	plan := req.Plan.Plan()
	return networkenforcement.RuleLifecycleMetadata{
		ID:             "microvm-live-rules-proof",
		PlanID:         plan.ID,
		AdapterID:      "microvm-live-rules",
		Status:         status,
		Mechanisms:     []networkenforcement.EnforcementMechanism{mechanism},
		Operations:     []string{req.Operation, "iptables -A OUTPUT -d 127.0.0.1 --dport 443 token=secret"},
		PolicySnapshot: plan.PolicySnapshot,
		CapabilityLabels: []string{
			"default_deny",
			"domain_rules",
			"private_range_rules",
			"metadata_endpoint",
			"process-handle-1234",
		},
		ReasonCode: reason,
	}, nil
}

func assertMicroVMLiveProxyListenerCalls(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("proxy listener calls = %#v, want %#v", got, want)
	}
}

func assertMicroVMLiveRuleProofCalls(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rule proof calls = %#v, want %#v", got, want)
	}
}

func assertMicroVMNetworkEnforcementNotStrictReady(t *testing.T, metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) {
	t.Helper()
	if metadata == nil || metadata.Result == nil || metadata.Orchestration == nil {
		return
	}
	result := metadata.Result
	if result.Outcome != string(networkenforcement.ResultOutcomeSuccess) ||
		result.EnforcementMode != string(networkenforcement.ResultModeProxyFirewall) ||
		result.Capability == nil ||
		!result.Capability.Supported ||
		!result.Capability.SupportsDefaultDenyPosture {
		return
	}
	if metadata.Orchestration.Status != string(networkenforcement.LifecycleStatusActive) ||
		metadata.Orchestration.Proxy == nil ||
		metadata.Orchestration.Proxy.Status != string(networkenforcement.LifecycleStatusActive) {
		return
	}
	for _, rule := range metadata.Orchestration.Rules {
		if rule.Status == string(networkenforcement.LifecycleStatusActive) &&
			reflect.DeepEqual(rule.Mechanisms, []string{string(networkenforcement.EnforcementMechanismFirewall)}) {
			t.Fatalf("network enforcement unexpectedly satisfies strict readiness: %#v", metadata)
		}
	}
}

func assertMicroVMLiveNetworkMetadataSanitized(t *testing.T, metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) {
	t.Helper()
	payload, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(NetworkEnforcement) error = %v", err)
	}
	publicText := strings.ToLower(string(payload))
	for _, unsafe := range []string{
		"127.0.0.1",
		"8080",
		"443",
		"/tmp",
		".sock",
		"iptables",
		"process-handle",
		"token",
		"secret",
		"://",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("network enforcement metadata leaked unsafe fragment %q in %s", unsafe, payload)
		}
	}
}
