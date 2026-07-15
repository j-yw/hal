package firecrackerhost

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestNewLiveDriverCanUseMicroVMGatedNetworkEnforcementWiring(t *testing.T) {
	listener := &firecrackerHostRecordingProxyListener{}
	rules := &firecrackerHostRecordingRuleProof{mechanism: networkenforcement.EnforcementMechanismFirewall}
	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         firecrackerHostShortSocketTestRoot(t),
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    &fakeHostProcessRunner{},
		BootAcceptancePoller: &fakeBootAcceptancePoller{},
		NetworkEnforcement: microvm.NewGatedNetworkEnforcementPlanning(microvm.NetworkEnforcementLiveOptions{
			Request:       firecrackerHostDualProofNetworkEnforcementPlanRequest(),
			ProxyListener: listener,
			RuleRunner:    rules,
			RuleGate: networkenforcement.RuleProofLiveGateInput{
				BuildTagEnabled: true,
				NetworkEnabled:  true,
				FirewallEnabled: true,
			},
		}),
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	if len(listener.calls) != 3 || len(rules.calls) != 3 {
		t.Fatalf("network enforcement calls = proxy:%#v rules:%#v, want planner to invoke fakeable networkenforcement contracts", listener.calls, rules.calls)
	}
	metadata := driver.Metadata().NetworkEnforcement
	if metadata == nil || metadata.Result == nil || metadata.Orchestration == nil {
		t.Fatalf("NetworkEnforcement = %#v, want result and orchestration metadata", metadata)
	}
	if metadata.Result.AdapterID != "live-enforcement-aggregation" ||
		metadata.Result.EnforcementMode != string(networkenforcement.ResultModeProxyFirewall) {
		t.Fatalf("NetworkEnforcement.Result = %#v, want networkenforcement aggregated proxy_firewall result", metadata.Result)
	}
	if metadata.Orchestration.Proxy == nil || len(metadata.Orchestration.Rules) != 1 {
		t.Fatalf("NetworkEnforcement.Orchestration = %#v, want proxy plus rule proof lifecycle", metadata.Orchestration)
	}
}

func TestNewLiveDriverNetworkEnforcementMissingGateDoesNotStartProxyOrRules(t *testing.T) {
	listener := &firecrackerHostRecordingProxyListener{}
	rules := &firecrackerHostRecordingRuleProof{mechanism: networkenforcement.EnforcementMechanismFirewall}
	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         firecrackerHostShortSocketTestRoot(t),
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    &fakeHostProcessRunner{},
		BootAcceptancePoller: &fakeBootAcceptancePoller{},
		NetworkEnforcement: microvm.NewGatedNetworkEnforcementPlanning(microvm.NetworkEnforcementLiveOptions{
			Request:       firecrackerHostDualProofNetworkEnforcementPlanRequest(),
			ProxyListener: listener,
			RuleRunner:    rules,
			RuleGate: networkenforcement.RuleProofLiveGateInput{
				BuildTagEnabled: true,
				NetworkEnabled:  true,
			},
		}),
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	if len(listener.calls) != 0 || len(rules.calls) != 0 {
		t.Fatalf("network enforcement calls = proxy:%#v rules:%#v, want none with incomplete live gate", listener.calls, rules.calls)
	}
	metadata := driver.Metadata().NetworkEnforcement
	if metadata == nil || metadata.Result == nil ||
		metadata.Result.Outcome != string(networkenforcement.ResultOutcomeUnsupported) ||
		metadata.Result.EnforcementMode != string(networkenforcement.ResultModeNone) ||
		metadata.Result.Capability != nil {
		t.Fatalf("NetworkEnforcement = %#v, want sanitized unsupported metadata", metadata)
	}
}

func TestNewLiveDriverNetworkEnforcementLiveOptionUsesBuildTagGate(t *testing.T) {
	listener := &firecrackerHostRecordingProxyListener{}
	rules := &firecrackerHostRecordingRuleProof{mechanism: networkenforcement.EnforcementMechanismFirewall}
	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         firecrackerHostShortSocketTestRoot(t),
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    &fakeHostProcessRunner{},
		BootAcceptancePoller: &fakeBootAcceptancePoller{},
		NetworkEnforcementLive: &microvm.NetworkEnforcementLiveOptions{
			Request:       firecrackerHostDualProofNetworkEnforcementPlanRequest(),
			ProxyListener: listener,
			RuleRunner:    rules,
			RuleGate: networkenforcement.RuleProofLiveGateInput{
				NetworkEnabled:  true,
				FirewallEnabled: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	metadata := driver.Metadata().NetworkEnforcement
	if networkenforcement.RuleProofLiveBuildTagEnabled() {
		if len(listener.calls) != 3 || len(rules.calls) != 3 {
			t.Fatalf("live-tag network calls = proxy:%#v rules:%#v, want fakeable adapter path invoked", listener.calls, rules.calls)
		}
		if metadata == nil || metadata.Result == nil || metadata.Result.EnforcementMode != string(networkenforcement.ResultModeProxyFirewall) {
			t.Fatalf("NetworkEnforcement = %#v, want proxy_firewall metadata with live build tag and env gates", metadata)
		}
		return
	}
	if len(listener.calls) != 0 || len(rules.calls) != 0 {
		t.Fatalf("default-build network calls = proxy:%#v rules:%#v, want none without live build tag", listener.calls, rules.calls)
	}
	if metadata == nil || metadata.Result == nil ||
		metadata.Result.Outcome != string(networkenforcement.ResultOutcomeUnsupported) ||
		metadata.Result.EnforcementMode != string(networkenforcement.ResultModeNone) {
		t.Fatalf("NetworkEnforcement = %#v, want unsupported metadata without live build tag", metadata)
	}
}

func firecrackerHostDualProofNetworkEnforcementPlanRequest() networkenforcement.PlanRequest {
	request := firecrackerHostNetworkEnforcementPlanRequest()
	request.RequestedPolicy.HTTP = networkenforcement.ProxyRoutingModeRouteViaProxy
	request.RequestedPolicy.HTTPS = networkenforcement.ProxyRoutingModeRouteViaProxy
	request.RequestedPolicy.ProxySessionID = "firecrackerhost-proxy-session"
	request.RequestedPolicy.ProxyMechanism = networkenforcement.EnforcementMechanismProxy
	return request
}

type firecrackerHostRecordingProxyListener struct {
	calls []string
}

func (listener *firecrackerHostRecordingProxyListener) PrepareProxyListener(_ context.Context, req networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	listener.calls = append(listener.calls, "prepare_proxy")
	return listener.metadata(req, networkenforcement.LifecycleStatusPrepared, networkenforcement.LifecycleReasonPrepared), nil
}

func (listener *firecrackerHostRecordingProxyListener) StartProxyListener(_ context.Context, req networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	listener.calls = append(listener.calls, "start_proxy")
	return listener.metadata(req, networkenforcement.LifecycleStatusStarting, networkenforcement.LifecycleReasonStarted), nil
}

func (listener *firecrackerHostRecordingProxyListener) ActiveProxyListener(_ context.Context, req networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	listener.calls = append(listener.calls, "active_proxy")
	return listener.metadata(req, networkenforcement.LifecycleStatusActive, networkenforcement.LifecycleReasonActive), nil
}

func (listener *firecrackerHostRecordingProxyListener) StopProxyListener(_ context.Context, req networkenforcement.ProxyListenerLifecycleRequest) (networkenforcement.ProxyListenerLifecycleMetadata, error) {
	listener.calls = append(listener.calls, "stop_proxy")
	return listener.metadata(req, networkenforcement.LifecycleStatusStopped, networkenforcement.LifecycleReasonStopped), nil
}

func (listener *firecrackerHostRecordingProxyListener) metadata(req networkenforcement.ProxyListenerLifecycleRequest, status networkenforcement.LifecycleStatus, reason networkenforcement.LifecycleReasonCode) networkenforcement.ProxyListenerLifecycleMetadata {
	plan := req.Plan.Plan()
	return networkenforcement.ProxyListenerLifecycleMetadata{
		ID:             "firecrackerhost-proxy-proof",
		PlanID:         plan.ID,
		AdapterID:      "firecrackerhost-proxy-listener",
		Status:         status,
		Mechanisms:     []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismProxy},
		Operations:     []string{listener.calls[len(listener.calls)-1], "listen 127.0.0.1:8080", "/tmp/proxy.sock", "token=secret"},
		PolicySnapshot: plan.PolicySnapshot,
		ReasonCode:     reason,
	}
}

type firecrackerHostRecordingRuleProof struct {
	mechanism networkenforcement.EnforcementMechanism
	calls     []string
}

func (rules *firecrackerHostRecordingRuleProof) RunRuleProofStep(_ context.Context, req networkenforcement.RuleProofStepRequest) (networkenforcement.RuleLifecycleMetadata, error) {
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
		ID:             "firecrackerhost-rule-proof",
		PlanID:         plan.ID,
		AdapterID:      "firecrackerhost-rules",
		Status:         status,
		Mechanisms:     []networkenforcement.EnforcementMechanism{mechanism},
		Operations:     []string{req.Operation, "iptables -A OUTPUT -d 127.0.0.1 --dport 443 token=secret"},
		PolicySnapshot: plan.PolicySnapshot,
		CapabilityLabels: []string{
			"default_deny",
			"domain_rules",
			"private_range_rules",
			"metadata_endpoint",
		},
		ReasonCode: reason,
	}, nil
}
