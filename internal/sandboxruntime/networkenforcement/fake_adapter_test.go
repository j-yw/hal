package networkenforcement

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

var _ Adapter = (*fakeEnforcementAdapter)(nil)

type fakeEnforcementAdapter struct {
	adapterID  string
	mode       ResultMode
	mechanisms []EnforcementMechanism
	operations []string
	capability *ResultCapability
	cause      error
	received   Plan
}

func (a *fakeEnforcementAdapter) EnforceNetwork(_ context.Context, plan SanitizedPlan) Result {
	a.received = plan.Plan()
	if a.cause != nil {
		return a.failureResult(a.received)
	}
	return Result{
		PlanID:          a.received.ID,
		AdapterID:       a.safeAdapterID(),
		Outcome:         ResultOutcomeSuccess,
		EnforcementMode: a.mode,
		Mechanisms:      append([]EnforcementMechanism(nil), a.mechanisms...),
		Operations:      append([]string(nil), a.operations...),
		PolicySnapshot:  clonePolicySnapshotForFakeAdapter(a.received.PolicySnapshot),
		Capability:      cloneResultCapabilityForFakeAdapter(a.capability),
		ReasonCode:      ResultReasonApplied,
	}
}

func (a *fakeEnforcementAdapter) failureResult(plan Plan) Result {
	operations := append([]string{"fail_closed"}, a.operations...)
	operations = append(operations, a.cause.Error())
	return Result{
		PlanID:          plan.ID,
		AdapterID:       a.safeAdapterID(),
		Outcome:         ResultOutcomeFailure,
		EnforcementMode: a.mode,
		Mechanisms:      append([]EnforcementMechanism(nil), a.mechanisms...),
		Operations:      operations,
		Capability:      cloneResultCapabilityForFakeAdapter(a.capability),
		ReasonCode:      ResultReasonAdapterFailed,
		WarningCodes:    []ResultWarningCode{ResultWarningSanitizedAdapterError},
	}
}

func (a *fakeEnforcementAdapter) publicError(result Result) error {
	if result.Outcome != ResultOutcomeFailure {
		return nil
	}
	reason := result.ReasonCode
	if reason == "" {
		reason = ResultReasonAdapterFailed
	}
	return errors.New("network enforcement adapter " + string(reason))
}

func (a *fakeEnforcementAdapter) safeAdapterID() string {
	if a.adapterID != "" {
		return a.adapterID
	}
	return "fake-network-enforcement-adapter"
}

func TestFakeEnforcementAdapterSuccessCanClaimStrongerCapability(t *testing.T) {
	adapter := &fakeEnforcementAdapter{
		adapterID:  "fake-proxy-firewall-adapter",
		mode:       ResultModeProxyFirewall,
		mechanisms: []EnforcementMechanism{EnforcementMechanismProxy, EnforcementMechanismFirewall},
		operations: []string{"proxy_route", "firewall_apply"},
		capability: &ResultCapability{
			Supported:                  true,
			Modes:                      []ResultMode{ResultModeProxyFirewall},
			SupportsDomainRules:        true,
			SupportsEndpointRules:      true,
			SupportsPrivateRangeRules:  true,
			SupportsMetadataEndpoint:   true,
			SupportsLoopbackRules:      true,
			SupportsLinkLocalRules:     true,
			SupportsDefaultDenyPosture: true,
		},
	}

	result := RunAdapter(context.Background(), adapter, fakeAdapterPlan())

	if adapter.received.ID != "network-plan-fake-adapter" ||
		adapter.received.Source != PlanSourceRuntime ||
		adapter.received.PolicySnapshot == nil ||
		adapter.received.PolicySnapshot.ID != "policy-snapshot-fake" {
		t.Fatalf("fake adapter received plan = %#v, want sanitized input plan", adapter.received)
	}
	if result.Outcome != ResultOutcomeSuccess {
		t.Fatalf("Outcome = %q, want success", result.Outcome)
	}
	if result.EnforcementMode != ResultModeProxyFirewall {
		t.Fatalf("EnforcementMode = %q, want proxy_firewall", result.EnforcementMode)
	}
	if !reflect.DeepEqual(result.Mechanisms, []EnforcementMechanism{EnforcementMechanismProxy, EnforcementMechanismFirewall}) {
		t.Fatalf("Mechanisms = %#v, want proxy and firewall", result.Mechanisms)
	}
	assertPlanStringArrayFromStrings(t, result.Operations, []string{"proxy_route", "firewall_apply"})
	if result.Capability == nil ||
		!result.Capability.Supported ||
		!reflect.DeepEqual(result.Capability.Modes, []ResultMode{ResultModeProxyFirewall}) ||
		!result.Capability.SupportsDomainRules ||
		!result.Capability.SupportsEndpointRules ||
		!result.Capability.SupportsPrivateRangeRules ||
		!result.Capability.SupportsMetadataEndpoint ||
		!result.Capability.SupportsLoopbackRules ||
		!result.Capability.SupportsLinkLocalRules ||
		!result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("Capability = %#v, want strong fake capability metadata", result.Capability)
	}
	got := mustMarshalPlanObject(t, result)
	assertPlanObjectKeys(t, got, []string{
		"planId",
		"adapterId",
		"outcome",
		"enforcementMode",
		"mechanisms",
		"operations",
		"policySnapshot",
		"capability",
		"reasonCode",
	})
}

func TestFakeEnforcementAdapterFailureFailsClosed(t *testing.T) {
	adapter := &fakeEnforcementAdapter{
		adapterID:  "fake-failing-adapter",
		mode:       ResultModeProxyFirewall,
		mechanisms: []EnforcementMechanism{EnforcementMechanismProxy, EnforcementMechanismFirewall},
		operations: []string{"proxy_route"},
		capability: &ResultCapability{
			Supported:                  true,
			Modes:                      []ResultMode{ResultModeProxyFirewall},
			SupportsDefaultDenyPosture: true,
		},
		cause: errors.New("dial https://api.internal.example.com:443 via /tmp/proxy.sock with token=secret"),
	}

	result := RunAdapter(context.Background(), adapter, fakeAdapterPlan())

	if result.Outcome != ResultOutcomeFailure {
		t.Fatalf("Outcome = %q, want failure", result.Outcome)
	}
	if result.EnforcementMode != ResultModeNone {
		t.Fatalf("EnforcementMode = %q, want fail-closed none", result.EnforcementMode)
	}
	if result.Capability != nil {
		t.Fatalf("Capability = %#v, want failure to clear capability upgrade", result.Capability)
	}
	if result.ReasonCode != ResultReasonAdapterFailed {
		t.Fatalf("ReasonCode = %q, want adapter_failed", result.ReasonCode)
	}
	if !reflect.DeepEqual(result.WarningCodes, []ResultWarningCode{ResultWarningSanitizedAdapterError}) {
		t.Fatalf("WarningCodes = %#v, want sanitized adapter error warning", result.WarningCodes)
	}
	assertPlanStringArrayFromStrings(t, result.Operations, []string{"fail_closed", "proxy_route"})
	mustMarshalPlanObject(t, result)
}

func TestFakeEnforcementAdapterErrorSurfacesAreRedacted(t *testing.T) {
	adapter := &fakeEnforcementAdapter{
		adapterID:  "fake-error-redaction-adapter",
		mode:       ResultModeFirewall,
		operations: []string{"firewall_apply"},
		capability: &ResultCapability{
			Supported:             true,
			Modes:                 []ResultMode{ResultModeFirewall},
			SupportsEndpointRules: true,
		},
		cause: errors.New("iptables failed for api.internal.example.com:443 with Authorization: Bearer ghp_secret using /Users/alice/.ssh/id_rsa"),
	}

	result := RunAdapter(context.Background(), adapter, fakeAdapterPlan())
	publicErr := adapter.publicError(result)
	if publicErr == nil {
		t.Fatal("public error = nil, want sanitized failure error")
	}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(Result) error: %v", err)
	}
	mustMarshalPlanObject(t, result)
	publicText := strings.ToLower(publicErr.Error() + " " + string(payload))
	for _, forbidden := range forbiddenPlanPayloadFragments() {
		if strings.Contains(publicText, strings.ToLower(forbidden)) {
			t.Fatalf("fake adapter public error or JSON leaked forbidden fragment %q in %q", forbidden, publicText)
		}
	}
	for _, required := range []string{
		string(ResultOutcomeFailure),
		string(ResultModeNone),
		string(ResultReasonAdapterFailed),
		string(ResultWarningSanitizedAdapterError),
	} {
		if !strings.Contains(publicText, required) {
			t.Fatalf("fake adapter public error or JSON = %q, want safe marker %q", publicText, required)
		}
	}
}

func fakeAdapterPlan() Plan {
	return BuildPlan(PlanRequest{
		ID:        "network-plan-fake-adapter",
		Source:    PlanSourceRuntime,
		Operation: "prepare_network",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-snapshot-fake",
			Version:   "v1",
			Preset:    PolicyPresetDenyByDefault,
			RuleSetID: "rules-fake",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:            PolicyPresetDenyByDefault,
			RuleSetID:         "rules-fake",
			RuleIDs:           []string{"rule-domain-fake", "api.internal.example.com"},
			RuleCategories:    []AllowlistRuleCategory{AllowlistRuleCategoryDomain, AllowlistRuleCategoryEndpoint},
			PrivateNetwork:    PostureBlock,
			MetadataEndpoint:  PostureBlock,
			HTTP:              ProxyRoutingModeRouteViaProxy,
			HTTPS:             ProxyRoutingModeBlock,
			ProxySessionID:    "proxy-session-fake",
			ProxyMechanism:    EnforcementMechanismProxy,
			FirewallMode:      FirewallIntentModeApply,
			FirewallMechanism: EnforcementMechanismFirewall,
		},
	})
}

func clonePolicySnapshotForFakeAdapter(snapshot *PolicySnapshotIdentity) *PolicySnapshotIdentity {
	if snapshot == nil {
		return nil
	}
	clone := *snapshot
	return &clone
}

func cloneResultCapabilityForFakeAdapter(capability *ResultCapability) *ResultCapability {
	if capability == nil {
		return nil
	}
	clone := *capability
	clone.Modes = append([]ResultMode(nil), capability.Modes...)
	return &clone
}
