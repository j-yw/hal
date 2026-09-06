package networkenforcement

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

var _ Adapter = (*recordingAdapter)(nil)

type recordingAdapter struct {
	received Plan
	result   Result
}

func (a *recordingAdapter) EnforceNetwork(_ context.Context, plan SanitizedPlan) Result {
	a.received = plan.Plan()
	return a.result
}

func TestAdapterConstantsAreStable(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "outcome success", got: string(ResultOutcomeSuccess), want: "success"},
		{name: "outcome best effort", got: string(ResultOutcomeBestEffort), want: "best_effort"},
		{name: "outcome unsupported", got: string(ResultOutcomeUnsupported), want: "unsupported"},
		{name: "outcome failure", got: string(ResultOutcomeFailure), want: "failure"},
		{name: "mode none", got: string(ResultModeNone), want: "none"},
		{name: "mode best effort", got: string(ResultModeBestEffort), want: "best_effort"},
		{name: "mode proxy", got: string(ResultModeProxy), want: "proxy"},
		{name: "mode firewall", got: string(ResultModeFirewall), want: "firewall"},
		{name: "mode runtime", got: string(ResultModeRuntime), want: "runtime"},
		{name: "mode proxy firewall", got: string(ResultModeProxyFirewall), want: "proxy_firewall"},
		{name: "reason applied", got: string(ResultReasonApplied), want: "applied"},
		{name: "reason unsupported", got: string(ResultReasonAdapterUnsupported), want: "adapter_unsupported"},
		{name: "reason failed", got: string(ResultReasonAdapterFailed), want: "adapter_failed"},
		{name: "warning sanitized error", got: string(ResultWarningSanitizedAdapterError), want: "sanitized_adapter_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestRunAdapterPassesSanitizedPlanAndReturnsSanitizedResult(t *testing.T) {
	adapter := &recordingAdapter{
		result: Result{
			PlanID:          "https://plans.internal.example.com/plan?token=secret",
			AdapterID:       "fake-firewall-adapter",
			Outcome:         ResultOutcome(" SUCCESS "),
			EnforcementMode: ResultMode(" FIREWALL "),
			Mechanisms: []EnforcementMechanism{
				EnforcementMechanismFirewall,
				EnforcementMechanism("https://firewall.internal.example.com?token=secret"),
			},
			Operations: []string{
				"apply_rules",
				"/tmp/firewall.sock",
				"Authorization: Bearer ghp_secret",
			},
			PolicySnapshot: &PolicySnapshotIdentity{
				ID:        "policy-result-01",
				Version:   "https://policy.internal.example.com/v1?token=secret",
				Preset:    PolicyPreset(" DENY_BY_DEFAULT "),
				RuleSetID: "/Users/alice/rules.json",
			},
			Capability: &ResultCapability{
				Supported:                  true,
				Modes:                      []ResultMode{ResultModeFirewall, ResultMode("https://bad.example.com/mode")},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsPrivateRangeRules:  true,
				SupportsMetadataEndpoint:   true,
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: ResultReasonCode(" APPLIED "),
			WarningCodes: []ResultWarningCode{
				ResultWarningPartialEnforcement,
				ResultWarningCode("https://warning.internal.example.com?token=secret"),
			},
		},
	}

	result := RunAdapter(context.Background(), adapter, Plan{
		ID:        "network-plan-adapter-01",
		Source:    PlanSource(" RUNTIME "),
		Operation: "prepare_network",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-input-01",
			Version:   "https://policy.internal.example.com/v1?token=secret",
			Preset:    PolicyPreset(" ALLOW_LISTED "),
			RuleSetID: "rules-input-01",
		},
		DefaultPosture: DefaultPostureDenyByDefault,
		Allowlist: &AllowlistPlan{
			Mode:      AllowlistModeEnforce,
			RuleSetID: "rules-input-01",
			RuleIDs: []string{
				"rule-safe-01",
				"api.internal.example.com",
				"/tmp/rules.json",
			},
			RuleCategories: []AllowlistRuleCategory{
				AllowlistRuleCategoryDomain,
				AllowlistRuleCategory("https://category.internal.example.com?token=secret"),
			},
			Operations: []string{"allowlist", "/tmp/rules.json"},
		},
		Category: &CategoryPosturePlan{
			PrivateNetwork:   Posture(" BLOCK "),
			MetadataEndpoint: Posture("http://169.254.169.254/latest?token=secret"),
		},
		Proxy: &ProxyRoutingIntent{
			HTTP:           ProxyRoutingModeRouteViaProxy,
			ProxySessionID: "/tmp/proxy.sock",
			Mechanism:      EnforcementMechanismProxy,
			Operations:     []string{"http_connect", "/tmp/proxy.sock"},
		},
		Firewall: &FirewallIntent{
			Mode:       FirewallIntentModeApply,
			Mechanism:  EnforcementMechanismFirewall,
			Operations: []string{"default_deny", "/Users/alice/.ssh/id_rsa"},
		},
	})

	if adapter.received.ID != "network-plan-adapter-01" ||
		adapter.received.Source != PlanSourceRuntime ||
		adapter.received.Operation != "prepare_network" {
		t.Fatalf("adapter received identity = %#v, want sanitized request identity", adapter.received)
	}
	if adapter.received.PolicySnapshot == nil ||
		adapter.received.PolicySnapshot.ID != "policy-input-01" ||
		adapter.received.PolicySnapshot.Version != "" ||
		adapter.received.PolicySnapshot.Preset != PolicyPresetAllowListed ||
		adapter.received.PolicySnapshot.RuleSetID != "rules-input-01" {
		t.Fatalf("adapter received policy snapshot = %#v, want sanitized snapshot", adapter.received.PolicySnapshot)
	}
	if adapter.received.Allowlist == nil {
		t.Fatal("adapter received Allowlist = nil, want sanitized allowlist")
	}
	assertPlanStringArrayFromStrings(t, adapter.received.Allowlist.RuleIDs, []string{"rule-safe-01"})
	assertPlanStringArrayFromStrings(t, adapter.received.Allowlist.Operations, []string{"allowlist"})
	if adapter.received.Category == nil || adapter.received.Category.MetadataEndpoint != "" {
		t.Fatalf("adapter received category = %#v, want unsafe metadata endpoint redacted", adapter.received.Category)
	}
	if adapter.received.Proxy == nil || adapter.received.Proxy.ProxySessionID != "" {
		t.Fatalf("adapter received proxy = %#v, want unsafe proxy session redacted", adapter.received.Proxy)
	}
	if adapter.received.Firewall == nil {
		t.Fatal("adapter received Firewall = nil, want sanitized firewall intent")
	}
	assertPlanStringArrayFromStrings(t, adapter.received.Firewall.Operations, []string{"default_deny"})
	mustMarshalPlanObject(t, adapter.received)

	if result.PlanID != "network-plan-adapter-01" {
		t.Fatalf("result PlanID = %q, want sanitized input plan ID fallback", result.PlanID)
	}
	if result.AdapterID != "fake-firewall-adapter" {
		t.Fatalf("result AdapterID = %q, want safe adapter ID preserved", result.AdapterID)
	}
	if result.Outcome != ResultOutcomeSuccess {
		t.Fatalf("result Outcome = %q, want success", result.Outcome)
	}
	if result.EnforcementMode != ResultModeFirewall {
		t.Fatalf("result EnforcementMode = %q, want firewall", result.EnforcementMode)
	}
	if !reflect.DeepEqual(result.Mechanisms, []EnforcementMechanism{EnforcementMechanismFirewall}) {
		t.Fatalf("result Mechanisms = %#v, want firewall only", result.Mechanisms)
	}
	assertPlanStringArrayFromStrings(t, result.Operations, []string{"apply_rules"})
	if result.PolicySnapshot == nil ||
		result.PolicySnapshot.ID != "policy-result-01" ||
		result.PolicySnapshot.Version != "" ||
		result.PolicySnapshot.Preset != PolicyPresetDenyByDefault ||
		result.PolicySnapshot.RuleSetID != "" {
		t.Fatalf("result PolicySnapshot = %#v, want sanitized result snapshot", result.PolicySnapshot)
	}
	if result.Capability == nil ||
		!result.Capability.Supported ||
		!reflect.DeepEqual(result.Capability.Modes, []ResultMode{ResultModeFirewall}) ||
		!result.Capability.SupportsDefaultDenyPosture {
		t.Fatalf("result Capability = %#v, want sanitized capability metadata", result.Capability)
	}
	if result.ReasonCode != ResultReasonApplied {
		t.Fatalf("result ReasonCode = %q, want applied", result.ReasonCode)
	}
	if !reflect.DeepEqual(result.WarningCodes, []ResultWarningCode{ResultWarningPartialEnforcement}) {
		t.Fatalf("result WarningCodes = %#v, want safe warning only", result.WarningCodes)
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
		"warningCodes",
	})
}

func TestRunAdapterNilAdapterReportsUnsupported(t *testing.T) {
	result := RunAdapter(context.Background(), nil, Plan{
		ID:             "network-plan-no-adapter",
		DefaultPosture: DefaultPostureDenyByDefault,
	})

	if result.PlanID != "network-plan-no-adapter" {
		t.Fatalf("PlanID = %q, want sanitized input plan ID", result.PlanID)
	}
	if result.Outcome != ResultOutcomeUnsupported {
		t.Fatalf("Outcome = %q, want unsupported", result.Outcome)
	}
	if result.EnforcementMode != ResultModeNone {
		t.Fatalf("EnforcementMode = %q, want none", result.EnforcementMode)
	}
	if result.Capability != nil {
		t.Fatalf("Capability = %#v, want no unsupported capability claim", result.Capability)
	}
	if result.ReasonCode != ResultReasonAdapterUnsupported {
		t.Fatalf("ReasonCode = %q, want adapter_unsupported", result.ReasonCode)
	}
}

func TestSanitizeResultSupportsOutcomeSemantics(t *testing.T) {
	tests := []struct {
		name       string
		input      Result
		wantMode   ResultMode
		wantReason ResultReasonCode
		wantCap    bool
	}{
		{
			name: "success keeps enforcing mode and capability",
			input: Result{
				Outcome:         ResultOutcomeSuccess,
				EnforcementMode: ResultModeProxyFirewall,
				Capability: &ResultCapability{
					Supported: true,
					Modes:     []ResultMode{ResultModeProxyFirewall},
				},
			},
			wantMode:   ResultModeProxyFirewall,
			wantReason: ResultReasonApplied,
			wantCap:    true,
		},
		{
			name: "best effort reports best effort mode",
			input: Result{
				Outcome:         ResultOutcomeBestEffort,
				EnforcementMode: ResultModeFirewall,
				Capability: &ResultCapability{
					Supported: true,
					Modes:     []ResultMode{ResultModeFirewall},
				},
			},
			wantMode:   ResultModeBestEffort,
			wantReason: ResultReasonBestEffort,
			wantCap:    true,
		},
		{
			name: "unsupported fails closed",
			input: Result{
				Outcome:         ResultOutcomeUnsupported,
				EnforcementMode: ResultModeFirewall,
				Capability: &ResultCapability{
					Supported: true,
					Modes:     []ResultMode{ResultModeFirewall},
				},
			},
			wantMode:   ResultModeNone,
			wantReason: ResultReasonAdapterUnsupported,
			wantCap:    false,
		},
		{
			name: "failure fails closed",
			input: Result{
				Outcome:         ResultOutcomeFailure,
				EnforcementMode: ResultModeProxyFirewall,
				Capability: &ResultCapability{
					Supported: true,
					Modes:     []ResultMode{ResultModeProxyFirewall},
				},
			},
			wantMode:   ResultModeNone,
			wantReason: ResultReasonAdapterFailed,
			wantCap:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeResult(tt.input)
			if got.EnforcementMode != tt.wantMode {
				t.Fatalf("EnforcementMode = %q, want %q", got.EnforcementMode, tt.wantMode)
			}
			if got.ReasonCode != tt.wantReason {
				t.Fatalf("ReasonCode = %q, want %q", got.ReasonCode, tt.wantReason)
			}
			if (got.Capability != nil) != tt.wantCap {
				t.Fatalf("Capability = %#v, want present %v", got.Capability, tt.wantCap)
			}
			mustMarshalPlanObject(t, got)
		})
	}
}

func TestSanitizedPlanJSONIsRedactionSafe(t *testing.T) {
	payload, err := json.Marshal(NewSanitizedPlan(Plan{
		ID:        "https://plan.internal.example.com?token=secret",
		Operation: "connect api.internal.example.com:443",
		Proxy: &ProxyRoutingIntent{
			HTTP:           ProxyRoutingModeRouteViaProxy,
			ProxySessionID: "/tmp/proxy.sock",
			Mechanism:      EnforcementMechanismProxy,
		},
	}))
	if err != nil {
		t.Fatalf("Marshal(SanitizedPlan) error: %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", payload, err)
	}
	if _, ok := object["id"]; ok {
		t.Fatalf("unsafe id survived sanitized plan JSON: %s", payload)
	}
	if _, ok := object["operation"]; ok {
		t.Fatalf("unsafe operation survived sanitized plan JSON: %s", payload)
	}
	proxy := requirePlanObject(t, object["proxy"])
	assertPlanObjectKeys(t, proxy, []string{"http", "mechanism"})
}
