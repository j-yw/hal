package networkenforcement

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestBuildPlanConstructsDefaultDenyPrivateAndMetadataPosture(t *testing.T) {
	request := PlanRequest{
		ID:        "network-plan-builder-01",
		Source:    PlanSourceWorker,
		Operation: "prepare_network",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-snapshot-builder-01",
			Version:   "v1",
			RuleSetID: "rules-builder-01",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:         PolicyPresetDenyByDefault,
			RuleSetID:      "rules-builder-01",
			TCP:            PostureBlock,
			UDP:            PostureBlock,
			ICMP:           PostureBlock,
			HTTP:           ProxyRoutingModeRouteViaProxy,
			HTTPS:          ProxyRoutingModeRouteViaProxy,
			ProxySessionID: "proxy-session-builder-01",
		},
	}

	plan := BuildPlan(request)

	if plan.ID != request.ID || plan.Source != request.Source || plan.Operation != request.Operation {
		t.Fatalf("plan identity = %#v, want request identity", plan)
	}
	if plan.DefaultPosture != DefaultPostureDenyByDefault {
		t.Fatalf("DefaultPosture = %q, want %q", plan.DefaultPosture, DefaultPostureDenyByDefault)
	}
	if plan.PolicySnapshot == nil || plan.PolicySnapshot.Preset != PolicyPresetDenyByDefault || plan.PolicySnapshot.RuleSetID != "rules-builder-01" {
		t.Fatalf("PolicySnapshot = %#v, want requested preset and rule set", plan.PolicySnapshot)
	}
	if plan.Category == nil {
		t.Fatal("Category = nil, want private network and metadata endpoint posture")
	}
	if plan.Category.PrivateNetwork != PostureBlock {
		t.Fatalf("PrivateNetwork = %q, want %q", plan.Category.PrivateNetwork, PostureBlock)
	}
	if plan.Category.MetadataEndpoint != PostureBlock {
		t.Fatalf("MetadataEndpoint = %q, want %q", plan.Category.MetadataEndpoint, PostureBlock)
	}
	if plan.RawProtocols == nil || plan.RawProtocols.TCP != PostureBlock || plan.RawProtocols.UDP != PostureBlock || plan.RawProtocols.ICMP != PostureBlock {
		t.Fatalf("RawProtocols = %#v, want tcp/udp/icmp block", plan.RawProtocols)
	}
	if plan.Proxy == nil || plan.Proxy.Mechanism != EnforcementMechanismProxy {
		t.Fatalf("Proxy = %#v, want proxy mechanism", plan.Proxy)
	}
	if !reflect.DeepEqual(plan.Proxy.Operations, []string{planOperationHTTPConnect, planOperationHTTPSConnect}) {
		t.Fatalf("Proxy.Operations = %#v, want HTTP/HTTPS connect operations", plan.Proxy.Operations)
	}
	if plan.Firewall == nil || plan.Firewall.Mode != FirewallIntentModePrepare || plan.Firewall.Mechanism != EnforcementMechanismFirewall {
		t.Fatalf("Firewall = %#v, want prepare firewall intent", plan.Firewall)
	}
	wantFirewallOps := []string{
		planOperationDefaultDeny,
		planOperationBlockPrivateNetwork,
		planOperationBlockMetadataEndpoint,
		planOperationBlockRawProtocols,
	}
	if !reflect.DeepEqual(plan.Firewall.Operations, wantFirewallOps) {
		t.Fatalf("Firewall.Operations = %#v, want %#v", plan.Firewall.Operations, wantFirewallOps)
	}

	got := mustMarshalPlanObject(t, plan)
	category := requirePlanObject(t, got["category"])
	if category["privateNetwork"] != string(PostureBlock) || category["metadataEndpoint"] != string(PostureBlock) {
		t.Fatalf("category JSON = %#v, want blocked private network and metadata endpoint", category)
	}
}

func TestBuildPlanHonorsExplicitRequestedNetworkPostureInput(t *testing.T) {
	plan := BuildPlan(PlanRequest{
		ID:        "network-plan-builder-02",
		Source:    PlanSourceMicroVM,
		Operation: "prepare_network",
		RequestedPolicy: RequestedNetworkPosture{
			Preset:            PolicyPresetLegacyDefault,
			DefaultPosture:    DefaultPostureAllowByDefault,
			PrivateNetwork:    PostureAudit,
			MetadataEndpoint:  PostureBlock,
			TCP:               PostureAudit,
			UDP:               PostureAllow,
			ICMP:              PostureUnspecified,
			HTTP:              ProxyRoutingModeBlock,
			HTTPS:             ProxyRoutingModeBypassProxy,
			ProxyMechanism:    EnforcementMechanismProxy,
			FirewallMode:      FirewallIntentModeAuditOnly,
			FirewallMechanism: EnforcementMechanismRuntime,
		},
	})

	if plan.DefaultPosture != DefaultPostureAllowByDefault {
		t.Fatalf("DefaultPosture = %q, want explicit %q", plan.DefaultPosture, DefaultPostureAllowByDefault)
	}
	if plan.Category == nil || plan.Category.PrivateNetwork != PostureAudit || plan.Category.MetadataEndpoint != PostureBlock {
		t.Fatalf("Category = %#v, want explicit audit/block posture", plan.Category)
	}
	if plan.RawProtocols == nil || plan.RawProtocols.TCP != PostureAudit || plan.RawProtocols.UDP != PostureAllow || plan.RawProtocols.ICMP != PostureUnspecified {
		t.Fatalf("RawProtocols = %#v, want explicit raw protocol posture", plan.RawProtocols)
	}
	if plan.Proxy == nil || plan.Proxy.HTTP != ProxyRoutingModeBlock || plan.Proxy.HTTPS != ProxyRoutingModeBypassProxy || plan.Proxy.Mechanism != EnforcementMechanismProxy {
		t.Fatalf("Proxy = %#v, want explicit proxy routing posture", plan.Proxy)
	}
	if !reflect.DeepEqual(plan.Proxy.Operations, []string{planOperationHTTPConnect}) {
		t.Fatalf("Proxy.Operations = %#v, want HTTP operation only", plan.Proxy.Operations)
	}
	if plan.Firewall == nil || plan.Firewall.Mode != FirewallIntentModeAuditOnly || plan.Firewall.Mechanism != EnforcementMechanismRuntime {
		t.Fatalf("Firewall = %#v, want explicit audit/runtime intent", plan.Firewall)
	}
	if !reflect.DeepEqual(plan.Firewall.Operations, []string{planOperationBlockMetadataEndpoint}) {
		t.Fatalf("Firewall.Operations = %#v, want metadata block operation only", plan.Firewall.Operations)
	}
}

func TestBuildPlanIsDeterministicAndDoesNotShareRequestSlices(t *testing.T) {
	request := PlanRequest{
		ID:        "network-plan-builder-03",
		Source:    PlanSourceRuntime,
		Operation: "prepare_network",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-snapshot-copy",
			RuleSetID: "rules-copy",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:    PolicyPresetAllowListed,
			RuleSetID: "rules-copy",
			RuleIDs: []string{
				"rule-alpha",
				"rule-beta",
			},
			RuleCategories: []AllowlistRuleCategory{
				AllowlistRuleCategoryDomain,
				AllowlistRuleCategoryEndpoint,
			},
		},
	}
	before := clonePlanRequestForPlannerTest(request)

	first := BuildPlan(request)
	second := BuildPlan(request)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("BuildPlan is not deterministic:\nfirst:  %#v\nsecond: %#v", first, second)
	}
	if !reflect.DeepEqual(request, before) {
		t.Fatalf("BuildPlan mutated request:\nbefore: %#v\nafter:  %#v", before, request)
	}

	request.PolicySnapshot.ID = "policy-snapshot-mutated"
	request.RequestedPolicy.RuleIDs[0] = "rule-mutated"
	request.RequestedPolicy.RuleCategories[0] = AllowlistRuleCategoryLoopback

	if first.PolicySnapshot == nil || first.PolicySnapshot.ID != "policy-snapshot-copy" {
		t.Fatalf("PolicySnapshot = %#v, want copied snapshot identity", first.PolicySnapshot)
	}
	if first.Allowlist == nil {
		t.Fatal("Allowlist = nil, want copied allowlist")
	}
	assertPlanStringArrayFromStrings(t, first.Allowlist.RuleIDs, []string{"rule-alpha", "rule-beta"})
	if !reflect.DeepEqual(first.Allowlist.RuleCategories, []AllowlistRuleCategory{AllowlistRuleCategoryDomain, AllowlistRuleCategoryEndpoint}) {
		t.Fatalf("RuleCategories = %#v, want copied categories", first.Allowlist.RuleCategories)
	}
	if !reflect.DeepEqual(first.Allowlist.Operations, []string{planOperationAllowlist, planOperationAllowlistDomain, planOperationAllowlistEndpoint}) {
		t.Fatalf("Allowlist.Operations = %#v, want allowlist operation", first.Allowlist.Operations)
	}
	if first.Category == nil || first.Category.PrivateNetwork != PostureBlock || first.Category.MetadataEndpoint != PostureBlock {
		t.Fatalf("Category = %#v, want allow_listed preset to block private network and metadata endpoint", first.Category)
	}
}

func TestNormalizeAllowlistRulesSupportsSafeRuleCategories(t *testing.T) {
	result := NormalizeAllowlistRules([]AllowlistRule{
		{ID: "rule-domain", Category: AllowlistRuleCategoryDomain, Value: "api.example.com"},
		{ID: "rule-endpoint", Category: AllowlistRuleCategoryEndpoint, Value: "api.example.com:443"},
		{ID: "rule-private", Category: AllowlistRuleCategoryPrivateRange, Value: "10.0.0.0/8"},
		{ID: "rule-metadata", Category: AllowlistRuleCategoryMetadataEndpoint, Value: "169.254.169.254"},
		{ID: "rule-loopback", Category: AllowlistRuleCategoryLoopback, Value: "127.0.0.1"},
		{ID: "rule-link-local", Category: AllowlistRuleCategoryLinkLocal, Value: "fe80::/10"},
	})

	if !result.Valid {
		t.Fatalf("NormalizeAllowlistRules valid = false, errors = %#v", result.Errors)
	}
	assertPlanStringArrayFromStrings(t, result.RuleIDs, []string{
		"rule-domain",
		"rule-endpoint",
		"rule-private",
		"rule-metadata",
		"rule-loopback",
		"rule-link-local",
	})
	if !reflect.DeepEqual(result.RuleCategories, []AllowlistRuleCategory{
		AllowlistRuleCategoryDomain,
		AllowlistRuleCategoryEndpoint,
		AllowlistRuleCategoryPrivateRange,
		AllowlistRuleCategoryMetadataEndpoint,
		AllowlistRuleCategoryLoopback,
		AllowlistRuleCategoryLinkLocal,
	}) {
		t.Fatalf("RuleCategories = %#v, want supported categories in stable order", result.RuleCategories)
	}
	assertPlanStringArrayFromStrings(t, result.Operations, []string{
		planOperationAllowlistDomain,
		planOperationAllowlistEndpoint,
		planOperationAllowlistPrivateRange,
		planOperationAllowlistMetadata,
		planOperationAllowlistLoopback,
		planOperationAllowlistLinkLocal,
	})
}

func TestBuildPlanNormalizesAllowlistRulesWithoutExposingRawValues(t *testing.T) {
	plan := BuildPlan(PlanRequest{
		ID:        "network-plan-allowlist-rules",
		Source:    PlanSourceRuntime,
		Operation: "prepare_network",
		RequestedPolicy: RequestedNetworkPosture{
			Preset:        PolicyPresetAllowListed,
			AllowlistMode: AllowlistModeEnforce,
			RuleSetID:     "rules-allowlist",
			AllowlistRules: []AllowlistRule{
				{ID: "rule-domain", Category: AllowlistRuleCategoryDomain, Value: "api.example.com"},
				{ID: "rule-endpoint", Category: AllowlistRuleCategoryEndpoint, Value: "api.example.com:443"},
				{ID: "rule-private", Category: AllowlistRuleCategoryPrivateRange, Value: "10.0.0.0/8"},
				{ID: "rule-metadata", Category: AllowlistRuleCategoryMetadataEndpoint, Value: "169.254.169.254"},
			},
		},
	})

	if plan.Allowlist == nil {
		t.Fatal("Allowlist = nil, want normalized rule metadata")
	}
	assertPlanStringArrayFromStrings(t, plan.Allowlist.RuleIDs, []string{"rule-domain", "rule-endpoint", "rule-private", "rule-metadata"})
	if !reflect.DeepEqual(plan.Allowlist.RuleCategories, []AllowlistRuleCategory{
		AllowlistRuleCategoryDomain,
		AllowlistRuleCategoryEndpoint,
		AllowlistRuleCategoryPrivateRange,
		AllowlistRuleCategoryMetadataEndpoint,
	}) {
		t.Fatalf("RuleCategories = %#v, want normalized safe categories", plan.Allowlist.RuleCategories)
	}
	assertPlanStringArrayFromStrings(t, plan.Allowlist.Operations, []string{
		planOperationAllowlist,
		planOperationAllowlistDomain,
		planOperationAllowlistEndpoint,
		planOperationAllowlistPrivateRange,
		planOperationAllowlistMetadata,
	})

	got := mustMarshalPlanObject(t, plan)
	allowlist := requirePlanObject(t, got["allowlist"])
	assertPlanStringArray(t, allowlist["ruleCategories"], []string{
		string(AllowlistRuleCategoryDomain),
		string(AllowlistRuleCategoryEndpoint),
		string(AllowlistRuleCategoryPrivateRange),
		string(AllowlistRuleCategoryMetadataEndpoint),
	})
	assertPlanStringArray(t, allowlist["operations"], []string{
		planOperationAllowlist,
		planOperationAllowlistDomain,
		planOperationAllowlistEndpoint,
		planOperationAllowlistPrivateRange,
		planOperationAllowlistMetadata,
	})
}

func TestNormalizeAllowlistRulesRejectsUnsafeValuesWithSanitizedErrors(t *testing.T) {
	result := NormalizeAllowlistRules([]AllowlistRule{
		{ID: "rule-safe", Category: AllowlistRuleCategoryDomain, Value: "safe.example.com"},
		{ID: "rule-url", Category: AllowlistRuleCategoryDomain, Value: "https://api.example.com/path?token=secret"},
		{ID: "rule-wildcard", Category: AllowlistRuleCategoryDomain, Value: "*.example.com"},
		{ID: "rule-endpoint", Category: AllowlistRuleCategoryEndpoint, Value: "api.example.com:not-a-port"},
		{ID: "rule-private", Category: AllowlistRuleCategoryPrivateRange, Value: "203.0.113.0/24"},
		{ID: "rule-invalid-category", Category: AllowlistRuleCategory("https://api.example.com/category?token=secret"), Value: "api.example.com"},
	})

	if result.Valid {
		t.Fatalf("NormalizeAllowlistRules valid = true, want errors")
	}
	if len(result.Errors) != 5 {
		t.Fatalf("Errors = %#v, want five sanitized errors", result.Errors)
	}
	wantCodes := []AllowlistRuleValidationCode{
		AllowlistRuleValidationUnsafeValue,
		AllowlistRuleValidationUnsupportedWildcard,
		AllowlistRuleValidationMalformedEndpoint,
		AllowlistRuleValidationNonPrivateRange,
		AllowlistRuleValidationInvalidCategory,
	}
	for i, want := range wantCodes {
		if result.Errors[i].Code != want {
			t.Fatalf("Errors[%d].Code = %q, want %q in %#v", i, result.Errors[i].Code, want, result.Errors)
		}
		if strings.Contains(strings.ToLower(result.Errors[i].Error()), "example.com") ||
			strings.Contains(strings.ToLower(result.Errors[i].Error()), "token") ||
			strings.Contains(strings.ToLower(result.Errors[i].Message), "example.com") ||
			strings.Contains(strings.ToLower(result.Errors[i].Message), "token") {
			t.Fatalf("error leaked raw rule value: %#v", result.Errors[i])
		}
	}
	assertPlanStringArrayFromStrings(t, result.RuleIDs, []string{"rule-safe"})
	if !reflect.DeepEqual(result.RuleCategories, []AllowlistRuleCategory{AllowlistRuleCategoryDomain}) {
		t.Fatalf("RuleCategories = %#v, want only valid safe category", result.RuleCategories)
	}

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal normalization result error: %v", err)
	}
	payloadLower := strings.ToLower(string(payload))
	for _, forbidden := range []string{
		"api.example.com",
		"safe.example.com",
		"203.0.113.0",
		"not-a-port",
		"https://",
		"?token",
		"secret",
	} {
		if strings.Contains(payloadLower, forbidden) {
			t.Fatalf("normalization result JSON %s leaked forbidden fragment %q", payload, forbidden)
		}
	}
}

func TestBuildPlanSanitizesUnsafeRequestedMetadata(t *testing.T) {
	plan := BuildPlan(PlanRequest{
		ID:        "https://policy.invalid/plan?token=secret",
		Source:    PlanSource(" RUNTIME "),
		Operation: "connect https://policy.invalid/path?credential=secret",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-snapshot-safe",
			Version:   "/Users/alice/private-version",
			RuleSetID: "/tmp/rules.json",
		},
		RequestedPolicy: RequestedNetworkPosture{
			Preset:           PolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID:        "/tmp/rules.json",
			RuleIDs:          []string{"rule-safe", "https://policy.invalid/rule?token=secret"},
			RuleCategories:   []AllowlistRuleCategory{AllowlistRuleCategoryDomain, AllowlistRuleCategory("http://policy.invalid/category")},
			PrivateNetwork:   Posture("api.internal.invalid"),
			MetadataEndpoint: Posture(" BLOCK "),
			HTTP:             ProxyRoutingMode(" ROUTE_VIA_PROXY "),
			ProxySessionID:   "/tmp/proxy.sock?token=secret",
		},
	})

	if plan.ID != "" {
		t.Fatalf("ID = %q, want unsafe id cleared", plan.ID)
	}
	if plan.Operation != "" {
		t.Fatalf("Operation = %q, want unsafe operation cleared", plan.Operation)
	}
	if plan.Source != PlanSourceRuntime {
		t.Fatalf("Source = %q, want normalized runtime", plan.Source)
	}
	if plan.PolicySnapshot == nil || plan.PolicySnapshot.ID != "policy-snapshot-safe" || plan.PolicySnapshot.Preset != PolicyPresetDenyByDefault {
		t.Fatalf("PolicySnapshot = %#v, want safe snapshot id and preset", plan.PolicySnapshot)
	}
	if plan.PolicySnapshot.RuleSetID != "" || plan.PolicySnapshot.Version != "" {
		t.Fatalf("PolicySnapshot = %#v, want unsafe version and rule set cleared", plan.PolicySnapshot)
	}
	if plan.Allowlist == nil || !reflect.DeepEqual(plan.Allowlist.RuleIDs, []string{"rule-safe"}) || !reflect.DeepEqual(plan.Allowlist.RuleCategories, []AllowlistRuleCategory{AllowlistRuleCategoryDomain}) {
		t.Fatalf("Allowlist = %#v, want only safe allowlist metadata", plan.Allowlist)
	}
	if plan.Category == nil || plan.Category.PrivateNetwork != PostureBlock || plan.Category.MetadataEndpoint != PostureBlock {
		t.Fatalf("Category = %#v, want sanitized default deny category blocks", plan.Category)
	}
	if plan.Proxy == nil || plan.Proxy.HTTP != ProxyRoutingModeRouteViaProxy || plan.Proxy.ProxySessionID != "" || plan.Proxy.Mechanism != EnforcementMechanismProxy {
		t.Fatalf("Proxy = %#v, want route_via_proxy without unsafe session id", plan.Proxy)
	}

	mustMarshalPlanObject(t, plan)
}

func clonePlanRequestForPlannerTest(request PlanRequest) PlanRequest {
	out := request
	if request.PolicySnapshot != nil {
		snapshot := *request.PolicySnapshot
		out.PolicySnapshot = &snapshot
	}
	if len(request.RequestedPolicy.RuleIDs) > 0 {
		out.RequestedPolicy.RuleIDs = append([]string(nil), request.RequestedPolicy.RuleIDs...)
	}
	if len(request.RequestedPolicy.RuleCategories) > 0 {
		out.RequestedPolicy.RuleCategories = append([]AllowlistRuleCategory(nil), request.RequestedPolicy.RuleCategories...)
	}
	if len(request.RequestedPolicy.AllowlistRules) > 0 {
		out.RequestedPolicy.AllowlistRules = append([]AllowlistRule(nil), request.RequestedPolicy.AllowlistRules...)
	}
	return out
}

func assertPlanStringArrayFromStrings(t *testing.T, got []string, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("strings = %#v, want %#v", got, want)
	}
}
