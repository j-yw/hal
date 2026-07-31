package networkenforcement

import (
	"reflect"
	"testing"
)

func TestLiveLifecycleConstantsAreStable(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "status requested", got: string(LifecycleStatusRequested), want: "requested"},
		{name: "status planned", got: string(LifecycleStatusPlanned), want: "planned"},
		{name: "status prepared", got: string(LifecycleStatusPrepared), want: "prepared"},
		{name: "status starting", got: string(LifecycleStatusStarting), want: "starting"},
		{name: "status applying", got: string(LifecycleStatusApplying), want: "applying"},
		{name: "status active", got: string(LifecycleStatusActive), want: "active"},
		{name: "status rolling back", got: string(LifecycleStatusRollingBack), want: "rolling_back"},
		{name: "status cleaning up", got: string(LifecycleStatusCleaningUp), want: "cleaning_up"},
		{name: "status stopped", got: string(LifecycleStatusStopped), want: "stopped"},
		{name: "status failed", got: string(LifecycleStatusFailed), want: "failed"},
		{name: "status skipped", got: string(LifecycleStatusSkipped), want: "skipped"},
		{name: "reason prepared", got: string(LifecycleReasonPrepared), want: "prepared"},
		{name: "reason started", got: string(LifecycleReasonStarted), want: "started"},
		{name: "reason applied", got: string(LifecycleReasonApplied), want: "applied"},
		{name: "reason active", got: string(LifecycleReasonActive), want: "active"},
		{name: "reason stopped", got: string(LifecycleReasonStopped), want: "stopped"},
		{name: "reason skipped", got: string(LifecycleReasonSkipped), want: "skipped"},
		{name: "reason unsupported", got: string(LifecycleReasonAdapterUnsupported), want: "adapter_unsupported"},
		{name: "reason failed", got: string(LifecycleReasonAdapterFailed), want: "adapter_failed"},
		{name: "reason capability missing", got: string(LifecycleReasonCapabilityMissing), want: "capability_missing"},
		{name: "reason cleanup failed", got: string(LifecycleReasonCleanupFailed), want: "cleanup_failed"},
		{name: "reason rollback failed", got: string(LifecycleReasonRollbackFailed), want: "rollback_failed"},
		{name: "reason active check failed", got: string(LifecycleReasonActiveCheckFailed), want: "active_check_failed"},
		{name: "warning cleanup failed", got: string(LifecycleWarningCleanupFailed), want: "cleanup_failed"},
		{name: "warning rollback failed", got: string(LifecycleWarningRollbackFailed), want: "rollback_failed"},
		{name: "warning active check failed", got: string(LifecycleWarningActiveCheckFailed), want: "active_check_failed"},
		{name: "warning partial lifecycle", got: string(LifecycleWarningPartialLifecycle), want: "partial_lifecycle"},
		{name: "warning unsupported mechanism", got: string(LifecycleWarningUnsupportedMechanism), want: "unsupported_mechanism"},
		{name: "warning sanitized adapter error", got: string(LifecycleWarningSanitizedAdapterError), want: "sanitized_adapter_error"},
		{name: "warning metadata only fallback", got: string(LifecycleWarningMetadataOnlyFallback), want: "metadata_only_fallback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestLiveLifecycleJSONRepresentsProxyAndRuleState(t *testing.T) {
	got := mustMarshalPlanObject(t, LiveLifecycleMetadata{
		PlanID:    "network-plan-live-01",
		AdapterID: "fake-live-adapter",
		Status:    LifecycleStatusActive,
		Mechanisms: []EnforcementMechanism{
			EnforcementMechanismProxy,
			EnforcementMechanismFirewall,
		},
		Operations: []string{"prepare_proxy", "apply_rules"},
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-live-01",
			Version:   "v1",
			Preset:    PolicyPresetDenyByDefault,
			RuleSetID: "rules-live-01",
		},
		Proxy: &ProxyListenerLifecycleMetadata{
			ID:        "proxy-live-01",
			PlanID:    "network-plan-live-01",
			AdapterID: "fake-live-adapter",
			Status:    LifecycleStatusActive,
			Mechanisms: []EnforcementMechanism{
				EnforcementMechanismProxy,
			},
			Operations:       []string{"prepare_proxy", "start_proxy"},
			PolicySnapshot:   &PolicySnapshotIdentity{ID: "policy-live-01", Preset: PolicyPresetDenyByDefault},
			CapabilityLabels: []string{"http_proxy", "default_deny"},
			ReasonCode:       LifecycleReasonActive,
			WarningCodes:     []LifecycleWarningCode{LifecycleWarningMetadataOnlyFallback},
		},
		Rules: []RuleLifecycleMetadata{
			{
				ID:        "rules-live-01",
				PlanID:    "network-plan-live-01",
				AdapterID: "fake-live-adapter",
				Status:    LifecycleStatusActive,
				Mechanisms: []EnforcementMechanism{
					EnforcementMechanismFirewall,
					EnforcementMechanismRuntime,
				},
				Operations:       []string{"plan_rules", "apply_rules"},
				PolicySnapshot:   &PolicySnapshotIdentity{ID: "policy-live-01", Preset: PolicyPresetDenyByDefault},
				CapabilityLabels: []string{"default_deny", "domain_rules"},
				ReasonCode:       LifecycleReasonApplied,
			},
		},
		CapabilityLabels: []string{"proxy_active", "rules_active"},
		ReasonCode:       LifecycleReasonActive,
		WarningCodes:     []LifecycleWarningCode{LifecycleWarningPartialLifecycle},
	})

	assertPlanObjectKeys(t, got, []string{
		"planId",
		"adapterId",
		"status",
		"mechanisms",
		"operations",
		"policySnapshot",
		"proxy",
		"rules",
		"capabilityLabels",
		"reasonCode",
		"warningCodes",
	})
	assertPlanStringArray(t, got["mechanisms"], []string{string(EnforcementMechanismProxy), string(EnforcementMechanismFirewall)})
	assertPlanStringArray(t, got["operations"], []string{"prepare_proxy", "apply_rules"})
	assertPlanStringArray(t, got["capabilityLabels"], []string{"proxy_active", "rules_active"})

	proxy := requirePlanObject(t, got["proxy"])
	assertPlanObjectKeys(t, proxy, []string{
		"id",
		"planId",
		"adapterId",
		"status",
		"mechanisms",
		"operations",
		"policySnapshot",
		"capabilityLabels",
		"reasonCode",
		"warningCodes",
	})
	if proxy["status"] != string(LifecycleStatusActive) {
		t.Fatalf("proxy status = %#v, want active", proxy["status"])
	}
	assertPlanStringArray(t, proxy["mechanisms"], []string{string(EnforcementMechanismProxy)})
	assertPlanStringArray(t, proxy["operations"], []string{"prepare_proxy", "start_proxy"})

	rulesArray, ok := got["rules"].([]any)
	if !ok || len(rulesArray) != 1 {
		t.Fatalf("rules = %#v, want one rule lifecycle object", got["rules"])
	}
	rules := requirePlanObject(t, rulesArray[0])
	assertPlanObjectKeys(t, rules, []string{
		"id",
		"planId",
		"adapterId",
		"status",
		"mechanisms",
		"operations",
		"policySnapshot",
		"capabilityLabels",
		"reasonCode",
	})
	assertPlanStringArray(t, rules["mechanisms"], []string{string(EnforcementMechanismFirewall), string(EnforcementMechanismRuntime)})
	assertPlanStringArray(t, rules["operations"], []string{"plan_rules", "apply_rules"})
}

func TestLiveLifecycleJSONOmitsAbsentOptionalSections(t *testing.T) {
	got := mustMarshalPlanObject(t, LiveLifecycleMetadata{
		PlanID: "network-plan-minimal",
		Status: LifecycleStatusRequested,
	})

	assertPlanObjectKeys(t, got, []string{"planId", "status"})
	for _, absent := range []string{
		"adapterId",
		"mechanisms",
		"operations",
		"policySnapshot",
		"proxy",
		"rules",
		"capabilityLabels",
		"reasonCode",
		"warningCodes",
	} {
		if _, ok := got[absent]; ok {
			t.Fatalf("minimal lifecycle included %q: %#v", absent, got)
		}
	}
}

func TestLiveLifecycleJSONRedactsUnsafeDynamicValues(t *testing.T) {
	got := mustMarshalPlanObject(t, LiveLifecycleMetadata{
		PlanID:    "https://plan.internal.example.com/live?token=secret",
		AdapterID: "adapter://internal/process-handle-1234",
		Status:    LifecycleStatus(" ACTIVE "),
		Mechanisms: []EnforcementMechanism{
			EnforcementMechanismProxy,
			EnforcementMechanism("http://127.0.0.1:8080"),
		},
		Operations: []string{
			"prepare_proxy",
			"iptables -A OUTPUT -d 127.0.0.1 --dport 443",
			"/tmp/proxy.sock",
			"Authorization: Bearer ghp_secret",
		},
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-live-redacted",
			Version:   "https://policy.internal.example.com/v1?token=secret",
			Preset:    PolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: "/Users/alice/firewall.rules",
		},
		Proxy: &ProxyListenerLifecycleMetadata{
			ID:        "/tmp/proxy.sock",
			PlanID:    "network-plan-redacted",
			AdapterID: "proxy-adapter-redacted",
			Status:    LifecycleStatus(" STARTING "),
			Mechanisms: []EnforcementMechanism{
				EnforcementMechanismProxy,
			},
			Operations: []string{
				"start_proxy",
				"listen 127.0.0.1:8080",
				"/tmp/proxy.sock",
			},
			CapabilityLabels: []string{
				"http_proxy",
				"api.internal.example.com",
				"secret_broker_session_01",
			},
			ReasonCode:   LifecycleReasonCode(" ACTIVE "),
			WarningCodes: []LifecycleWarningCode{LifecycleWarningCode("https://warning.internal.example.com?token=secret")},
		},
		Rules: []RuleLifecycleMetadata{
			{
				ID:        "iptables -A OUTPUT -d 127.0.0.1 --dport 443",
				PlanID:    "network-plan-redacted",
				AdapterID: "rule-adapter-redacted",
				Status:    LifecycleStatus(" APPLYING "),
				Mechanisms: []EnforcementMechanism{
					EnforcementMechanismFirewall,
					EnforcementMechanism("nftables add rule ip filter output drop"),
				},
				Operations: []string{
					"apply_rules",
					"pfctl -f /tmp/pf.rules",
					"ENV_TOKEN=secret",
				},
				CapabilityLabels: []string{
					"default_deny",
					"process-handle-1234",
				},
				ReasonCode:   LifecycleReasonCode(" APPLIED "),
				WarningCodes: []LifecycleWarningCode{LifecycleWarningCleanupFailed},
			},
		},
		CapabilityLabels: []string{"proxy_active", "token_holder"},
		ReasonCode:       LifecycleReasonCode(" ACTIVE "),
		WarningCodes: []LifecycleWarningCode{
			LifecycleWarningPartialLifecycle,
			LifecycleWarningCode("Authorization: Bearer ghp_secret"),
		},
	})

	assertPlanObjectKeys(t, got, []string{
		"status",
		"mechanisms",
		"operations",
		"policySnapshot",
		"proxy",
		"rules",
		"capabilityLabels",
		"reasonCode",
		"warningCodes",
	})
	if _, ok := got["planId"]; ok {
		t.Fatalf("unsafe top-level plan id survived redaction: %#v", got)
	}
	if _, ok := got["adapterId"]; ok {
		t.Fatalf("unsafe top-level adapter id survived redaction: %#v", got)
	}
	assertPlanStringArray(t, got["mechanisms"], []string{string(EnforcementMechanismProxy)})
	assertPlanStringArray(t, got["operations"], []string{"prepare_proxy"})
	assertPlanStringArray(t, got["capabilityLabels"], []string{"proxy_active"})

	proxy := requirePlanObject(t, got["proxy"])
	assertPlanObjectKeys(t, proxy, []string{
		"planId",
		"adapterId",
		"status",
		"mechanisms",
		"operations",
		"capabilityLabels",
		"reasonCode",
	})
	if _, ok := proxy["id"]; ok {
		t.Fatalf("unsafe proxy id survived redaction: %#v", proxy)
	}
	assertPlanStringArray(t, proxy["operations"], []string{"start_proxy"})
	assertPlanStringArray(t, proxy["capabilityLabels"], []string{"http_proxy"})

	rulesArray := got["rules"].([]any)
	rules := requirePlanObject(t, rulesArray[0])
	assertPlanObjectKeys(t, rules, []string{
		"planId",
		"adapterId",
		"status",
		"mechanisms",
		"operations",
		"capabilityLabels",
		"reasonCode",
		"warningCodes",
	})
	if _, ok := rules["id"]; ok {
		t.Fatalf("unsafe rule id survived redaction: %#v", rules)
	}
	assertPlanStringArray(t, rules["mechanisms"], []string{string(EnforcementMechanismFirewall)})
	assertPlanStringArray(t, rules["operations"], []string{"apply_rules"})
	assertPlanStringArray(t, rules["capabilityLabels"], []string{"default_deny"})
}

func TestLiveLifecycleJSONOmitsSectionsEmptiedByRedaction(t *testing.T) {
	got := mustMarshalPlanObject(t, LiveLifecycleMetadata{
		PlanID:    "http://127.0.0.1:8080/live?token=secret",
		AdapterID: "/tmp/adapter.sock",
		Status:    LifecycleStatus("https://status.internal.example.com?token=secret"),
		Operations: []string{
			"/tmp/proxy.sock",
			"iptables -A OUTPUT -d 127.0.0.1 --dport 443",
		},
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "https://policy.internal.example.com/snapshot?token=secret",
			Version:   "/Users/alice/policy-version",
			RuleSetID: "api.internal.example.com",
		},
		Proxy: &ProxyListenerLifecycleMetadata{
			ID:               "/tmp/proxy.sock",
			Operations:       []string{"listen 127.0.0.1:8080"},
			CapabilityLabels: []string{"secret_broker_session_01"},
		},
		Rules: []RuleLifecycleMetadata{
			{
				ID:               "iptables -A OUTPUT -d 127.0.0.1 --dport 443",
				Operations:       []string{"pfctl -f /tmp/pf.rules"},
				CapabilityLabels: []string{"process-handle-1234"},
			},
		},
		CapabilityLabels: []string{"token_holder"},
		WarningCodes:     []LifecycleWarningCode{LifecycleWarningCode("Authorization: Bearer ghp_secret")},
	})

	assertPlanObjectKeys(t, got, []string{})
}

func TestLiveLifecyclePublicSchemaContainsNoUnsafeFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(LiveLifecycleMetadata{}),
		reflect.TypeOf(EnforcementCorrelation{}),
		reflect.TypeOf(InspectedRuleProof{}),
		reflect.TypeOf(RawPacketIsolationProof{}),
		reflect.TypeOf(ProxyListenerLifecycleMetadata{}),
		reflect.TypeOf(ProxyListenerLifecycleResult{}),
		reflect.TypeOf(RuleLifecycleMetadata{}),
		reflect.TypeOf(RuleLifecycleResult{}),
	}

	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" {
					continue
				}
				jsonName := planJSONName(t, typ.Name(), field)
				assertSafePlanFieldName(t, typ.Name(), field.Name, jsonName)
				assertSafePlanFieldType(t, typ.Name(), field)
			}
		})
	}
}
