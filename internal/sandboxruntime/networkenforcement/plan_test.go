package networkenforcement

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPlanConstantsAreStable(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "source runtime", got: string(PlanSourceRuntime), want: "runtime"},
		{name: "source worker", got: string(PlanSourceWorker), want: "worker"},
		{name: "source microvm", got: string(PlanSourceMicroVM), want: "microvm"},
		{name: "preset deny by default", got: string(PolicyPresetDenyByDefault), want: "deny_by_default"},
		{name: "preset allow listed", got: string(PolicyPresetAllowListed), want: "allow_listed"},
		{name: "preset legacy default", got: string(PolicyPresetLegacyDefault), want: "legacy_default"},
		{name: "allowlist disabled", got: string(AllowlistModeDisabled), want: "disabled"},
		{name: "allowlist audit", got: string(AllowlistModeAudit), want: "audit"},
		{name: "allowlist enforce", got: string(AllowlistModeEnforce), want: "enforce"},
		{name: "rule category domain", got: string(AllowlistRuleCategoryDomain), want: "domain"},
		{name: "rule category endpoint", got: string(AllowlistRuleCategoryEndpoint), want: "endpoint"},
		{name: "rule category private range", got: string(AllowlistRuleCategoryPrivateRange), want: "private_range"},
		{name: "rule category metadata endpoint", got: string(AllowlistRuleCategoryMetadataEndpoint), want: "metadata_endpoint"},
		{name: "posture allow", got: string(PostureAllow), want: "allow"},
		{name: "posture block", got: string(PostureBlock), want: "block"},
		{name: "posture audit", got: string(PostureAudit), want: "audit"},
		{name: "default deny", got: string(DefaultPostureDenyByDefault), want: "deny_by_default"},
		{name: "default allow", got: string(DefaultPostureAllowByDefault), want: "allow_by_default"},
		{name: "mechanism proxy", got: string(EnforcementMechanismProxy), want: "proxy"},
		{name: "mechanism firewall", got: string(EnforcementMechanismFirewall), want: "firewall"},
		{name: "proxy route", got: string(ProxyRoutingModeRouteViaProxy), want: "route_via_proxy"},
		{name: "proxy block", got: string(ProxyRoutingModeBlock), want: "block"},
		{name: "firewall apply", got: string(FirewallIntentModeApply), want: "apply"},
		{name: "firewall audit", got: string(FirewallIntentModeAuditOnly), want: "audit_only"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestPlanJSONRepresentsRequiredNetworkPosture(t *testing.T) {
	plan := Plan{
		ID:        "network-plan-01",
		Source:    PlanSourceRuntime,
		Operation: "create",
		PolicySnapshot: &PolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "v1",
			Preset:    PolicyPresetAllowListed,
			RuleSetID: "rules-01",
		},
		DefaultPosture: DefaultPostureDenyByDefault,
		Allowlist: &AllowlistPlan{
			Mode:      AllowlistModeEnforce,
			RuleSetID: "rules-01",
			RuleIDs:   []string{"rule-domain-01", "rule-endpoint-01"},
			RuleCategories: []AllowlistRuleCategory{
				AllowlistRuleCategoryDomain,
				AllowlistRuleCategoryEndpoint,
			},
			Operations: []string{"connect", "resolve"},
		},
		Category: &CategoryPosturePlan{
			PrivateNetwork:   PostureBlock,
			MetadataEndpoint: PostureBlock,
		},
		RawProtocols: &RawProtocolPlan{
			TCP:  PostureBlock,
			UDP:  PostureBlock,
			ICMP: PostureBlock,
		},
		Proxy: &ProxyRoutingIntent{
			HTTP:           ProxyRoutingModeRouteViaProxy,
			HTTPS:          ProxyRoutingModeRouteViaProxy,
			ProxySessionID: "proxy-session-01",
			Mechanism:      EnforcementMechanismProxy,
			Operations:     []string{"http_connect", "https_connect"},
		},
		Firewall: &FirewallIntent{
			Mode:       FirewallIntentModeApply,
			Mechanism:  EnforcementMechanismFirewall,
			Operations: []string{"default_deny", "block_private_network", "block_metadata_endpoint", "block_raw_protocols"},
		},
	}

	got := mustMarshalPlanObject(t, plan)
	assertPlanObjectKeys(t, got, []string{
		"id",
		"source",
		"operation",
		"policySnapshot",
		"defaultPosture",
		"allowlist",
		"category",
		"rawProtocols",
		"proxy",
		"firewall",
	})
	if got["defaultPosture"] != string(DefaultPostureDenyByDefault) {
		t.Fatalf("defaultPosture = %#v, want %q", got["defaultPosture"], DefaultPostureDenyByDefault)
	}

	assertPlanObjectKeys(t, got["policySnapshot"], []string{"id", "version", "preset", "ruleSetId"})
	assertPlanObjectKeys(t, got["allowlist"], []string{"mode", "ruleSetId", "ruleIds", "ruleCategories", "operations"})
	assertPlanObjectKeys(t, got["category"], []string{"privateNetwork", "metadataEndpoint"})
	assertPlanObjectKeys(t, got["rawProtocols"], []string{"tcp", "udp", "icmp"})
	assertPlanObjectKeys(t, got["proxy"], []string{"http", "https", "proxySessionId", "mechanism", "operations"})
	assertPlanObjectKeys(t, got["firewall"], []string{"mode", "mechanism", "operations"})

	category := got["category"].(map[string]any)
	if category["privateNetwork"] != string(PostureBlock) {
		t.Fatalf("privateNetwork = %#v, want block", category["privateNetwork"])
	}
	if category["metadataEndpoint"] != string(PostureBlock) {
		t.Fatalf("metadataEndpoint = %#v, want block", category["metadataEndpoint"])
	}
	rawProtocols := got["rawProtocols"].(map[string]any)
	for _, protocol := range []string{"tcp", "udp", "icmp"} {
		if rawProtocols[protocol] != string(PostureBlock) {
			t.Fatalf("%s posture = %#v, want block", protocol, rawProtocols[protocol])
		}
	}
	proxy := got["proxy"].(map[string]any)
	if proxy["http"] != string(ProxyRoutingModeRouteViaProxy) || proxy["https"] != string(ProxyRoutingModeRouteViaProxy) {
		t.Fatalf("proxy routing = %#v, want HTTP/HTTPS route_via_proxy", proxy)
	}
}

func TestPlanJSONOmitsAbsentOptionalSections(t *testing.T) {
	got := mustMarshalPlanObject(t, Plan{
		ID:             "network-plan-02",
		DefaultPosture: DefaultPostureNoPolicy,
	})

	assertPlanObjectKeys(t, got, []string{"id", "defaultPosture"})
	for _, absent := range []string{
		"source",
		"operation",
		"policySnapshot",
		"allowlist",
		"category",
		"rawProtocols",
		"proxy",
		"firewall",
	} {
		if _, ok := got[absent]; ok {
			t.Fatalf("minimal plan included %q: %#v", absent, got)
		}
	}
}

func TestPlanPublicSchemaContainsNoUnsafeFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(PolicySnapshotIdentity{}),
		reflect.TypeOf(Plan{}),
		reflect.TypeOf(AllowlistPlan{}),
		reflect.TypeOf(CategoryPosturePlan{}),
		reflect.TypeOf(RawProtocolPlan{}),
		reflect.TypeOf(ProxyRoutingIntent{}),
		reflect.TypeOf(FirewallIntent{}),
	}

	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" {
					continue
				}
				jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
				if jsonName == "" || jsonName == "-" {
					t.Fatalf("%s.%s must have a public JSON name", typ.Name(), field.Name)
				}
				if !strings.Contains(field.Tag.Get("json"), "omitempty") {
					t.Fatalf("%s.%s json tag %q must use omitempty for additive schema fields", typ.Name(), field.Name, field.Tag.Get("json"))
				}
				assertSafePlanFieldName(t, typ.Name(), field.Name, jsonName)
				assertSafePlanFieldType(t, typ.Name(), field)
			}
		})
	}
}

func assertSafePlanFieldName(t *testing.T, typeName, fieldName, jsonName string) {
	t.Helper()
	fieldLower := strings.ToLower(fieldName)
	jsonLower := strings.ToLower(jsonName)
	for _, forbidden := range forbiddenPlanRawFieldNameFragments() {
		if strings.Contains(fieldLower, forbidden) || strings.Contains(jsonLower, forbidden) {
			t.Fatalf("%s.%s json %q exposes forbidden raw field fragment %q", typeName, fieldName, jsonName, forbidden)
		}
	}
}

func assertSafePlanFieldType(t *testing.T, typeName string, field reflect.StructField) {
	t.Helper()
	typ := field.Type
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Map {
		t.Fatalf("%s.%s must not expose map-shaped arbitrary public metadata", typeName, field.Name)
	}
	if typ.Kind() == reflect.Interface {
		t.Fatalf("%s.%s must not expose interface-shaped arbitrary public metadata", typeName, field.Name)
	}
	if typ.Kind() == reflect.Struct {
		switch typ {
		case reflect.TypeOf(PolicySnapshotIdentity{}),
			reflect.TypeOf(AllowlistPlan{}),
			reflect.TypeOf(CategoryPosturePlan{}),
			reflect.TypeOf(RawProtocolPlan{}),
			reflect.TypeOf(ProxyRoutingIntent{}),
			reflect.TypeOf(FirewallIntent{}):
			return
		default:
			t.Fatalf("%s.%s exposes unsupported public struct type %s", typeName, field.Name, typ)
		}
	}
}

func mustMarshalPlanObject(t *testing.T, value any) map[string]any {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", payload, err)
	}
	for _, forbidden := range forbiddenPlanPayloadFragments() {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("plan JSON %s leaked forbidden fragment %q", payload, forbidden)
		}
	}
	return object
}

func assertPlanObjectKeys(t *testing.T, value any, wantKeys []string) {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value %#v is %T, want object", value, value)
	}
	if len(object) != len(wantKeys) {
		t.Fatalf("object keys = %#v, want exactly %#v", object, wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := object[key]; !ok {
			t.Fatalf("object keys = %#v, want key %q", object, key)
		}
		for _, forbidden := range forbiddenPlanRawFieldNameFragments() {
			if strings.Contains(strings.ToLower(key), forbidden) {
				t.Fatalf("JSON key %q exposes forbidden raw field fragment %q", key, forbidden)
			}
		}
	}
}

func forbiddenPlanRawFieldNameFragments() []string {
	return []string{
		"address",
		"body",
		"credential",
		"destination",
		"env",
		"header",
		"host",
		"hostname",
		"interface",
		"listener",
		"localpath",
		"packet",
		"peer",
		"port",
		"remotepath",
		"secret",
		"socket",
		"token",
		"url",
		"uri",
		"value",
	}
}

func forbiddenPlanPayloadFragments() []string {
	return []string{
		"example.com",
		"127.0.0.1",
		"169.254.169.254",
		":443",
		"http://",
		"https://",
		"/tmp/",
		"socketPath",
		"Authorization",
		"token",
		"secret",
	}
}
