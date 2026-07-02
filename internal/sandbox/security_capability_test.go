package sandbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityCapabilityReadinessContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "readiness metadata only", got: string(SandboxSecurityCapabilityReadinessMetadataOnly), want: "metadata_only"},
		{name: "readiness unsupported", got: string(SandboxSecurityCapabilityReadinessUnsupported), want: "unsupported"},
		{name: "readiness blocked", got: string(SandboxSecurityCapabilityReadinessBlocked), want: "blocked"},
		{name: "readiness ready", got: string(SandboxSecurityCapabilityReadinessReady), want: "ready"},
		{name: "family network policy", got: string(SandboxSecurityCapabilityFamilyNetworkPolicy), want: "network_policy"},
		{name: "family network proxy", got: string(SandboxSecurityCapabilityFamilyNetworkProxy), want: "network_proxy"},
		{name: "family credential proxy", got: string(SandboxSecurityCapabilityFamilyCredentialProxy), want: "credential_proxy"},
		{name: "family secret delivery", got: string(SandboxSecurityCapabilityFamilySecretDelivery), want: "secret_delivery"},
		{name: "family isolation", got: string(SandboxSecurityCapabilityFamilyIsolation), want: "isolation"},
		{name: "capability deny by default", got: string(SandboxSecurityCapabilityNetworkDenyByDefault), want: "network_deny_by_default"},
		{name: "capability network proxy", got: string(SandboxSecurityCapabilityNetworkProxyEnforcement), want: "network_proxy_enforcement"},
		{name: "capability firewall", got: string(SandboxSecurityCapabilityNetworkFirewallEnforcement), want: "network_firewall_enforcement"},
		{name: "capability runtime", got: string(SandboxSecurityCapabilityNetworkRuntimeEnforcement), want: "network_runtime_enforcement"},
		{name: "capability credential proxy", got: string(SandboxSecurityCapabilityCredentialProxy), want: "credential_proxy"},
		{name: "capability secret env", got: string(SandboxSecurityCapabilitySecretEnv), want: "secret_env"},
		{name: "capability secret file tmpfs", got: string(SandboxSecurityCapabilitySecretFileTmpfs), want: "secret_file_tmpfs"},
		{name: "capability secret ssh agent", got: string(SandboxSecurityCapabilitySecretSSHAgent), want: "secret_ssh_agent"},
		{name: "capability secret http proxy", got: string(SandboxSecurityCapabilitySecretHTTPProxy), want: "secret_http_proxy"},
		{name: "capability isolation microvm", got: string(SandboxSecurityCapabilityIsolationMicroVM), want: "isolation_microvm"},
		{name: "source requested", got: string(SandboxSecurityCapabilitySourceRequested), want: "requested"},
		{name: "source metadata", got: string(SandboxSecurityCapabilitySourceMetadata), want: "metadata"},
		{name: "source runtime", got: string(SandboxSecurityCapabilitySourceRuntime), want: "runtime"},
		{name: "source worker", got: string(SandboxSecurityCapabilitySourceWorker), want: "worker"},
		{name: "reason metadata only", got: string(SandboxSecurityCapabilityReasonMetadataOnly), want: "metadata_only"},
		{name: "reason capability missing", got: string(SandboxSecurityCapabilityReasonCapabilityMissing), want: "capability_missing"},
		{name: "reason mode unsupported", got: string(SandboxSecurityCapabilityReasonModeUnsupported), want: "mode_unsupported"},
		{name: "reason capability blocked", got: string(SandboxSecurityCapabilityReasonCapabilityBlocked), want: "capability_blocked"},
		{name: "reason capability confirmed", got: string(SandboxSecurityCapabilityReasonCapabilityConfirmed), want: "capability_confirmed"},
		{name: "reason metadata enforcement unproven", got: string(SandboxSecurityCapabilityReasonMetadataEnforcementUnproven), want: "metadata_enforcement_unproven"},
		{name: "reason metadata delivery unproven", got: string(SandboxSecurityCapabilityReasonMetadataDeliveryUnproven), want: "metadata_delivery_unproven"},
		{name: "reason unknown", got: string(SandboxSecurityCapabilityReasonUnknown), want: "unknown"},
		{name: "warning metadata not capability", got: string(SandboxSecurityCapabilityWarningMetadataNotCapability), want: "metadata_not_capability"},
		{name: "warning unsupported mode", got: string(SandboxSecurityCapabilityWarningUnsupportedMode), want: "unsupported_mode"},
		{name: "warning blocked by policy", got: string(SandboxSecurityCapabilityWarningBlockedByPolicy), want: "blocked_by_policy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
			assertSecurityCapabilitySafeEnumValue(t, tt.got)
		})
	}
}

func TestSecurityCapabilityReadinessRequestJSONSchema(t *testing.T) {
	request := SandboxSecurityCapabilityReadinessRequest{
		Requested: []SandboxSecurityCapabilityMetadata{
			{
				ID:         "requested-network-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRequested,
			},
			{
				ID:         "requested-credential-01",
				Family:     SandboxSecurityCapabilityFamilyCredentialProxy,
				Capability: SandboxSecurityCapabilityCredentialProxy,
				Mode:       SandboxSecretModeHTTPProxy,
				Source:     SandboxSecurityCapabilitySourceRequested,
			},
		},
		Ready: []SandboxSecurityCapabilityMetadata{
			{
				ID:         "ready-network-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkFirewallEnforcement,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRuntime,
			},
		},
	}

	got := mustMarshalObject(t, request)
	assertObjectKeys(t, got, []string{"requested", "ready"}, forbiddenSecurityCapabilityRawFieldNames())

	requested := got["requested"].([]any)
	if len(requested) != 2 {
		t.Fatalf("requested count = %d, want 2", len(requested))
	}
	assertObjectKeys(t, requested[0], []string{"id", "family", "capability", "mode", "source"}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, requested[0], "family", "network_policy")
	assertSecurityCapabilityJSONValue(t, requested[0], "capability", "network_deny_by_default")
	assertSecurityCapabilityJSONValue(t, requested[0], "mode", SandboxNetworkEnforcementModeFirewall)
	assertSecurityCapabilityJSONValue(t, requested[1], "family", "credential_proxy")
	assertSecurityCapabilityJSONValue(t, requested[1], "capability", "credential_proxy")
	assertSecurityCapabilityJSONValue(t, requested[1], "mode", SandboxSecretModeHTTPProxy)

	ready := got["ready"].([]any)
	if len(ready) != 1 {
		t.Fatalf("ready count = %d, want 1", len(ready))
	}
	assertObjectKeys(t, ready[0], []string{"id", "family", "capability", "mode", "source"}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, ready[0], "source", "runtime")
}

func TestSecurityCapabilityReadinessResultJSONSchema(t *testing.T) {
	result := SandboxSecurityCapabilityReadinessResult{
		State: SandboxSecurityCapabilityReadinessReady,
		Metadata: &SandboxSecurityCapabilityMetadata{
			ID:         "metadata-network-01",
			Family:     SandboxSecurityCapabilityFamilyNetworkProxy,
			Capability: SandboxSecurityCapabilityNetworkProxyEnforcement,
			Source:     SandboxSecurityCapabilitySourceMetadata,
			Status:     SandboxSecurityCapabilityReadinessMetadataOnly,
		},
		Requested: &SandboxSecurityCapabilityMetadata{
			ID:         "requested-network-01",
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		Ready: &SandboxSecurityCapabilityMetadata{
			ID:         "ready-network-01",
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkFirewallEnforcement,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceRuntime,
		},
		ReasonCode:   SandboxSecurityCapabilityReasonCapabilityConfirmed,
		WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
	}

	got := mustMarshalObject(t, result)
	assertObjectKeys(t, got, []string{
		"state",
		"metadata",
		"requested",
		"ready",
		"reasonCode",
		"warningCodes",
	}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, got, "state", "ready")
	assertSecurityCapabilityJSONValue(t, got, "reasonCode", "capability_confirmed")

	assertObjectKeys(t, got["metadata"], []string{"id", "family", "capability", "source", "status"}, forbiddenSecurityCapabilityRawFieldNames())
	assertObjectKeys(t, got["requested"], []string{"id", "family", "capability", "mode", "source"}, forbiddenSecurityCapabilityRawFieldNames())
	assertObjectKeys(t, got["ready"], []string{"id", "family", "capability", "mode", "source"}, forbiddenSecurityCapabilityRawFieldNames())

	warnings := got["warningCodes"].([]any)
	if len(warnings) != 1 || warnings[0] != "metadata_not_capability" {
		t.Fatalf("warningCodes = %#v, want metadata_not_capability", warnings)
	}
}

func TestSecurityCapabilityMetadataStatusReasonWarningJSONSchema(t *testing.T) {
	metadata := SandboxSecurityCapabilityMetadata{
		ID:           "blocked-network-01",
		Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability:   SandboxSecurityCapabilityNetworkProxyEnforcement,
		Mode:         SandboxNetworkEnforcementModeProxy,
		Source:       SandboxSecurityCapabilitySourceRuntime,
		Status:       SandboxSecurityCapabilityReadinessBlocked,
		ReasonCode:   SandboxSecurityCapabilityReasonCapabilityBlocked,
		WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy},
	}

	got := mustMarshalObject(t, metadata)
	assertObjectKeys(t, got, []string{
		"id",
		"family",
		"capability",
		"mode",
		"source",
		"status",
		"reasonCode",
		"warningCodes",
	}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, got, "status", "blocked")
	assertSecurityCapabilityJSONValue(t, got, "reasonCode", "capability_blocked")

	warnings := got["warningCodes"].([]any)
	if len(warnings) != 1 || warnings[0] != "blocked_by_policy" {
		t.Fatalf("warningCodes = %#v, want blocked_by_policy", warnings)
	}
}

func TestSecurityCapabilityReadinessOutputJSONSchema(t *testing.T) {
	output := SandboxSecurityCapabilityReadinessOutput{
		Results: []SandboxSecurityCapabilityReadinessResult{
			{
				State:      SandboxSecurityCapabilityReadinessMetadataOnly,
				ReasonCode: SandboxSecurityCapabilityReasonMetadataOnly,
			},
			{
				State:      SandboxSecurityCapabilityReadinessUnsupported,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityMissing,
			},
		},
	}

	got := mustMarshalObject(t, output)
	assertObjectKeys(t, got, []string{"results"}, forbiddenSecurityCapabilityRawFieldNames())

	results := got["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("results count = %d, want 2", len(results))
	}
	assertSecurityCapabilityJSONValue(t, results[0], "state", "metadata_only")
	assertSecurityCapabilityJSONValue(t, results[1], "state", "unsupported")
}

func TestSecurityCapabilityReadinessDefaultMetadataOmitsOptionalJSONFields(t *testing.T) {
	request := mustMarshalObject(t, SandboxSecurityCapabilityReadinessRequest{})
	if len(request) != 0 {
		t.Fatalf("zero readiness request = %#v, want empty object", request)
	}

	result := mustMarshalObject(t, SandboxSecurityCapabilityReadinessResult{})
	assertObjectKeys(t, result, []string{"state"}, []string{
		"requested",
		"ready",
		"reasonCode",
		"warningCodes",
	})

	output := mustMarshalObject(t, SandboxSecurityCapabilityReadinessOutput{})
	if len(output) != 0 {
		t.Fatalf("zero readiness output = %#v, want empty object", output)
	}

	metadata := mustMarshalObject(t, SandboxSecurityCapabilityMetadata{
		Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
	})
	assertObjectKeys(t, metadata, []string{"family", "capability"}, []string{
		"id",
		"mode",
		"source",
		"status",
		"reasonCode",
		"warningCodes",
	})
}

func TestSecurityCapabilityReadinessJSONTagsAreStable(t *testing.T) {
	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityMetadata{}), []securityCapabilityJSONTagExpectation{
		{field: "ID", name: "id", omitempty: true},
		{field: "Family", name: "family"},
		{field: "Capability", name: "capability"},
		{field: "Mode", name: "mode", omitempty: true},
		{field: "Source", name: "source", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
		{field: "WarningCodes", name: "warningCodes", omitempty: true},
	})

	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessRequest{}), []securityCapabilityJSONTagExpectation{
		{field: "Requested", name: "requested", omitempty: true},
		{field: "Ready", name: "ready", omitempty: true},
		{field: "NetworkProxySession", name: "networkProxySession", omitempty: true},
		{field: "NetworkPolicyDecisionLogs", name: "networkPolicyDecisionLogs", omitempty: true},
		{field: "CredentialProxyPlan", name: "credentialPlanMetadata", omitempty: true},
		{field: "CredentialProxySession", name: "credentialSessionMetadata", omitempty: true},
		{field: "CredentialProxyBindings", name: "credentialBindingMetadata", omitempty: true},
	})

	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessResult{}), []securityCapabilityJSONTagExpectation{
		{field: "State", name: "state"},
		{field: "Metadata", name: "metadata", omitempty: true},
		{field: "Requested", name: "requested", omitempty: true},
		{field: "Ready", name: "ready", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
		{field: "WarningCodes", name: "warningCodes", omitempty: true},
	})

	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessOutput{}), []securityCapabilityJSONTagExpectation{
		{field: "Results", name: "results", omitempty: true},
	})
}

func TestSecurityCapabilityReadinessContractsExposeNoRawValueFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(SandboxSecurityCapabilityMetadata{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessRequest{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessResult{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessOutput{}),
	}
	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				fieldName := strings.ToLower(field.Name)
				jsonName := strings.ToLower(strings.Split(field.Tag.Get("json"), ",")[0])
				for _, forbidden := range forbiddenSecurityCapabilityRawFieldNameFragments() {
					if strings.Contains(fieldName, forbidden) || strings.Contains(jsonName, forbidden) {
						t.Fatalf("%s.%s json %q exposes forbidden raw readiness field fragment %q", typ.Name(), field.Name, jsonName, forbidden)
					}
				}
			}
		})
	}
}

func TestSecurityCapabilitySerializedReadinessContainsNoUnsafeRawFieldNames(t *testing.T) {
	samples := []struct {
		name  string
		value any
	}{
		{
			name: "metadata",
			value: SandboxSecurityCapabilityMetadata{
				ID:         "ready-network-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkFirewallEnforcement,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRuntime,
			},
		},
		{
			name: "request",
			value: SandboxSecurityCapabilityReadinessRequest{
				Requested: []SandboxSecurityCapabilityMetadata{{
					ID:         "requested-credential-01",
					Family:     SandboxSecurityCapabilityFamilyCredentialProxy,
					Capability: SandboxSecurityCapabilityCredentialProxy,
					Mode:       SandboxSecretModeHTTPProxy,
					Source:     SandboxSecurityCapabilitySourceRequested,
				}},
			},
		},
		{
			name: "result",
			value: SandboxSecurityCapabilityReadinessResult{
				State:      SandboxSecurityCapabilityReadinessBlocked,
				Requested:  &SandboxSecurityCapabilityMetadata{Family: SandboxSecurityCapabilityFamilySecretDelivery, Capability: SandboxSecurityCapabilitySecretFileTmpfs},
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
			},
		},
		{
			name: "output",
			value: SandboxSecurityCapabilityReadinessOutput{
				Results: []SandboxSecurityCapabilityReadinessResult{{
					State:      SandboxSecurityCapabilityReadinessMetadataOnly,
					ReasonCode: SandboxSecurityCapabilityReasonMetadataOnly,
				}},
			},
		},
	}

	for _, tt := range samples {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			var decoded any
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			assertSecurityCapabilityJSONKeysExcludeUnsafeRawFields(t, decoded, "$")
		})
	}
}

func assertSecurityCapabilityJSONValue(t *testing.T, object any, key, want string) {
	t.Helper()

	got, ok := object.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v, want JSON object", object)
	}
	if got[key] != want {
		t.Fatalf("%s = %#v, want %q", key, got[key], want)
	}
	gotString, ok := got[key].(string)
	if !ok {
		t.Fatalf("%s = %#v, want string", key, got[key])
	}
	assertSecurityCapabilitySafeEnumValue(t, gotString)
}

func assertSecurityCapabilitySafeEnumValue(t *testing.T, value string) {
	t.Helper()

	if value == "" {
		t.Fatal("enum value must not be empty")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		t.Fatalf("enum value %q is not redaction-safe snake_case", value)
	}
}

func forbiddenSecurityCapabilityRawFieldNames() []string {
	return []string{
		"host",
		"hostname",
		"ip",
		"port",
		"url",
		"uri",
		"header",
		"headers",
		"body",
		"socketPath",
		"localPath",
		"remotePath",
		"path",
		"environment",
		"environmentValue",
		"envValue",
		"token",
		"credentialValue",
		"secretValue",
		"rawCredential",
		"rawSecret",
	}
}

func forbiddenSecurityCapabilityRawFieldNameFragments() []string {
	return []string{
		"host",
		"hostname",
		"ip",
		"port",
		"url",
		"uri",
		"header",
		"body",
		"socketpath",
		"localpath",
		"remotepath",
		"path",
		"environment",
		"envvalue",
		"token",
		"credentialvalue",
		"secretvalue",
		"raw",
	}
}

type securityCapabilityJSONTagExpectation struct {
	field     string
	name      string
	omitempty bool
}

func assertSecurityCapabilityJSONTags(t *testing.T, typ reflect.Type, expectations []securityCapabilityJSONTagExpectation) {
	t.Helper()

	if typ.NumField() != len(expectations) {
		t.Fatalf("%s field count = %d, want %d", typ.Name(), typ.NumField(), len(expectations))
	}

	expectedFields := make(map[string]struct{}, len(expectations))
	for _, expectation := range expectations {
		expectedFields[expectation.field] = struct{}{}

		field, ok := typ.FieldByName(expectation.field)
		if !ok {
			t.Fatalf("%s missing expected field %s", typ.Name(), expectation.field)
		}
		tag := field.Tag.Get("json")
		parts := strings.Split(tag, ",")
		if parts[0] != expectation.name {
			t.Fatalf("%s.%s json name = %q, want %q", typ.Name(), expectation.field, parts[0], expectation.name)
		}

		gotOmitEmpty := false
		for _, option := range parts[1:] {
			if option == "omitempty" {
				gotOmitEmpty = true
			}
		}
		if gotOmitEmpty != expectation.omitempty {
			t.Fatalf("%s.%s omitempty = %t, want %t", typ.Name(), expectation.field, gotOmitEmpty, expectation.omitempty)
		}
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if _, ok := expectedFields[field.Name]; !ok {
			t.Fatalf("%s has unlocked JSON field %s with tag %q", typ.Name(), field.Name, field.Tag.Get("json"))
		}
	}
}

func assertSecurityCapabilityJSONKeysExcludeUnsafeRawFields(t *testing.T, value any, path string) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			for _, forbidden := range forbiddenSecurityCapabilityRawFieldNames() {
				if strings.EqualFold(key, forbidden) {
					t.Fatalf("%s contains unsafe raw field name %q", path, key)
				}
			}
			assertSecurityCapabilityJSONKeysExcludeUnsafeRawFields(t, child, path+"."+key)
		}
	case []any:
		for _, child := range typed {
			assertSecurityCapabilityJSONKeysExcludeUnsafeRawFields(t, child, path+"[]")
		}
	}
}
