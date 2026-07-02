package sandbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityCapabilityReadinessDiagnosticsContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "code ready", got: string(SandboxSecurityCapabilityDiagnosticCodeReady), want: "security_capability_ready"},
		{name: "code metadata only", got: string(SandboxSecurityCapabilityDiagnosticCodeMetadataOnly), want: "security_capability_metadata_only"},
		{name: "code unsupported", got: string(SandboxSecurityCapabilityDiagnosticCodeUnsupported), want: "security_capability_unsupported"},
		{name: "code blocked", got: string(SandboxSecurityCapabilityDiagnosticCodeBlocked), want: "security_capability_blocked"},
		{name: "code readiness missing", got: string(SandboxSecurityCapabilityDiagnosticCodeReadinessMissing), want: "security_capability_readiness_missing"},
		{name: "severity info", got: string(SandboxSecurityCapabilityDiagnosticSeverityInfo), want: "info"},
		{name: "severity warning", got: string(SandboxSecurityCapabilityDiagnosticSeverityWarning), want: "warning"},
		{name: "severity error", got: string(SandboxSecurityCapabilityDiagnosticSeverityError), want: "error"},
		{name: "classification ready", got: string(SandboxSecurityCapabilityDiagnosticClassificationReady), want: "capability_ready"},
		{name: "classification metadata only", got: string(SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly), want: "metadata_only"},
		{name: "classification unsupported", got: string(SandboxSecurityCapabilityDiagnosticClassificationUnsupported), want: "capability_unsupported"},
		{name: "classification blocked", got: string(SandboxSecurityCapabilityDiagnosticClassificationBlocked), want: "capability_blocked"},
		{name: "classification readiness missing", got: string(SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing), want: "readiness_missing"},
		{name: "summary unknown", got: string(SandboxSecurityCapabilityDiagnosticSummaryStatusUnknown), want: "unknown"},
		{name: "summary ready", got: string(SandboxSecurityCapabilityDiagnosticSummaryStatusReady), want: "ready"},
		{name: "summary advisory", got: string(SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory), want: "advisory"},
		{name: "summary blocked", got: string(SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked), want: "blocked"},
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

func TestSecurityCapabilityReadinessDiagnosticsJSONSchema(t *testing.T) {
	summary := SandboxSecurityCapabilityReadinessDiagnosticSummary{
		Status:               SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked,
		Total:                1,
		HighestSeverity:      SandboxSecurityCapabilityDiagnosticSeverityWarning,
		AdvisoryOnly:         true,
		WouldBlockStrictGate: true,
		Items: []SandboxSecurityCapabilityReadinessDiagnosticItem{
			{
				Code:                 SandboxSecurityCapabilityDiagnosticCodeBlocked,
				Severity:             SandboxSecurityCapabilityDiagnosticSeverityWarning,
				Classification:       SandboxSecurityCapabilityDiagnosticClassificationBlocked,
				AdvisoryOnly:         true,
				WouldBlockStrictGate: true,
				State:                SandboxSecurityCapabilityReadinessBlocked,
				Family:               SandboxSecurityCapabilityFamilySecretDelivery,
				Capability:           SandboxSecurityCapabilitySecretFileTmpfs,
				ReasonCode:           SandboxSecurityCapabilityReasonCapabilityBlocked,
				WarningCodes:         []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy},
			},
		},
	}

	got := mustMarshalObject(t, summary)
	assertObjectKeys(t, got, []string{
		"status",
		"total",
		"highestSeverity",
		"advisoryOnly",
		"wouldBlockStrictGate",
		"items",
	}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, got, "status", "blocked")
	assertSecurityCapabilityJSONValue(t, got, "highestSeverity", "warning")
	if got["advisoryOnly"] != true {
		t.Fatalf("advisoryOnly = %#v, want true", got["advisoryOnly"])
	}
	if got["wouldBlockStrictGate"] != true {
		t.Fatalf("wouldBlockStrictGate = %#v, want true", got["wouldBlockStrictGate"])
	}

	items := got["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("items count = %d, want 1", len(items))
	}
	assertObjectKeys(t, items[0], []string{
		"code",
		"severity",
		"classification",
		"advisoryOnly",
		"wouldBlockStrictGate",
		"state",
		"family",
		"capability",
		"reasonCode",
		"warningCodes",
	}, forbiddenSecurityCapabilityRawFieldNames())
	item := items[0].(map[string]any)
	assertSecurityCapabilityJSONValue(t, item, "code", "security_capability_blocked")
	assertSecurityCapabilityJSONValue(t, item, "severity", "warning")
	assertSecurityCapabilityJSONValue(t, item, "classification", "capability_blocked")
	assertSecurityCapabilityJSONValue(t, item, "state", "blocked")
	assertSecurityCapabilityJSONValue(t, item, "family", "secret_delivery")
	assertSecurityCapabilityJSONValue(t, item, "capability", "secret_file_tmpfs")
	assertSecurityCapabilityJSONValue(t, item, "reasonCode", "capability_blocked")
	if item["advisoryOnly"] != true {
		t.Fatalf("item advisoryOnly = %#v, want true", item["advisoryOnly"])
	}
	if item["wouldBlockStrictGate"] != true {
		t.Fatalf("item wouldBlockStrictGate = %#v, want true", item["wouldBlockStrictGate"])
	}
}

func TestSecurityCapabilityReadinessDiagnosticsDefaultMetadataOmitsOptionalJSONFields(t *testing.T) {
	summary := mustMarshalObject(t, SandboxSecurityCapabilityReadinessDiagnosticSummary{})
	assertObjectKeys(t, summary, []string{
		"status",
		"advisoryOnly",
		"wouldBlockStrictGate",
	}, []string{
		"total",
		"highestSeverity",
		"items",
	})

	item := mustMarshalObject(t, SandboxSecurityCapabilityReadinessDiagnosticItem{})
	assertObjectKeys(t, item, []string{
		"code",
		"severity",
		"classification",
		"advisoryOnly",
		"wouldBlockStrictGate",
	}, []string{
		"state",
		"family",
		"capability",
		"reasonCode",
		"warningCodes",
	})
}

func TestSecurityCapabilityReadinessDiagnosticsJSONTagsAreStable(t *testing.T) {
	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessDiagnosticSummary{}), []securityCapabilityJSONTagExpectation{
		{field: "Status", name: "status"},
		{field: "Total", name: "total", omitempty: true},
		{field: "HighestSeverity", name: "highestSeverity", omitempty: true},
		{field: "AdvisoryOnly", name: "advisoryOnly"},
		{field: "WouldBlockStrictGate", name: "wouldBlockStrictGate"},
		{field: "Items", name: "items", omitempty: true},
	})

	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessDiagnosticItem{}), []securityCapabilityJSONTagExpectation{
		{field: "Code", name: "code"},
		{field: "Severity", name: "severity"},
		{field: "Classification", name: "classification"},
		{field: "AdvisoryOnly", name: "advisoryOnly"},
		{field: "WouldBlockStrictGate", name: "wouldBlockStrictGate"},
		{field: "State", name: "state", omitempty: true},
		{field: "Family", name: "family", omitempty: true},
		{field: "Capability", name: "capability", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
		{field: "WarningCodes", name: "warningCodes", omitempty: true},
	})
}

func TestSecurityCapabilityReadinessDiagnosticsContractsExposeNoRawValueFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(SandboxSecurityCapabilityReadinessDiagnosticSummary{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessDiagnosticItem{}),
	}
	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				fieldName := strings.ToLower(field.Name)
				jsonName := strings.ToLower(strings.Split(field.Tag.Get("json"), ",")[0])
				for _, forbidden := range forbiddenSecurityCapabilityRawFieldNameFragments() {
					if strings.Contains(fieldName, forbidden) || strings.Contains(jsonName, forbidden) {
						t.Fatalf("%s.%s json %q exposes forbidden diagnostic field fragment %q", typ.Name(), field.Name, jsonName, forbidden)
					}
				}
			}
		})
	}
}

func TestSecurityCapabilitySerializedReadinessDiagnosticsContainNoUnsafeRawFieldNames(t *testing.T) {
	samples := []struct {
		name  string
		value any
	}{
		{
			name: "summary",
			value: SandboxSecurityCapabilityReadinessDiagnosticSummary{
				Status:          SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory,
				Total:           1,
				HighestSeverity: SandboxSecurityCapabilityDiagnosticSeverityWarning,
				AdvisoryOnly:    true,
				Items: []SandboxSecurityCapabilityReadinessDiagnosticItem{{
					Code:           SandboxSecurityCapabilityDiagnosticCodeMetadataOnly,
					Severity:       SandboxSecurityCapabilityDiagnosticSeverityWarning,
					Classification: SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
					AdvisoryOnly:   true,
					State:          SandboxSecurityCapabilityReadinessMetadataOnly,
					Family:         SandboxSecurityCapabilityFamilyNetworkProxy,
					Capability:     SandboxSecurityCapabilityNetworkProxyEnforcement,
					ReasonCode:     SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
				}},
			},
		},
		{
			name: "item",
			value: SandboxSecurityCapabilityReadinessDiagnosticItem{
				Code:           SandboxSecurityCapabilityDiagnosticCodeReadinessMissing,
				Severity:       SandboxSecurityCapabilityDiagnosticSeverityWarning,
				Classification: SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing,
				AdvisoryOnly:   true,
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
