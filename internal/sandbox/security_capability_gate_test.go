package sandbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityCapabilityReadinessGateContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "policy off", got: string(SandboxSecurityCapabilityReadinessGatePolicyModeOff), want: "off"},
		{name: "policy advisory", got: string(SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory), want: "advisory"},
		{name: "policy strict", got: string(SandboxSecurityCapabilityReadinessGatePolicyModeStrict), want: "strict"},
		{name: "outcome allowed", got: string(SandboxSecurityCapabilityReadinessGateOutcomeAllowed), want: "allowed"},
		{name: "outcome advisory", got: string(SandboxSecurityCapabilityReadinessGateOutcomeAdvisory), want: "advisory"},
		{name: "outcome blocked", got: string(SandboxSecurityCapabilityReadinessGateOutcomeBlocked), want: "blocked"},
		{name: "code allowed", got: string(SandboxSecurityCapabilityReadinessGateCodeAllowed), want: "security_readiness_gate_allowed"},
		{name: "code advisory", got: string(SandboxSecurityCapabilityReadinessGateCodeAdvisory), want: "security_readiness_gate_advisory"},
		{name: "code blocked", got: string(SandboxSecurityCapabilityReadinessGateCodeBlocked), want: "security_readiness_gate_blocked"},
		{name: "reason policy off", got: string(SandboxSecurityCapabilityReadinessGateReasonPolicyOff), want: "policy_off"},
		{name: "reason policy advisory", got: string(SandboxSecurityCapabilityReadinessGateReasonPolicyAdvisory), want: "policy_advisory"},
		{name: "reason readiness ready", got: string(SandboxSecurityCapabilityReadinessGateReasonReadinessReady), want: "readiness_ready"},
		{name: "reason readiness missing", got: string(SandboxSecurityCapabilityReadinessGateReasonReadinessMissing), want: "readiness_missing"},
		{name: "reason metadata only", got: string(SandboxSecurityCapabilityReadinessGateReasonMetadataOnly), want: "metadata_only"},
		{name: "reason unsupported", got: string(SandboxSecurityCapabilityReadinessGateReasonCapabilityUnsupported), want: "capability_unsupported"},
		{name: "reason blocked", got: string(SandboxSecurityCapabilityReadinessGateReasonCapabilityBlocked), want: "capability_blocked"},
		{name: "reason strict block", got: string(SandboxSecurityCapabilityReadinessGateReasonStrictBlockRequired), want: "strict_block_required"},
		{name: "reason unknown", got: string(SandboxSecurityCapabilityReadinessGateReasonUnknown), want: "unknown"},
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

func TestSecurityCapabilityReadinessGateDecisionJSONSchema(t *testing.T) {
	decision := SandboxSecurityCapabilityReadinessGateDecision{
		Code:       SandboxSecurityCapabilityReadinessGateCodeBlocked,
		Outcome:    SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		PolicyMode: SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Reason:     SandboxSecurityCapabilityReadinessGateReasonCapabilityBlocked,
		Counts: &SandboxSecurityCapabilityReadinessGateCounts{
			Total:          7,
			Ready:          1,
			Advisory:       2,
			Blocked:        1,
			Missing:        1,
			MetadataOnly:   1,
			Unsupported:    1,
			StrictBlocking: 4,
		},
	}

	got := mustMarshalObject(t, decision)
	assertObjectKeys(t, got, []string{
		"code",
		"outcome",
		"policyMode",
		"reason",
		"counts",
	}, forbiddenSecurityCapabilityReadinessGateRawFieldNames())
	assertSecurityCapabilityJSONValue(t, got, "code", "security_readiness_gate_blocked")
	assertSecurityCapabilityJSONValue(t, got, "outcome", "blocked")
	assertSecurityCapabilityJSONValue(t, got, "policyMode", "strict")
	assertSecurityCapabilityJSONValue(t, got, "reason", "capability_blocked")

	counts := got["counts"].(map[string]any)
	assertObjectKeys(t, counts, []string{
		"total",
		"ready",
		"advisory",
		"blocked",
		"missing",
		"metadataOnly",
		"unsupported",
		"strictBlocking",
	}, forbiddenSecurityCapabilityReadinessGateRawFieldNames())
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "total", 7)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "ready", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "advisory", 2)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "blocked", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "missing", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "metadataOnly", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "unsupported", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "strictBlocking", 4)
}

func TestSecurityCapabilityReadinessGateDefaultOmitsOptionalJSONFields(t *testing.T) {
	decision := mustMarshalObject(t, SandboxSecurityCapabilityReadinessGateDecision{})
	if len(decision) != 0 {
		t.Fatalf("zero gate decision = %#v, want empty object", decision)
	}

	counts := mustMarshalObject(t, SandboxSecurityCapabilityReadinessGateCounts{})
	if len(counts) != 0 {
		t.Fatalf("zero gate counts = %#v, want empty object", counts)
	}

	partial := mustMarshalObject(t, SandboxSecurityCapabilityReadinessGateDecision{
		Code:       SandboxSecurityCapabilityReadinessGateCodeAllowed,
		Outcome:    SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
		PolicyMode: SandboxSecurityCapabilityReadinessGatePolicyModeOff,
	})
	assertObjectKeys(t, partial, []string{"code", "outcome", "policyMode"}, []string{"reason", "counts"})
}

func TestSecurityCapabilityReadinessGateJSONTagsAreStable(t *testing.T) {
	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessGateCounts{}), []securityCapabilityJSONTagExpectation{
		{field: "Total", name: "total", omitempty: true},
		{field: "Ready", name: "ready", omitempty: true},
		{field: "Advisory", name: "advisory", omitempty: true},
		{field: "Blocked", name: "blocked", omitempty: true},
		{field: "Missing", name: "missing", omitempty: true},
		{field: "MetadataOnly", name: "metadataOnly", omitempty: true},
		{field: "Unsupported", name: "unsupported", omitempty: true},
		{field: "StrictBlocking", name: "strictBlocking", omitempty: true},
	})

	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessGateDecision{}), []securityCapabilityJSONTagExpectation{
		{field: "Code", name: "code", omitempty: true},
		{field: "Outcome", name: "outcome", omitempty: true},
		{field: "PolicyMode", name: "policyMode", omitempty: true},
		{field: "Reason", name: "reason", omitempty: true},
		{field: "Counts", name: "counts", omitempty: true},
	})
}

func TestSecurityCapabilityReadinessGateContractsExposeNoRawValueFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(SandboxSecurityCapabilityReadinessGateCounts{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessGateDecision{}),
	}

	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				fieldName := strings.ToLower(field.Name)
				jsonName := strings.ToLower(strings.Split(field.Tag.Get("json"), ",")[0])
				for _, forbidden := range forbiddenSecurityCapabilityReadinessGateRawFieldNameFragments() {
					if strings.Contains(fieldName, forbidden) || strings.Contains(jsonName, forbidden) {
						t.Fatalf("%s.%s json %q exposes forbidden raw gate field fragment %q", typ.Name(), field.Name, jsonName, forbidden)
					}
				}
			}
		})
	}
}

func TestSecurityCapabilityReadinessGateSerializedDecisionContainsOnlySafeMetadataFields(t *testing.T) {
	decision := SandboxSecurityCapabilityReadinessGateDecision{
		Code:       SandboxSecurityCapabilityReadinessGateCodeAdvisory,
		Outcome:    SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
		PolicyMode: SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory,
		Reason:     SandboxSecurityCapabilityReadinessGateReasonPolicyAdvisory,
		Counts: &SandboxSecurityCapabilityReadinessGateCounts{
			Total:          3,
			Ready:          1,
			Advisory:       2,
			StrictBlocking: 2,
		},
	}

	data, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	assertSecurityCapabilityReadinessGateJSONOnlySafeFields(t, decoded, "$")
}

func assertSecurityCapabilityReadinessGateJSONOnlySafeFields(t *testing.T, value any, path string) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			switch key {
			case "code", "outcome", "policyMode", "reason":
				assertSecurityCapabilitySafeEnumValue(t, requireSecurityCapabilityJSONString(t, child, childPath))
			case "counts":
				assertSecurityCapabilityReadinessGateJSONOnlySafeFields(t, child, childPath)
			case "total", "ready", "advisory", "blocked", "missing", "metadataOnly", "unsupported", "strictBlocking":
				if _, ok := child.(float64); !ok {
					t.Fatalf("%s = %#v, want JSON number", childPath, child)
				}
			default:
				t.Fatalf("%s contains unexpected gate JSON key %q", path, key)
			}
		}
	default:
		t.Fatalf("%s = %#v, want gate JSON object", path, value)
	}
}

func assertSecurityCapabilityReadinessGateJSONNumber(t *testing.T, object map[string]any, key string, want float64) {
	t.Helper()

	got, ok := object[key].(float64)
	if !ok {
		t.Fatalf("%s = %#v, want JSON number", key, object[key])
	}
	if got != want {
		t.Fatalf("%s = %#v, want %#v", key, got, want)
	}
}

func forbiddenSecurityCapabilityReadinessGateRawFieldNames() []string {
	return append(forbiddenSecurityCapabilityRawFieldNames(),
		"command",
		"commandLine",
		"cmdline",
		"provider",
		"providerPrivateMetadata",
		"worker",
		"workerEndpoint",
		"endpoint",
		"image",
	)
}

func forbiddenSecurityCapabilityReadinessGateRawFieldNameFragments() []string {
	return []string{
		"host",
		"hostname",
		"ip",
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
		"command",
		"cmdline",
		"provider",
		"private",
		"worker",
		"endpoint",
		"image",
	}
}
