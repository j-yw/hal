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

func TestSecurityCapabilityReadinessDiagnosticsDeriveStateMatrix(t *testing.T) {
	tests := []struct {
		name       string
		output     SandboxSecurityCapabilityReadinessOutput
		wantStatus SandboxSecurityCapabilityDiagnosticSummaryStatus
		wantBlock  bool
		wantItems  []securityCapabilityReadinessDiagnosticItemExpectation
	}{
		{
			name:       "ready",
			output:     SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{securityCapabilityDiagnosticReadyResult()}},
			wantStatus: SandboxSecurityCapabilityDiagnosticSummaryStatusReady,
			wantBlock:  false,
			wantItems: []securityCapabilityReadinessDiagnosticItemExpectation{
				securityCapabilityDiagnosticReadyExpectation(),
			},
		},
		{
			name:       "metadata only",
			output:     SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{securityCapabilityDiagnosticMetadataOnlyResult()}},
			wantStatus: SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory,
			wantBlock:  true,
			wantItems: []securityCapabilityReadinessDiagnosticItemExpectation{
				securityCapabilityDiagnosticMetadataOnlyExpectation(),
			},
		},
		{
			name:       "unsupported",
			output:     SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{securityCapabilityDiagnosticUnsupportedResult()}},
			wantStatus: SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory,
			wantBlock:  true,
			wantItems: []securityCapabilityReadinessDiagnosticItemExpectation{
				securityCapabilityDiagnosticUnsupportedExpectation(),
			},
		},
		{
			name:       "blocked",
			output:     SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{securityCapabilityDiagnosticBlockedResult()}},
			wantStatus: SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked,
			wantBlock:  true,
			wantItems: []securityCapabilityReadinessDiagnosticItemExpectation{
				securityCapabilityDiagnosticBlockedExpectation(),
			},
		},
		{
			name:       "missing",
			output:     SandboxSecurityCapabilityReadinessOutput{},
			wantStatus: SandboxSecurityCapabilityDiagnosticSummaryStatusUnknown,
			wantBlock:  true,
			wantItems: []securityCapabilityReadinessDiagnosticItemExpectation{
				{
					code:           SandboxSecurityCapabilityDiagnosticCodeReadinessMissing,
					severity:       SandboxSecurityCapabilityDiagnosticSeverityWarning,
					classification: SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing,
					wouldBlock:     true,
					reason:         SandboxSecurityCapabilityReasonReadinessMissing,
				},
			},
		},
		{
			name: "mixed",
			output: SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{
				securityCapabilityDiagnosticReadyResult(),
				securityCapabilityDiagnosticMetadataOnlyResult(),
				securityCapabilityDiagnosticBlockedResult(),
				securityCapabilityDiagnosticUnsupportedResult(),
			}},
			wantStatus: SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked,
			wantBlock:  true,
			wantItems:  securityCapabilityDiagnosticMixedExpectations(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(tt.output)
			assertSecurityCapabilityReadinessDiagnosticSummary(t, got, tt.wantStatus, tt.wantBlock, tt.wantItems)
			assertSecurityCapabilityJSONExcludes(t, got, securityCapabilityDiagnosticUnsafeValueFixtures()...)
		})
	}
}

func TestSecurityCapabilityReadinessDiagnosticsOrderingIsDeterministic(t *testing.T) {
	firstInput := SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{
		securityCapabilityDiagnosticReadyResult(),
		securityCapabilityDiagnosticMetadataOnlyResult(),
		securityCapabilityDiagnosticBlockedResult(),
		securityCapabilityDiagnosticUnsupportedResult(),
	}}
	reorderedInput := SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{
		securityCapabilityDiagnosticUnsupportedResult(),
		securityCapabilityDiagnosticBlockedResult(),
		securityCapabilityDiagnosticReadyResult(),
		securityCapabilityDiagnosticMetadataOnlyResult(),
	}}

	first := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(firstInput)
	second := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(firstInput)
	reordered := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(reorderedInput)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary() is not deterministic:\nfirst:  %#v\nsecond: %#v", first, second)
	}
	if !reflect.DeepEqual(first, reordered) {
		t.Fatalf("diagnostic order changed for reordered equivalent input:\nfirst:     %#v\nreordered: %#v", first, reordered)
	}

	assertSecurityCapabilityReadinessDiagnosticSummary(t, first, SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked, true, securityCapabilityDiagnosticMixedExpectations())
}

func TestSecurityCapabilityReadinessDiagnosticsSanitizeUnsafeReadinessOutput(t *testing.T) {
	output := SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{
		securityCapabilityDiagnosticReadyResult(),
		securityCapabilityDiagnosticMetadataOnlyResult(),
		securityCapabilityDiagnosticBlockedResult(),
		securityCapabilityDiagnosticUnsupportedResult(),
		{
			State: SandboxSecurityCapabilityReadinessReady,
			Requested: &SandboxSecurityCapabilityMetadata{
				ID:         "config:///Users/v/project/.hal/config.yaml?header=Authorization",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       "https://metadata.google.internal/latest",
				Source:     SandboxSecurityCapabilitySourceRequested,
			},
			Ready: &SandboxSecurityCapabilityMetadata{
				ID:         "/var/run/docker.sock",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       "/tmp/hal.sock",
				Source:     SandboxSecurityCapabilitySourceRuntime,
				Status:     SandboxSecurityCapabilityReadinessReady,
				ReasonCode: SandboxSecurityCapabilityReasonCode("Authorization: Bearer raw-token"),
				WarningCodes: []SandboxSecurityCapabilityWarningCode{
					SandboxSecurityCapabilityWarningCode("body={\"password\":\"hunter2\"}"),
				},
			},
			ReasonCode: SandboxSecurityCapabilityReasonCode("curl -H Authorization https://api.example.invalid"),
			WarningCodes: []SandboxSecurityCapabilityWarningCode{
				SandboxSecurityCapabilityWarningCode("GITHUB_TOKEN=raw-secret"),
			},
		},
	}}

	got := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(output)
	assertSecurityCapabilityReadinessDiagnosticSummary(t, got, SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked, true, securityCapabilityDiagnosticMixedExpectations())
	assertSecurityCapabilityJSONExcludes(t, got, securityCapabilityDiagnosticUnsafeValueFixtures()...)
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

type securityCapabilityReadinessDiagnosticItemExpectation struct {
	code           SandboxSecurityCapabilityDiagnosticCode
	severity       SandboxSecurityCapabilityDiagnosticSeverity
	classification SandboxSecurityCapabilityDiagnosticClassification
	wouldBlock     bool
	state          SandboxSecurityCapabilityReadinessState
	family         SandboxSecurityCapabilityFamily
	capability     SandboxSecurityCapabilityName
	reason         SandboxSecurityCapabilityReasonCode
	warnings       []SandboxSecurityCapabilityWarningCode
}

func assertSecurityCapabilityReadinessDiagnosticSummary(t *testing.T, got SandboxSecurityCapabilityReadinessDiagnosticSummary, status SandboxSecurityCapabilityDiagnosticSummaryStatus, wouldBlock bool, wantItems []securityCapabilityReadinessDiagnosticItemExpectation) {
	t.Helper()

	if got.Status != status {
		t.Fatalf("status = %q, want %q", got.Status, status)
	}
	if got.Total != len(wantItems) {
		t.Fatalf("total = %d, want %d", got.Total, len(wantItems))
	}
	if got.AdvisoryOnly != true {
		t.Fatalf("advisoryOnly = %t, want true", got.AdvisoryOnly)
	}
	if got.WouldBlockStrictGate != wouldBlock {
		t.Fatalf("wouldBlockStrictGate = %t, want %t", got.WouldBlockStrictGate, wouldBlock)
	}
	wantSeverity := SandboxSecurityCapabilityDiagnosticSeverityInfo
	for _, item := range wantItems {
		if sandboxSecurityCapabilityDiagnosticSeverityRank(item.severity) > sandboxSecurityCapabilityDiagnosticSeverityRank(wantSeverity) {
			wantSeverity = item.severity
		}
	}
	if got.HighestSeverity != wantSeverity {
		t.Fatalf("highestSeverity = %q, want %q", got.HighestSeverity, wantSeverity)
	}
	if len(got.Items) != len(wantItems) {
		t.Fatalf("item count = %d, want %d: %#v", len(got.Items), len(wantItems), got.Items)
	}
	for i := range wantItems {
		assertSecurityCapabilityReadinessDiagnosticItem(t, i, got.Items[i], wantItems[i])
	}
}

func assertSecurityCapabilityReadinessDiagnosticItem(t *testing.T, index int, got SandboxSecurityCapabilityReadinessDiagnosticItem, want securityCapabilityReadinessDiagnosticItemExpectation) {
	t.Helper()

	if got.Code != want.code {
		t.Fatalf("item[%d].code = %q, want %q", index, got.Code, want.code)
	}
	if got.Severity != want.severity {
		t.Fatalf("item[%d].severity = %q, want %q", index, got.Severity, want.severity)
	}
	if got.Classification != want.classification {
		t.Fatalf("item[%d].classification = %q, want %q", index, got.Classification, want.classification)
	}
	if got.AdvisoryOnly != true {
		t.Fatalf("item[%d].advisoryOnly = %t, want true", index, got.AdvisoryOnly)
	}
	if got.WouldBlockStrictGate != want.wouldBlock {
		t.Fatalf("item[%d].wouldBlockStrictGate = %t, want %t", index, got.WouldBlockStrictGate, want.wouldBlock)
	}
	if got.State != want.state {
		t.Fatalf("item[%d].state = %q, want %q", index, got.State, want.state)
	}
	if got.Family != want.family {
		t.Fatalf("item[%d].family = %q, want %q", index, got.Family, want.family)
	}
	if got.Capability != want.capability {
		t.Fatalf("item[%d].capability = %q, want %q", index, got.Capability, want.capability)
	}
	if got.ReasonCode != want.reason {
		t.Fatalf("item[%d].reasonCode = %q, want %q", index, got.ReasonCode, want.reason)
	}
	if !reflect.DeepEqual(got.WarningCodes, want.warnings) {
		t.Fatalf("item[%d].warningCodes = %#v, want %#v", index, got.WarningCodes, want.warnings)
	}
}

func securityCapabilityDiagnosticMixedExpectations() []securityCapabilityReadinessDiagnosticItemExpectation {
	return []securityCapabilityReadinessDiagnosticItemExpectation{
		securityCapabilityDiagnosticBlockedExpectation(),
		securityCapabilityDiagnosticUnsupportedExpectation(),
		securityCapabilityDiagnosticMetadataOnlyExpectation(),
		securityCapabilityDiagnosticReadyExpectation(),
	}
}

func securityCapabilityDiagnosticReadyExpectation() securityCapabilityReadinessDiagnosticItemExpectation {
	return securityCapabilityReadinessDiagnosticItemExpectation{
		code:           SandboxSecurityCapabilityDiagnosticCodeReady,
		severity:       SandboxSecurityCapabilityDiagnosticSeverityInfo,
		classification: SandboxSecurityCapabilityDiagnosticClassificationReady,
		wouldBlock:     false,
		state:          SandboxSecurityCapabilityReadinessReady,
		family:         SandboxSecurityCapabilityFamilyNetworkPolicy,
		capability:     SandboxSecurityCapabilityNetworkDenyByDefault,
		reason:         SandboxSecurityCapabilityReasonCapabilityConfirmed,
	}
}

func securityCapabilityDiagnosticMetadataOnlyExpectation() securityCapabilityReadinessDiagnosticItemExpectation {
	return securityCapabilityReadinessDiagnosticItemExpectation{
		code:           SandboxSecurityCapabilityDiagnosticCodeMetadataOnly,
		severity:       SandboxSecurityCapabilityDiagnosticSeverityWarning,
		classification: SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
		wouldBlock:     true,
		state:          SandboxSecurityCapabilityReadinessMetadataOnly,
		family:         SandboxSecurityCapabilityFamilyNetworkProxy,
		capability:     SandboxSecurityCapabilityNetworkProxyEnforcement,
		reason:         SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		warnings:       []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
	}
}

func securityCapabilityDiagnosticUnsupportedExpectation() securityCapabilityReadinessDiagnosticItemExpectation {
	return securityCapabilityReadinessDiagnosticItemExpectation{
		code:           SandboxSecurityCapabilityDiagnosticCodeUnsupported,
		severity:       SandboxSecurityCapabilityDiagnosticSeverityWarning,
		classification: SandboxSecurityCapabilityDiagnosticClassificationUnsupported,
		wouldBlock:     true,
		state:          SandboxSecurityCapabilityReadinessUnsupported,
		family:         SandboxSecurityCapabilityFamilyCredentialProxy,
		capability:     SandboxSecurityCapabilityCredentialProxy,
		reason:         SandboxSecurityCapabilityReasonModeUnsupported,
		warnings:       []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningUnsupportedMode},
	}
}

func securityCapabilityDiagnosticBlockedExpectation() securityCapabilityReadinessDiagnosticItemExpectation {
	return securityCapabilityReadinessDiagnosticItemExpectation{
		code:           SandboxSecurityCapabilityDiagnosticCodeBlocked,
		severity:       SandboxSecurityCapabilityDiagnosticSeverityWarning,
		classification: SandboxSecurityCapabilityDiagnosticClassificationBlocked,
		wouldBlock:     true,
		state:          SandboxSecurityCapabilityReadinessBlocked,
		family:         SandboxSecurityCapabilityFamilySecretDelivery,
		capability:     SandboxSecurityCapabilitySecretFileTmpfs,
		reason:         SandboxSecurityCapabilityReasonCapabilityBlocked,
		warnings:       []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy},
	}
}

func securityCapabilityDiagnosticReadyResult() SandboxSecurityCapabilityReadinessResult {
	return SandboxSecurityCapabilityReadinessResult{
		State: SandboxSecurityCapabilityReadinessReady,
		Requested: &SandboxSecurityCapabilityMetadata{
			ID:         "https://api.example.invalid/private?token=raw-token",
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceRequested,
			Status:     SandboxSecurityCapabilityReadinessReady,
			ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{
				SandboxSecurityCapabilityWarningCode("Authorization: Bearer raw-token"),
			},
		},
		Ready: &SandboxSecurityCapabilityMetadata{
			ID:         "runtime://host.example.invalid/var/run/provider.sock",
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceRuntime,
			Status:     SandboxSecurityCapabilityReadinessReady,
			ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
		},
		ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
	}
}

func securityCapabilityDiagnosticMetadataOnlyResult() SandboxSecurityCapabilityReadinessResult {
	return SandboxSecurityCapabilityReadinessResult{
		State: SandboxSecurityCapabilityReadinessMetadataOnly,
		Metadata: &SandboxSecurityCapabilityMetadata{
			ID:         "/Users/v/project/.hal/config.yaml",
			Family:     SandboxSecurityCapabilityFamilyNetworkProxy,
			Capability: SandboxSecurityCapabilityNetworkProxyEnforcement,
			Source:     SandboxSecurityCapabilitySourceMetadata,
			Status:     SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode: SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{
				SandboxSecurityCapabilityWarningMetadataNotCapability,
				SandboxSecurityCapabilityWarningCode("10.0.0.7:8080"),
			},
		},
		ReasonCode: SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		WarningCodes: []SandboxSecurityCapabilityWarningCode{
			SandboxSecurityCapabilityWarningMetadataNotCapability,
		},
	}
}

func securityCapabilityDiagnosticUnsupportedResult() SandboxSecurityCapabilityReadinessResult {
	return SandboxSecurityCapabilityReadinessResult{
		State: SandboxSecurityCapabilityReadinessUnsupported,
		Requested: &SandboxSecurityCapabilityMetadata{
			ID:         "http://169.254.169.254/latest/meta-data",
			Family:     SandboxSecurityCapabilityFamilyCredentialProxy,
			Capability: SandboxSecurityCapabilityCredentialProxy,
			Mode:       SandboxSecretModeHTTPProxy,
			Source:     SandboxSecurityCapabilitySourceRequested,
			Status:     SandboxSecurityCapabilityReadinessUnsupported,
			ReasonCode: SandboxSecurityCapabilityReasonModeUnsupported,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{
				SandboxSecurityCapabilityWarningUnsupportedMode,
				SandboxSecurityCapabilityWarningCode("body=password=hunter2"),
			},
		},
		ReasonCode: SandboxSecurityCapabilityReasonModeUnsupported,
		WarningCodes: []SandboxSecurityCapabilityWarningCode{
			SandboxSecurityCapabilityWarningUnsupportedMode,
		},
	}
}

func securityCapabilityDiagnosticBlockedResult() SandboxSecurityCapabilityReadinessResult {
	return SandboxSecurityCapabilityReadinessResult{
		State: SandboxSecurityCapabilityReadinessBlocked,
		Requested: &SandboxSecurityCapabilityMetadata{
			ID:         "ssh://worker.internal.example.invalid:2222/tmp/secret.sock",
			Family:     SandboxSecurityCapabilityFamilySecretDelivery,
			Capability: SandboxSecurityCapabilitySecretFileTmpfs,
			Mode:       SandboxSecretModeFileTmpfs,
			Source:     SandboxSecurityCapabilitySourceRequested,
			Status:     SandboxSecurityCapabilityReadinessBlocked,
			ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{
				SandboxSecurityCapabilityWarningBlockedByPolicy,
			},
		},
		Ready: &SandboxSecurityCapabilityMetadata{
			ID:         "file:///private/var/run/credential-proxy.sock",
			Family:     SandboxSecurityCapabilityFamilySecretDelivery,
			Capability: SandboxSecurityCapabilitySecretFileTmpfs,
			Mode:       SandboxSecretModeFileTmpfs,
			Source:     SandboxSecurityCapabilitySourceWorker,
			Status:     SandboxSecurityCapabilityReadinessBlocked,
			ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{
				SandboxSecurityCapabilityWarningBlockedByPolicy,
				SandboxSecurityCapabilityWarningCode("command=curl https://api.example.invalid"),
			},
		},
		ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
		WarningCodes: []SandboxSecurityCapabilityWarningCode{
			SandboxSecurityCapabilityWarningBlockedByPolicy,
		},
	}
}

func securityCapabilityDiagnosticUnsafeValueFixtures() []string {
	return []string{
		"https://api.example.invalid/private?token=raw-token",
		"api.example.invalid",
		"host.example.invalid",
		"worker.internal.example.invalid",
		"127.0.0.1:8443",
		"10.0.0.7",
		"10.0.0.7:8080",
		"169.254.169.254",
		"fd00::1",
		":2222",
		"/Users/v/project",
		".hal/config.yaml",
		"/var/run/provider.sock",
		"/tmp/secret.sock",
		"/private/var/run/credential-proxy.sock",
		"/var/run/docker.sock",
		"/tmp/hal.sock",
		"curl -H Authorization",
		"command=curl",
		"Authorization: Bearer raw-token",
		"GITHUB_TOKEN",
		"raw-secret",
		"raw-token",
		"password=hunter2",
		"body={\"password\":\"hunter2\"}",
		"header=Authorization",
		"https://metadata.google.internal/latest",
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
