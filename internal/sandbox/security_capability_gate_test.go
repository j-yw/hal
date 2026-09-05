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
		{name: "policy compatibility", got: string(SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility), want: "compatibility"},
		{name: "policy advisory", got: string(SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory), want: "advisory"},
		{name: "policy strict", got: string(SandboxSecurityCapabilityReadinessGatePolicyModeStrict), want: "strict"},
		{name: "outcome allowed", got: string(SandboxSecurityCapabilityReadinessGateOutcomeAllowed), want: "allowed"},
		{name: "outcome advisory", got: string(SandboxSecurityCapabilityReadinessGateOutcomeAdvisory), want: "advisory"},
		{name: "outcome blocked", got: string(SandboxSecurityCapabilityReadinessGateOutcomeBlocked), want: "blocked"},
		{name: "code allowed", got: string(SandboxSecurityCapabilityReadinessGateCodeAllowed), want: "security_readiness_gate_allowed"},
		{name: "code advisory", got: string(SandboxSecurityCapabilityReadinessGateCodeAdvisory), want: "security_readiness_gate_advisory"},
		{name: "code blocked", got: string(SandboxSecurityCapabilityReadinessGateCodeBlocked), want: "security_readiness_gate_blocked"},
		{name: "reason policy off", got: string(SandboxSecurityCapabilityReadinessGateReasonPolicyOff), want: "policy_off"},
		{name: "reason policy compatibility", got: string(SandboxSecurityCapabilityReadinessGateReasonPolicyCompatibility), want: "policy_compatibility"},
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

func TestSecurityCapabilityReadinessGate(t *testing.T) {
	blockingDiagnostics := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(SandboxSecurityCapabilityReadinessOutput{
		Results: []SandboxSecurityCapabilityReadinessResult{
			securityCapabilityDiagnosticReadyResult(),
			securityCapabilityDiagnosticMetadataOnlyResult(),
			securityCapabilityDiagnosticBlockedResult(),
			securityCapabilityDiagnosticUnsupportedResult(),
		},
	})
	readyDiagnostics := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(SandboxSecurityCapabilityReadinessOutput{
		Results: []SandboxSecurityCapabilityReadinessResult{securityCapabilityDiagnosticReadyResult()},
	})

	tests := []struct {
		name        string
		mode        SandboxSecurityCapabilityReadinessGatePolicyMode
		diagnostics SandboxSecurityCapabilityReadinessDiagnosticSummary
		want        SandboxSecurityCapabilityReadinessGateDecision
	}{
		{
			name:        "default mode is allowed even when strict would block",
			diagnostics: blockingDiagnostics,
			want: securityCapabilityReadinessGateDecisionExpectation(
				SandboxSecurityCapabilityReadinessGateCodeAllowed,
				SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
				SandboxSecurityCapabilityReadinessGatePolicyModeOff,
				SandboxSecurityCapabilityReadinessGateReasonPolicyOff,
				securityCapabilityReadinessGateMixedCounts(),
			),
		},
		{
			name:        "off mode is allowed even when strict would block",
			mode:        SandboxSecurityCapabilityReadinessGatePolicyModeOff,
			diagnostics: blockingDiagnostics,
			want: securityCapabilityReadinessGateDecisionExpectation(
				SandboxSecurityCapabilityReadinessGateCodeAllowed,
				SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
				SandboxSecurityCapabilityReadinessGatePolicyModeOff,
				SandboxSecurityCapabilityReadinessGateReasonPolicyOff,
				securityCapabilityReadinessGateMixedCounts(),
			),
		},
		{
			name:        "advisory mode returns non-blocking advisory when strict would block",
			mode:        SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory,
			diagnostics: blockingDiagnostics,
			want: securityCapabilityReadinessGateDecisionExpectation(
				SandboxSecurityCapabilityReadinessGateCodeAdvisory,
				SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
				SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory,
				SandboxSecurityCapabilityReadinessGateReasonPolicyAdvisory,
				securityCapabilityReadinessGateMixedCounts(),
			),
		},
		{
			name:        "strict mode blocks when diagnostics would block strict gate",
			mode:        SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			diagnostics: blockingDiagnostics,
			want: securityCapabilityReadinessGateDecisionExpectation(
				SandboxSecurityCapabilityReadinessGateCodeBlocked,
				SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				SandboxSecurityCapabilityReadinessGateReasonCapabilityBlocked,
				securityCapabilityReadinessGateMixedCounts(),
			),
		},
		{
			name:        "strict mode passes ready-only diagnostics",
			mode:        SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			diagnostics: readyDiagnostics,
			want: securityCapabilityReadinessGateDecisionExpectation(
				SandboxSecurityCapabilityReadinessGateCodeAllowed,
				SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
				SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
				SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Ready: 1},
			),
		},
		{
			name:        "strict mode treats missing readiness conservatively",
			mode:        SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			diagnostics: DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(SandboxSecurityCapabilityReadinessOutput{}),
			want: securityCapabilityReadinessGateDecisionExpectation(
				SandboxSecurityCapabilityReadinessGateCodeBlocked,
				SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				SandboxSecurityCapabilityReadinessGateReasonReadinessMissing,
				SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Missing: 1, StrictBlocking: 1},
			),
		},
		{
			name:        "strict mode treats metadata-only readiness conservatively",
			mode:        SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			diagnostics: DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{securityCapabilityDiagnosticMetadataOnlyResult()}}),
			want: securityCapabilityReadinessGateDecisionExpectation(
				SandboxSecurityCapabilityReadinessGateCodeBlocked,
				SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonMetadataEnforcementUnproven),
				SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, MetadataOnly: 1, StrictBlocking: 1},
			),
		},
		{
			name:        "strict mode treats unsupported readiness conservatively",
			mode:        SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			diagnostics: DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{securityCapabilityDiagnosticUnsupportedResult()}}),
			want: securityCapabilityReadinessGateDecisionExpectation(
				SandboxSecurityCapabilityReadinessGateCodeBlocked,
				SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonModeUnsupported),
				SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, Unsupported: 1, StrictBlocking: 1},
			),
		},
		{
			name:        "strict mode treats blocked readiness conservatively",
			mode:        SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			diagnostics: DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(SandboxSecurityCapabilityReadinessOutput{Results: []SandboxSecurityCapabilityReadinessResult{securityCapabilityDiagnosticBlockedResult()}}),
			want: securityCapabilityReadinessGateDecisionExpectation(
				SandboxSecurityCapabilityReadinessGateCodeBlocked,
				SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				SandboxSecurityCapabilityReadinessGateReasonCapabilityBlocked,
				SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Blocked: 1, StrictBlocking: 1},
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EvaluateSandboxSecurityCapabilityReadinessGate(tt.mode, tt.diagnostics)
			assertSecurityCapabilityReadinessGateDecision(t, got, tt.want)
			assertSecurityCapabilityReadinessGateDecisionContainsOnlySafeFields(t, got)
			assertSecurityCapabilityJSONExcludes(t, got, securityCapabilityDiagnosticUnsafeValueFixtures()...)
		})
	}

	t.Run("readiness output path derives diagnostics before gating", func(t *testing.T) {
		got := EvaluateSandboxSecurityCapabilityReadinessGateFromOutput(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, SandboxSecurityCapabilityReadinessOutput{
			Results: []SandboxSecurityCapabilityReadinessResult{securityCapabilityDiagnosticReadyResult()},
		})
		want := securityCapabilityReadinessGateDecisionExpectation(
			SandboxSecurityCapabilityReadinessGateCodeAllowed,
			SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
			SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
			SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Ready: 1},
		)
		assertSecurityCapabilityReadinessGateDecision(t, got, want)
		assertSecurityCapabilityReadinessGateDecisionContainsOnlySafeFields(t, got)
		assertSecurityCapabilityJSONExcludes(t, got, securityCapabilityDiagnosticUnsafeValueFixtures()...)
	})

	t.Run("diagnostics pointer path treats nil diagnostics as missing readiness", func(t *testing.T) {
		got := EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, nil)
		want := securityCapabilityReadinessGateDecisionExpectation(
			SandboxSecurityCapabilityReadinessGateCodeBlocked,
			SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			SandboxSecurityCapabilityReadinessGateReasonReadinessMissing,
			SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Missing: 1, StrictBlocking: 1},
		)
		assertSecurityCapabilityReadinessGateDecision(t, got, want)
		assertSecurityCapabilityReadinessGateDecisionContainsOnlySafeFields(t, got)
	})

	t.Run("diagnostics pointer path matches value diagnostics path", func(t *testing.T) {
		got := EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, &readyDiagnostics)
		want := EvaluateSandboxSecurityCapabilityReadinessGate(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, readyDiagnostics)
		assertSecurityCapabilityReadinessGateDecision(t, got, want)
		assertSecurityCapabilityReadinessGateDecisionContainsOnlySafeFields(t, got)
	})
}

func TestSecurityCapabilityReadinessGateDeterministic(t *testing.T) {
	output := SandboxSecurityCapabilityReadinessOutput{
		Results: []SandboxSecurityCapabilityReadinessResult{
			securityCapabilityDiagnosticUnsupportedResult(),
			securityCapabilityDiagnosticReadyResult(),
			securityCapabilityDiagnosticMetadataOnlyResult(),
			securityCapabilityDiagnosticBlockedResult(),
		},
	}
	diagnostics := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(output)
	want := EvaluateSandboxSecurityCapabilityReadinessGate(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, diagnostics)

	for i := 0; i < 10; i++ {
		got := EvaluateSandboxSecurityCapabilityReadinessGate(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, diagnostics)
		assertSecurityCapabilityReadinessGateDecision(t, got, want)

		fromOutput := EvaluateSandboxSecurityCapabilityReadinessGateFromOutput(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, output)
		assertSecurityCapabilityReadinessGateDecision(t, fromOutput, want)
	}
}

func TestSecurityCapabilityReadinessGateDoesNotCopyRawDiagnosticValues(t *testing.T) {
	rawValues := []string{
		"https://api.example.invalid/private?token=raw-token",
		"api.example.invalid",
		"Authorization: Bearer raw-header-token",
		"GITHUB_TOKEN=raw-secret",
		"/private/var/run/credential-proxy.sock",
		"command=curl https://api.example.invalid",
	}
	diagnostics := SandboxSecurityCapabilityReadinessDiagnosticSummary{
		Status:               SandboxSecurityCapabilityDiagnosticSummaryStatus(rawValues[0]),
		Total:                1,
		HighestSeverity:      SandboxSecurityCapabilityDiagnosticSeverity(rawValues[1]),
		AdvisoryOnly:         true,
		WouldBlockStrictGate: true,
		Items: []SandboxSecurityCapabilityReadinessDiagnosticItem{{
			Code:                 SandboxSecurityCapabilityDiagnosticCode(rawValues[2]),
			Severity:             SandboxSecurityCapabilityDiagnosticSeverity(rawValues[3]),
			Classification:       SandboxSecurityCapabilityDiagnosticClassification(rawValues[4]),
			AdvisoryOnly:         true,
			WouldBlockStrictGate: true,
			State:                SandboxSecurityCapabilityReadinessState(rawValues[5]),
			Family:               SandboxSecurityCapabilityFamily(rawValues[0]),
			Capability:           SandboxSecurityCapabilityName(rawValues[1]),
			ReasonCode:           SandboxSecurityCapabilityReasonCode(rawValues[2]),
			WarningCodes: []SandboxSecurityCapabilityWarningCode{
				SandboxSecurityCapabilityWarningCode(rawValues[3]),
			},
		}},
	}

	got := EvaluateSandboxSecurityCapabilityReadinessGate(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, diagnostics)
	want := securityCapabilityReadinessGateDecisionExpectation(
		SandboxSecurityCapabilityReadinessGateCodeBlocked,
		SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		SandboxSecurityCapabilityReadinessGateReasonStrictBlockRequired,
		SandboxSecurityCapabilityReadinessGateCounts{Total: 1, StrictBlocking: 1},
	)
	assertSecurityCapabilityReadinessGateDecision(t, got, want)
	assertSecurityCapabilityReadinessGateDecisionContainsOnlySafeFields(t, got)
	assertSecurityCapabilityJSONExcludes(t, got, rawValues...)
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
			ReasonCodeCounts: map[SandboxSecurityCapabilityReasonCode]int{
				SandboxSecurityCapabilityReasonCapabilityBlocked: 1,
				SandboxSecurityCapabilityReasonCapabilityMissing: 2,
			},
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
		"reasonCodeCounts",
	}, forbiddenSecurityCapabilityReadinessGateRawFieldNames())
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "total", 7)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "ready", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "advisory", 2)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "blocked", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "missing", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "metadataOnly", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "unsupported", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, counts, "strictBlocking", 4)
	reasonCodeCounts := counts["reasonCodeCounts"].(map[string]any)
	assertObjectKeys(t, reasonCodeCounts, []string{
		"capability_blocked",
		"capability_missing",
	}, forbiddenSecurityCapabilityReadinessGateRawFieldNames())
	assertSecurityCapabilityReadinessGateJSONNumber(t, reasonCodeCounts, "capability_blocked", 1)
	assertSecurityCapabilityReadinessGateJSONNumber(t, reasonCodeCounts, "capability_missing", 2)
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
		{field: "ReasonCodeCounts", name: "reasonCodeCounts", omitempty: true},
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

func securityCapabilityReadinessGateDecisionExpectation(
	code SandboxSecurityCapabilityReadinessGateCode,
	outcome SandboxSecurityCapabilityReadinessGateOutcome,
	policyMode SandboxSecurityCapabilityReadinessGatePolicyMode,
	reason SandboxSecurityCapabilityReadinessGateReasonCode,
	counts SandboxSecurityCapabilityReadinessGateCounts,
) SandboxSecurityCapabilityReadinessGateDecision {
	return SandboxSecurityCapabilityReadinessGateDecision{
		Code:       code,
		Outcome:    outcome,
		PolicyMode: policyMode,
		Reason:     reason,
		Counts:     &counts,
	}
}

func securityCapabilityReadinessGateMixedCounts() SandboxSecurityCapabilityReadinessGateCounts {
	return SandboxSecurityCapabilityReadinessGateCounts{
		Total:          4,
		Ready:          1,
		Advisory:       2,
		Blocked:        1,
		MetadataOnly:   1,
		Unsupported:    1,
		StrictBlocking: 3,
	}
}

func assertSecurityCapabilityReadinessGateDecision(t *testing.T, got, want SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()

	if got.Code != want.Code {
		t.Fatalf("code = %q, want %q", got.Code, want.Code)
	}
	if got.Outcome != want.Outcome {
		t.Fatalf("outcome = %q, want %q", got.Outcome, want.Outcome)
	}
	if got.PolicyMode != want.PolicyMode {
		t.Fatalf("policyMode = %q, want %q", got.PolicyMode, want.PolicyMode)
	}
	if got.Reason != want.Reason {
		t.Fatalf("reason = %q, want %q", got.Reason, want.Reason)
	}
	if !securityCapabilityReadinessGateCountsEqual(got.Counts, want.Counts) {
		t.Fatalf("counts = %#v, want %#v", got.Counts, want.Counts)
	}
}

func securityCapabilityReadinessGateCountsEqual(got, want *SandboxSecurityCapabilityReadinessGateCounts) bool {
	if got == nil || want == nil {
		return got == want
	}
	if got.Total != want.Total ||
		got.Ready != want.Ready ||
		got.Advisory != want.Advisory ||
		got.Blocked != want.Blocked ||
		got.Missing != want.Missing ||
		got.MetadataOnly != want.MetadataOnly ||
		got.Unsupported != want.Unsupported ||
		got.StrictBlocking != want.StrictBlocking {
		return false
	}
	if want.ReasonCodeCounts == nil {
		return true
	}
	return reflect.DeepEqual(got.ReasonCodeCounts, want.ReasonCodeCounts)
}

func assertSecurityCapabilityReadinessGateDecisionContainsOnlySafeFields(t *testing.T, decision SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()

	data, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("marshal decision failed: %v", err)
	}
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal decision failed: %v", err)
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
			case "reasonCodeCounts":
				assertSecurityCapabilityReadinessGateReasonCodeCountsJSONOnlySafeFields(t, child, childPath)
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

func assertSecurityCapabilityReadinessGateReasonCodeCountsJSONOnlySafeFields(t *testing.T, value any, path string) {
	t.Helper()

	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want reason-code count object", path, value)
	}
	for key, child := range object {
		assertSecurityCapabilitySafeEnumValue(t, key)
		if _, ok := child.(float64); !ok {
			t.Fatalf("%s.%s = %#v, want JSON number", path, key, child)
		}
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
