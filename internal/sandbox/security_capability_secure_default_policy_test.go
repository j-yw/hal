package sandbox

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestUS001SecureDefaultReadinessPolicyClassifiesIncompleteEvidence(t *testing.T) {
	tests := []struct {
		name            string
		output          SandboxSecurityCapabilityReadinessOutput
		wantOutcome     SandboxSecurityCapabilityReadinessGateOutcome
		wantReason      SandboxSecurityCapabilityReadinessGateReasonCode
		wantCounts      SandboxSecurityCapabilityReadinessGateCounts
		wantReasonCount SandboxSecurityCapabilityReasonCode
	}{
		{
			name:            "proof complete",
			output:          us001SecureDefaultPolicyReadinessOutput(us001SecureDefaultPolicyReadyResult()),
			wantOutcome:     SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
			wantReason:      SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
			wantCounts:      SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Ready: 1},
			wantReasonCount: SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed,
		},
		{
			name:            "proof missing",
			output:          SandboxSecurityCapabilityReadinessOutput{},
			wantOutcome:     SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			wantReason:      SandboxSecurityCapabilityReadinessGateReasonReadinessMissing,
			wantCounts:      SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Missing: 1, StrictBlocking: 1},
			wantReasonCount: SandboxSecurityCapabilityReasonReadinessMissing,
		},
		{
			name:            "metadata only",
			output:          us001SecureDefaultPolicyReadinessOutput(us001SecureDefaultPolicyMetadataOnlyResult(SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly)),
			wantOutcome:     SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			wantReason:      SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly),
			wantCounts:      SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, MetadataOnly: 1, StrictBlocking: 1},
			wantReasonCount: SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly,
		},
		{
			name:            "advisory only",
			output:          us001SecureDefaultPolicyReadinessOutput(us001SecureDefaultPolicyAdvisoryOnlyResult()),
			wantOutcome:     SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			wantReason:      SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonSelectedTemplateTrustAdvisoryOnly),
			wantCounts:      SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, MetadataOnly: 1, StrictBlocking: 1},
			wantReasonCount: SandboxSecurityCapabilityReasonSelectedTemplateTrustAdvisoryOnly,
		},
		{
			name:            "failed",
			output:          us001SecureDefaultPolicyReadinessOutput(us001SecureDefaultPolicyBlockedResult(SandboxSecurityCapabilityReasonNetworkEnforcementFailed)),
			wantOutcome:     SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			wantReason:      SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonNetworkEnforcementFailed),
			wantCounts:      SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Blocked: 1, StrictBlocking: 1},
			wantReasonCount: SandboxSecurityCapabilityReasonNetworkEnforcementFailed,
		},
		{
			name:            "unsupported",
			output:          us001SecureDefaultPolicyReadinessOutput(us001SecureDefaultPolicyUnsupportedResult(SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported)),
			wantOutcome:     SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			wantReason:      SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported),
			wantCounts:      SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, Unsupported: 1, StrictBlocking: 1},
			wantReasonCount: SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported,
		},
		{
			name:            "compatibility only",
			output:          us001SecureDefaultPolicyReadinessOutput(us001SecureDefaultPolicyUnsupportedResult(SandboxSecurityCapabilityReasonCapabilityMissing)),
			wantOutcome:     SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			wantReason:      SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonCapabilityMissing),
			wantCounts:      SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, Unsupported: 1, StrictBlocking: 1},
			wantReasonCount: SandboxSecurityCapabilityReasonCapabilityMissing,
		},
		{
			name:            "partial",
			output:          us001SecureDefaultPolicyReadinessOutput(us001SecureDefaultPolicyMetadataOnlyResult(SandboxSecurityCapabilityReasonNetworkEnforcementPartial)),
			wantOutcome:     SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			wantReason:      SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonNetworkEnforcementPartial),
			wantCounts:      SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, MetadataOnly: 1, StrictBlocking: 1},
			wantReasonCount: SandboxSecurityCapabilityReasonNetworkEnforcementPartial,
		},
		{
			name:            "warning bearing",
			output:          us001SecureDefaultPolicyReadinessOutput(us001SecureDefaultPolicyWarningBearingReadyResult()),
			wantOutcome:     SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			wantReason:      SandboxSecurityCapabilityReadinessGateReasonCode(SandboxSecurityCapabilityReasonWarningBearing),
			wantCounts:      SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, Unsupported: 1, StrictBlocking: 1},
			wantReasonCount: SandboxSecurityCapabilityReasonWarningBearing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diagnostics := ProjectSandboxSecureDefaultReadinessDiagnostics(tt.output)
			decision := EvaluateSandboxSecureDefaultReadiness(tt.output)

			if decision.Code != us001SecureDefaultPolicyDecisionCode(tt.wantOutcome) {
				t.Fatalf("decision.code = %q, want outcome-compatible code for %q", decision.Code, tt.wantOutcome)
			}
			if decision.Outcome != tt.wantOutcome {
				t.Fatalf("decision.outcome = %q, want %q", decision.Outcome, tt.wantOutcome)
			}
			if decision.PolicyMode != SandboxSecurityCapabilityReadinessGatePolicyModeStrict {
				t.Fatalf("decision.policyMode = %q, want strict", decision.PolicyMode)
			}
			if decision.Reason != tt.wantReason {
				t.Fatalf("decision.reason = %q, want %q", decision.Reason, tt.wantReason)
			}
			if !us001SecureDefaultPolicyCountsEqual(decision.Counts, tt.wantCounts) {
				t.Fatalf("decision.counts = %#v, want %#v", decision.Counts, tt.wantCounts)
			}
			if got := decision.Counts.ReasonCodeCounts[tt.wantReasonCount]; got != 1 {
				t.Fatalf("decision.reasonCodeCounts[%q] = %d, want 1", tt.wantReasonCount, got)
			}
			if diagnostics.Total != tt.wantCounts.Total {
				t.Fatalf("diagnostics.total = %d, want %d", diagnostics.Total, tt.wantCounts.Total)
			}
			us001SecureDefaultPolicyAssertSafeDiagnosticLabels(t, diagnostics)
		})
	}
}

func TestUS001SecureDefaultReadinessPolicyIsDeterministicAndSanitized(t *testing.T) {
	rawValues := []string{
		"https://worker.internal.invalid/control?token=raw-us001-token",
		"Authorization: Bearer raw-us001-token",
		"/Users/v/private/us001/worktree",
		"/private/var/run/us001-firewall.sock",
		"iptables -A OUTPUT -d 169.254.169.254 -j DROP",
		"credential_value=raw-us001-credential",
		"ghcr.io/acme/private-template:latest?token=raw-us001-template",
	}
	output := us001SecureDefaultPolicyReadinessOutput(
		us001SecureDefaultPolicyWarningBearingReadyResult(),
		us001SecureDefaultPolicyMetadataOnlyResult(SandboxSecurityCapabilityReasonNetworkEnforcementPartial),
		us001SecureDefaultPolicyReadyResult(),
	)
	output.Results = append(output.Results, SandboxSecurityCapabilityReadinessResult{
		State:      SandboxSecurityCapabilityReadinessReady,
		ReasonCode: SandboxSecurityCapabilityReasonCode(rawValues[1]),
		Requested: &SandboxSecurityCapabilityMetadata{
			ID:         rawValues[0],
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       rawValues[2],
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		Ready: &SandboxSecurityCapabilityMetadata{
			ID:         rawValues[3],
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       rawValues[4],
			Source:     SandboxSecurityCapabilitySourceRuntime,
			Status:     SandboxSecurityCapabilityReadinessReady,
			ReasonCode: SandboxSecurityCapabilityReasonCode(rawValues[5]),
			WarningCodes: []SandboxSecurityCapabilityWarningCode{
				SandboxSecurityCapabilityWarningCode(rawValues[6]),
			},
		},
	})

	firstDiagnostics := ProjectSandboxSecureDefaultReadinessDiagnostics(output)
	firstDecision := EvaluateSandboxSecureDefaultReadiness(output)
	for i := 0; i < 8; i++ {
		if got := ProjectSandboxSecureDefaultReadinessDiagnostics(output); !reflect.DeepEqual(got, firstDiagnostics) {
			t.Fatalf("diagnostics changed on iteration %d:\ngot:  %#v\nwant: %#v", i, got, firstDiagnostics)
		}
		if got := EvaluateSandboxSecureDefaultReadiness(output); !reflect.DeepEqual(got, firstDecision) {
			t.Fatalf("decision changed on iteration %d:\ngot:  %#v\nwant: %#v", i, got, firstDecision)
		}
	}

	if firstDecision.Outcome != SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
		t.Fatalf("decision.outcome = %q, want blocked", firstDecision.Outcome)
	}
	assertSecurityCapabilityJSONExcludes(t, firstDiagnostics, rawValues...)
	assertSecurityCapabilityJSONExcludes(t, firstDecision, rawValues...)
	us001SecureDefaultPolicyAssertSafeDiagnosticLabels(t, firstDiagnostics)
	us001SecureDefaultPolicyAssertSafeDecisionLabels(t, firstDecision)
}

func us001SecureDefaultPolicyReadinessOutput(results ...SandboxSecurityCapabilityReadinessResult) SandboxSecurityCapabilityReadinessOutput {
	return SandboxSecurityCapabilityReadinessOutput{Results: results}
}

func us001SecureDefaultPolicyReadyResult() SandboxSecurityCapabilityReadinessResult {
	return SandboxSecurityCapabilityReadinessResult{
		State:      SandboxSecurityCapabilityReadinessReady,
		ReasonCode: SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed,
		Requested: &SandboxSecurityCapabilityMetadata{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeProxyFirewall,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		Ready: &SandboxSecurityCapabilityMetadata{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeProxyFirewall,
			Source:     SandboxSecurityCapabilitySourceRuntime,
			Status:     SandboxSecurityCapabilityReadinessReady,
			ReasonCode: SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed,
		},
	}
}

func us001SecureDefaultPolicyWarningBearingReadyResult() SandboxSecurityCapabilityReadinessResult {
	result := us001SecureDefaultPolicyReadyResult()
	result.WarningCodes = []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningUnsupportedMode}
	result.Ready.WarningCodes = []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy}
	return result
}

func us001SecureDefaultPolicyMetadataOnlyResult(reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReadinessResult {
	return SandboxSecurityCapabilityReadinessResult{
		State:      SandboxSecurityCapabilityReadinessMetadataOnly,
		ReasonCode: reason,
		Metadata: &SandboxSecurityCapabilityMetadata{
			Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability:   SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:         SandboxNetworkEnforcementModeProxyFirewall,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   reason,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
		WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
	}
}

func us001SecureDefaultPolicyAdvisoryOnlyResult() SandboxSecurityCapabilityReadinessResult {
	return SandboxSecurityCapabilityReadinessResult{
		State:      SandboxSecurityCapabilityReadinessMetadataOnly,
		ReasonCode: SandboxSecurityCapabilityReasonSelectedTemplateTrustAdvisoryOnly,
		Metadata: &SandboxSecurityCapabilityMetadata{
			Family:       SandboxSecurityCapabilityFamilyTemplate,
			Capability:   SandboxSecurityCapabilitySelectedTemplateTrust,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonSelectedTemplateTrustAdvisoryOnly,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
		WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
	}
}

func us001SecureDefaultPolicyBlockedResult(reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReadinessResult {
	return SandboxSecurityCapabilityReadinessResult{
		State:      SandboxSecurityCapabilityReadinessBlocked,
		ReasonCode: reason,
		Requested: &SandboxSecurityCapabilityMetadata{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeProxyFirewall,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		Ready: &SandboxSecurityCapabilityMetadata{
			Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability:   SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:         SandboxNetworkEnforcementModeProxyFirewall,
			Source:       SandboxSecurityCapabilitySourceRuntime,
			Status:       SandboxSecurityCapabilityReadinessBlocked,
			ReasonCode:   reason,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy},
		},
	}
}

func us001SecureDefaultPolicyUnsupportedResult(reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReadinessResult {
	return SandboxSecurityCapabilityReadinessResult{
		State:      SandboxSecurityCapabilityReadinessUnsupported,
		ReasonCode: reason,
		Requested: &SandboxSecurityCapabilityMetadata{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeProxyFirewall,
			Source:     SandboxSecurityCapabilitySourceRequested,
			Status:     SandboxSecurityCapabilityReadinessUnsupported,
			ReasonCode: reason,
		},
	}
}

func us001SecureDefaultPolicyDecisionCode(outcome SandboxSecurityCapabilityReadinessGateOutcome) SandboxSecurityCapabilityReadinessGateCode {
	if outcome == SandboxSecurityCapabilityReadinessGateOutcomeAllowed {
		return SandboxSecurityCapabilityReadinessGateCodeAllowed
	}
	return SandboxSecurityCapabilityReadinessGateCodeBlocked
}

func us001SecureDefaultPolicyCountsEqual(got *SandboxSecurityCapabilityReadinessGateCounts, want SandboxSecurityCapabilityReadinessGateCounts) bool {
	if got == nil {
		return false
	}
	return got.Total == want.Total &&
		got.Ready == want.Ready &&
		got.Advisory == want.Advisory &&
		got.Blocked == want.Blocked &&
		got.Missing == want.Missing &&
		got.MetadataOnly == want.MetadataOnly &&
		got.Unsupported == want.Unsupported &&
		got.StrictBlocking == want.StrictBlocking
}

func us001SecureDefaultPolicyAssertSafeDiagnosticLabels(t *testing.T, diagnostics SandboxSecurityCapabilityReadinessDiagnosticSummary) {
	t.Helper()
	data, err := json.Marshal(diagnostics)
	if err != nil {
		t.Fatalf("json.Marshal(diagnostics) error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(diagnostics) error = %v", err)
	}
	for _, item := range diagnostics.Items {
		for _, value := range []string{
			string(item.Code),
			string(item.Severity),
			string(item.Classification),
			string(item.State),
			string(item.Family),
			string(item.Capability),
			string(item.ReasonCode),
		} {
			if value != "" {
				assertSecurityCapabilitySafeEnumValue(t, value)
			}
		}
	}
}

func us001SecureDefaultPolicyAssertSafeDecisionLabels(t *testing.T, decision SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()
	for _, value := range []string{
		string(decision.Code),
		string(decision.Outcome),
		string(decision.PolicyMode),
		string(decision.Reason),
	} {
		if value != "" {
			assertSecurityCapabilitySafeEnumValue(t, value)
		}
	}
	if decision.Counts == nil {
		t.Fatal("decision.counts = nil, want aggregate counts")
	}
	for reason := range decision.Counts.ReasonCodeCounts {
		assertSecurityCapabilitySafeEnumValue(t, string(reason))
	}
}
