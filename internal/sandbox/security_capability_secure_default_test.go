package sandbox

import (
	"encoding/json"
	"testing"
)

const (
	secureDefaultReadinessGatePolicyModeCompatibility SandboxSecurityCapabilityReadinessGatePolicyMode = "compatibility"

	secureDefaultReadinessGateReasonPolicyCompatibility SandboxSecurityCapabilityReadinessGateReasonCode = "policy_compatibility"

	secureDefaultReasonMicroVMReadinessMissing       SandboxSecurityCapabilityReasonCode = "microvm_readiness_missing"
	secureDefaultReasonMicroVMSupportMissing         SandboxSecurityCapabilityReasonCode = "microvm_support_missing"
	secureDefaultReasonWorkspaceIsolationMissing     SandboxSecurityCapabilityReasonCode = "workspace_isolation_missing"
	secureDefaultReasonWorkspaceDirectHostWorktree   SandboxSecurityCapabilityReasonCode = "workspace_direct_host_worktree"
	secureDefaultReasonNetworkEnforcementMissing     SandboxSecurityCapabilityReasonCode = "network_enforcement_missing"
	secureDefaultReasonNetworkEnforcementPlannedOnly SandboxSecurityCapabilityReasonCode = "network_enforcement_planned_only"
	secureDefaultReasonNetworkEnforcementBestEffort  SandboxSecurityCapabilityReasonCode = "network_enforcement_best_effort"
	secureDefaultReasonNetworkEnforcementPartial     SandboxSecurityCapabilityReasonCode = "network_enforcement_partial"
	secureDefaultReasonNetworkEnforcementUnsupported SandboxSecurityCapabilityReasonCode = "network_enforcement_unsupported"
	secureDefaultReasonNetworkEnforcementFailed      SandboxSecurityCapabilityReasonCode = "network_enforcement_failed"
	secureDefaultReasonCredentialActivationMissing   SandboxSecurityCapabilityReasonCode = "credential_activation_missing"
	secureDefaultReasonTemplateLockDigestMissing     SandboxSecurityCapabilityReasonCode = "template_lock_digest_missing"
	secureDefaultReasonMicroVMReady                  SandboxSecurityCapabilityReasonCode = "microvm_readiness_confirmed"
	secureDefaultReasonWorkspaceIsolationReady       SandboxSecurityCapabilityReasonCode = "workspace_isolation_confirmed"
	secureDefaultReasonNetworkEnforcementReady       SandboxSecurityCapabilityReasonCode = "network_enforcement_confirmed"
	secureDefaultReasonCredentialActivationReady     SandboxSecurityCapabilityReasonCode = "credential_activation_confirmed"
	secureDefaultReasonTemplateLockDigestReady       SandboxSecurityCapabilityReasonCode = "template_lock_digest_confirmed"

	secureDefaultFamilyWorkspace SandboxSecurityCapabilityFamily = "workspace"
	secureDefaultFamilyTemplate  SandboxSecurityCapabilityFamily = "template"

	secureDefaultCapabilityIsolatedWorkspace  SandboxSecurityCapabilityName = "isolated_workspace"
	secureDefaultCapabilityDirectHostWorktree SandboxSecurityCapabilityName = "direct_host_worktree"
	secureDefaultCapabilityTemplateLockDigest SandboxSecurityCapabilityName = "template_lock_digest"
)

func TestSecureDefaultReadinessStrictBlocksMissingAndIncompleteProofs(t *testing.T) {
	tests := []struct {
		name           string
		classification SandboxSecurityCapabilityDiagnosticClassification
		state          SandboxSecurityCapabilityReadinessState
		family         SandboxSecurityCapabilityFamily
		capability     SandboxSecurityCapabilityName
		reason         SandboxSecurityCapabilityReasonCode
		wantCounts     SandboxSecurityCapabilityReadinessGateCounts
	}{
		{
			name:           "missing microVM readiness",
			classification: SandboxSecurityCapabilityDiagnosticClassificationUnsupported,
			state:          SandboxSecurityCapabilityReadinessUnsupported,
			family:         SandboxSecurityCapabilityFamilyIsolation,
			capability:     SandboxSecurityCapabilityIsolationMicroVM,
			reason:         secureDefaultReasonMicroVMReadinessMissing,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, Unsupported: 1, StrictBlocking: 1},
		},
		{
			name:           "missing microVM support",
			classification: SandboxSecurityCapabilityDiagnosticClassificationBlocked,
			state:          SandboxSecurityCapabilityReadinessBlocked,
			family:         SandboxSecurityCapabilityFamilyIsolation,
			capability:     SandboxSecurityCapabilityIsolationMicroVM,
			reason:         secureDefaultReasonMicroVMSupportMissing,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Blocked: 1, StrictBlocking: 1},
		},
		{
			name:           "missing isolated workspace metadata",
			classification: SandboxSecurityCapabilityDiagnosticClassificationUnsupported,
			state:          SandboxSecurityCapabilityReadinessUnsupported,
			family:         secureDefaultFamilyWorkspace,
			capability:     secureDefaultCapabilityIsolatedWorkspace,
			reason:         secureDefaultReasonWorkspaceIsolationMissing,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, Unsupported: 1, StrictBlocking: 1},
		},
		{
			name:           "direct host worktree metadata",
			classification: SandboxSecurityCapabilityDiagnosticClassificationBlocked,
			state:          SandboxSecurityCapabilityReadinessBlocked,
			family:         secureDefaultFamilyWorkspace,
			capability:     secureDefaultCapabilityDirectHostWorktree,
			reason:         secureDefaultReasonWorkspaceDirectHostWorktree,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Blocked: 1, StrictBlocking: 1},
		},
		{
			name:           "missing network enforcement",
			classification: SandboxSecurityCapabilityDiagnosticClassificationUnsupported,
			state:          SandboxSecurityCapabilityReadinessUnsupported,
			family:         SandboxSecurityCapabilityFamilyNetworkPolicy,
			capability:     SandboxSecurityCapabilityNetworkDenyByDefault,
			reason:         secureDefaultReasonNetworkEnforcementMissing,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, Unsupported: 1, StrictBlocking: 1},
		},
		{
			name:           "planned-only network enforcement",
			classification: SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
			state:          SandboxSecurityCapabilityReadinessMetadataOnly,
			family:         SandboxSecurityCapabilityFamilyNetworkPolicy,
			capability:     SandboxSecurityCapabilityNetworkDenyByDefault,
			reason:         secureDefaultReasonNetworkEnforcementPlannedOnly,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, MetadataOnly: 1, StrictBlocking: 1},
		},
		{
			name:           "best-effort network enforcement",
			classification: SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
			state:          SandboxSecurityCapabilityReadinessMetadataOnly,
			family:         SandboxSecurityCapabilityFamilyNetworkPolicy,
			capability:     SandboxSecurityCapabilityNetworkDenyByDefault,
			reason:         secureDefaultReasonNetworkEnforcementBestEffort,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, MetadataOnly: 1, StrictBlocking: 1},
		},
		{
			name:           "partial network enforcement",
			classification: SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
			state:          SandboxSecurityCapabilityReadinessMetadataOnly,
			family:         SandboxSecurityCapabilityFamilyNetworkPolicy,
			capability:     SandboxSecurityCapabilityNetworkDenyByDefault,
			reason:         secureDefaultReasonNetworkEnforcementPartial,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, MetadataOnly: 1, StrictBlocking: 1},
		},
		{
			name:           "unsupported network enforcement",
			classification: SandboxSecurityCapabilityDiagnosticClassificationUnsupported,
			state:          SandboxSecurityCapabilityReadinessUnsupported,
			family:         SandboxSecurityCapabilityFamilyNetworkPolicy,
			capability:     SandboxSecurityCapabilityNetworkDenyByDefault,
			reason:         secureDefaultReasonNetworkEnforcementUnsupported,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, Unsupported: 1, StrictBlocking: 1},
		},
		{
			name:           "failed network enforcement",
			classification: SandboxSecurityCapabilityDiagnosticClassificationBlocked,
			state:          SandboxSecurityCapabilityReadinessBlocked,
			family:         SandboxSecurityCapabilityFamilyNetworkPolicy,
			capability:     SandboxSecurityCapabilityNetworkDenyByDefault,
			reason:         secureDefaultReasonNetworkEnforcementFailed,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Blocked: 1, StrictBlocking: 1},
		},
		{
			name:           "credential delivery requested without active activation proof",
			classification: SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
			state:          SandboxSecurityCapabilityReadinessMetadataOnly,
			family:         SandboxSecurityCapabilityFamilySecretDelivery,
			capability:     SandboxSecurityCapabilitySecretHTTPProxy,
			reason:         secureDefaultReasonCredentialActivationMissing,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, MetadataOnly: 1, StrictBlocking: 1},
		},
		{
			name:           "required template metadata without locked digest proof",
			classification: SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
			state:          SandboxSecurityCapabilityReadinessMetadataOnly,
			family:         secureDefaultFamilyTemplate,
			capability:     secureDefaultCapabilityTemplateLockDigest,
			reason:         secureDefaultReasonTemplateLockDigestMissing,
			wantCounts:     SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, MetadataOnly: 1, StrictBlocking: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diagnostics := secureDefaultReadinessDiagnostics(
				secureDefaultReadinessDiagnosticItem(tt.classification, tt.state, tt.family, tt.capability, tt.reason, true),
			)

			got := EvaluateSandboxSecurityCapabilityReadinessGate(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, diagnostics)
			secureDefaultAssertGateDecision(t, got, SandboxSecurityCapabilityReadinessGateDecision{
				Code:       SandboxSecurityCapabilityReadinessGateCodeBlocked,
				Outcome:    SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				PolicyMode: SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				Reason:     SandboxSecurityCapabilityReadinessGateReasonCode(tt.reason),
				Counts:     &tt.wantCounts,
			})
			secureDefaultAssertReasonCodeCounts(t, got, map[SandboxSecurityCapabilityReasonCode]int{tt.reason: 1})
		})
	}
}

func TestSecureDefaultReadinessMissingInputsStrictVersusCompatibility(t *testing.T) {
	strict := EvaluateSandboxSecurityCapabilityReadinessGate(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, SandboxSecurityCapabilityReadinessDiagnosticSummary{})
	secureDefaultAssertGateDecision(t, strict, SandboxSecurityCapabilityReadinessGateDecision{
		Code:       SandboxSecurityCapabilityReadinessGateCodeBlocked,
		Outcome:    SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		PolicyMode: SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Reason:     SandboxSecurityCapabilityReadinessGateReasonReadinessMissing,
		Counts:     &SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Missing: 1, StrictBlocking: 1},
	})

	compatibility := EvaluateSandboxSecurityCapabilityReadinessGate(secureDefaultReadinessGatePolicyModeCompatibility, SandboxSecurityCapabilityReadinessDiagnosticSummary{})
	secureDefaultAssertGateDecision(t, compatibility, SandboxSecurityCapabilityReadinessGateDecision{
		Code:       SandboxSecurityCapabilityReadinessGateCodeAdvisory,
		Outcome:    SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
		PolicyMode: secureDefaultReadinessGatePolicyModeCompatibility,
		Reason:     secureDefaultReadinessGateReasonPolicyCompatibility,
		Counts:     &SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Missing: 1, StrictBlocking: 1},
	})
	secureDefaultAssertReasonCodeCounts(t, compatibility, map[SandboxSecurityCapabilityReasonCode]int{
		SandboxSecurityCapabilityReasonCode(SandboxSecurityCapabilityReadinessGateReasonReadinessMissing): 1,
	})
}

func TestSecureDefaultReadinessCompatibilityIsAdvisoryForIncompleteProofs(t *testing.T) {
	diagnostics := secureDefaultReadinessDiagnostics(
		secureDefaultReadinessDiagnosticItem(
			SandboxSecurityCapabilityDiagnosticClassificationUnsupported,
			SandboxSecurityCapabilityReadinessUnsupported,
			SandboxSecurityCapabilityFamilyIsolation,
			SandboxSecurityCapabilityIsolationMicroVM,
			secureDefaultReasonMicroVMReadinessMissing,
			true,
		),
	)

	got := EvaluateSandboxSecurityCapabilityReadinessGate(secureDefaultReadinessGatePolicyModeCompatibility, diagnostics)
	secureDefaultAssertGateDecision(t, got, SandboxSecurityCapabilityReadinessGateDecision{
		Code:       SandboxSecurityCapabilityReadinessGateCodeAdvisory,
		Outcome:    SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
		PolicyMode: secureDefaultReadinessGatePolicyModeCompatibility,
		Reason:     secureDefaultReadinessGateReasonPolicyCompatibility,
		Counts:     &SandboxSecurityCapabilityReadinessGateCounts{Total: 1, Advisory: 1, Unsupported: 1, StrictBlocking: 1},
	})
	secureDefaultAssertReasonCodeCounts(t, got, map[SandboxSecurityCapabilityReasonCode]int{
		secureDefaultReasonMicroVMReadinessMissing: 1,
	})
}

func TestSecureDefaultReadinessProofCompleteAllowedIncludesReasonCodeCounts(t *testing.T) {
	diagnostics := secureDefaultReadinessDiagnostics(
		secureDefaultReadinessDiagnosticItem(
			SandboxSecurityCapabilityDiagnosticClassificationReady,
			SandboxSecurityCapabilityReadinessReady,
			SandboxSecurityCapabilityFamilyIsolation,
			SandboxSecurityCapabilityIsolationMicroVM,
			secureDefaultReasonMicroVMReady,
			false,
		),
		secureDefaultReadinessDiagnosticItem(
			SandboxSecurityCapabilityDiagnosticClassificationReady,
			SandboxSecurityCapabilityReadinessReady,
			secureDefaultFamilyWorkspace,
			secureDefaultCapabilityIsolatedWorkspace,
			secureDefaultReasonWorkspaceIsolationReady,
			false,
		),
		secureDefaultReadinessDiagnosticItem(
			SandboxSecurityCapabilityDiagnosticClassificationReady,
			SandboxSecurityCapabilityReadinessReady,
			SandboxSecurityCapabilityFamilyNetworkPolicy,
			SandboxSecurityCapabilityNetworkDenyByDefault,
			secureDefaultReasonNetworkEnforcementReady,
			false,
		),
		secureDefaultReadinessDiagnosticItem(
			SandboxSecurityCapabilityDiagnosticClassificationReady,
			SandboxSecurityCapabilityReadinessReady,
			SandboxSecurityCapabilityFamilySecretDelivery,
			SandboxSecurityCapabilitySecretHTTPProxy,
			secureDefaultReasonCredentialActivationReady,
			false,
		),
		secureDefaultReadinessDiagnosticItem(
			SandboxSecurityCapabilityDiagnosticClassificationReady,
			SandboxSecurityCapabilityReadinessReady,
			secureDefaultFamilyTemplate,
			secureDefaultCapabilityTemplateLockDigest,
			secureDefaultReasonTemplateLockDigestReady,
			false,
		),
	)

	got := EvaluateSandboxSecurityCapabilityReadinessGate(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, diagnostics)
	secureDefaultAssertGateDecision(t, got, SandboxSecurityCapabilityReadinessGateDecision{
		Code:       SandboxSecurityCapabilityReadinessGateCodeAllowed,
		Outcome:    SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
		PolicyMode: SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Reason:     SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
		Counts:     &SandboxSecurityCapabilityReadinessGateCounts{Total: 5, Ready: 5},
	})
	secureDefaultAssertReasonCodeCounts(t, got, map[SandboxSecurityCapabilityReasonCode]int{
		secureDefaultReasonMicroVMReady:              1,
		secureDefaultReasonWorkspaceIsolationReady:   1,
		secureDefaultReasonNetworkEnforcementReady:   1,
		secureDefaultReasonCredentialActivationReady: 1,
		secureDefaultReasonTemplateLockDigestReady:   1,
	})
}

func TestSecureDefaultReadinessDiagnosticsAndDecisionsAreRedactionSafe(t *testing.T) {
	rawValues := []string{
		"https://worker.internal.invalid:8443/control?token=raw-token",
		"worker.internal.invalid",
		"/Users/v/private/project/.git/worktrees/direct",
		"/private/var/run/firewall.sock",
		"/private/var/run/proxy.sock",
		"Authorization: Bearer raw-header-token",
		"GITHUB_TOKEN=raw-secret-value",
		"credential_value=raw-credential",
		"secret_value=raw-secret",
		"ghcr.io/acme/private-template:latest?token=raw-template-token",
		"iptables -A OUTPUT -d 169.254.169.254 -j DROP",
	}
	output := SandboxSecurityCapabilityReadinessOutput{
		Results: []SandboxSecurityCapabilityReadinessResult{
			{
				State:      SandboxSecurityCapabilityReadinessUnsupported,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityMissing,
				WarningCodes: []SandboxSecurityCapabilityWarningCode{
					SandboxSecurityCapabilityWarningCode(rawValues[5]),
				},
				Requested: &SandboxSecurityCapabilityMetadata{
					ID:         rawValues[0],
					Family:     SandboxSecurityCapabilityFamilyIsolation,
					Capability: SandboxSecurityCapabilityIsolationMicroVM,
					Source:     SandboxSecurityCapabilitySourceRequested,
					Status:     SandboxSecurityCapabilityReadinessUnsupported,
					ReasonCode: SandboxSecurityCapabilityReasonCapabilityMissing,
				},
			},
			{
				State:      SandboxSecurityCapabilityReadinessMetadataOnly,
				ReasonCode: SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
				Metadata: &SandboxSecurityCapabilityMetadata{
					ID:         rawValues[3],
					Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
					Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
					Source:     SandboxSecurityCapabilitySourceMetadata,
					Status:     SandboxSecurityCapabilityReadinessMetadataOnly,
					ReasonCode: SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
				},
			},
			{
				State:      SandboxSecurityCapabilityReadinessBlocked,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
				Requested: &SandboxSecurityCapabilityMetadata{
					ID:         rawValues[2],
					Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
					Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
					Source:     SandboxSecurityCapabilitySourceRequested,
					Status:     SandboxSecurityCapabilityReadinessBlocked,
					ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
				},
				Ready: &SandboxSecurityCapabilityMetadata{
					ID:         rawValues[4],
					Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
					Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
					Source:     SandboxSecurityCapabilitySourceRuntime,
					Status:     SandboxSecurityCapabilityReadinessBlocked,
					ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
					WarningCodes: []SandboxSecurityCapabilityWarningCode{
						SandboxSecurityCapabilityWarningBlockedByPolicy,
						SandboxSecurityCapabilityWarningCode(rawValues[10]),
					},
				},
			},
			{
				State:      SandboxSecurityCapabilityReadinessMetadataOnly,
				ReasonCode: SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
				Metadata: &SandboxSecurityCapabilityMetadata{
					ID:         rawValues[9],
					Family:     SandboxSecurityCapabilityFamilySecretDelivery,
					Capability: SandboxSecurityCapabilitySecretHTTPProxy,
					Source:     SandboxSecurityCapabilitySourceMetadata,
					Status:     SandboxSecurityCapabilityReadinessMetadataOnly,
					ReasonCode: SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
					WarningCodes: []SandboxSecurityCapabilityWarningCode{
						SandboxSecurityCapabilityWarningCode(rawValues[6]),
						SandboxSecurityCapabilityWarningCode(rawValues[7]),
						SandboxSecurityCapabilityWarningCode(rawValues[8]),
					},
				},
			},
		},
	}

	diagnostics := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(output)
	decision := EvaluateSandboxSecurityCapabilityReadinessGate(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, diagnostics)

	assertSecurityCapabilityJSONExcludes(t, diagnostics, rawValues...)
	assertSecurityCapabilityJSONExcludes(t, decision, rawValues...)
	assertSecurityCapabilityReadinessGateDecisionContainsOnlySafeFields(t, decision)
}

func secureDefaultReadinessDiagnostics(items ...SandboxSecurityCapabilityReadinessDiagnosticItem) SandboxSecurityCapabilityReadinessDiagnosticSummary {
	status := SandboxSecurityCapabilityDiagnosticSummaryStatusReady
	highestSeverity := SandboxSecurityCapabilityDiagnosticSeverityInfo
	wouldBlock := false
	for _, item := range items {
		if item.WouldBlockStrictGate {
			wouldBlock = true
			if item.Classification == SandboxSecurityCapabilityDiagnosticClassificationBlocked {
				status = SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked
			} else if status == SandboxSecurityCapabilityDiagnosticSummaryStatusReady {
				status = SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory
			}
			highestSeverity = SandboxSecurityCapabilityDiagnosticSeverityWarning
		}
	}
	return SandboxSecurityCapabilityReadinessDiagnosticSummary{
		Status:               status,
		Total:                len(items),
		HighestSeverity:      highestSeverity,
		AdvisoryOnly:         true,
		WouldBlockStrictGate: wouldBlock,
		Items:                items,
	}
}

func secureDefaultReadinessDiagnosticItem(
	classification SandboxSecurityCapabilityDiagnosticClassification,
	state SandboxSecurityCapabilityReadinessState,
	family SandboxSecurityCapabilityFamily,
	capability SandboxSecurityCapabilityName,
	reason SandboxSecurityCapabilityReasonCode,
	wouldBlock bool,
) SandboxSecurityCapabilityReadinessDiagnosticItem {
	code := SandboxSecurityCapabilityDiagnosticCodeReady
	if wouldBlock {
		code = SandboxSecurityCapabilityDiagnosticCodeUnsupported
	}
	switch classification {
	case SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly:
		code = SandboxSecurityCapabilityDiagnosticCodeMetadataOnly
	case SandboxSecurityCapabilityDiagnosticClassificationUnsupported:
		code = SandboxSecurityCapabilityDiagnosticCodeUnsupported
	case SandboxSecurityCapabilityDiagnosticClassificationBlocked:
		code = SandboxSecurityCapabilityDiagnosticCodeBlocked
	}
	severity := SandboxSecurityCapabilityDiagnosticSeverityInfo
	if wouldBlock {
		severity = SandboxSecurityCapabilityDiagnosticSeverityWarning
	}
	return SandboxSecurityCapabilityReadinessDiagnosticItem{
		Code:                 code,
		Severity:             severity,
		Classification:       classification,
		AdvisoryOnly:         true,
		WouldBlockStrictGate: wouldBlock,
		State:                state,
		Family:               family,
		Capability:           capability,
		ReasonCode:           reason,
	}
}

func secureDefaultAssertGateDecision(t *testing.T, got, want SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()

	if got.Code != want.Code {
		t.Errorf("code = %q, want %q", got.Code, want.Code)
	}
	if got.Outcome != want.Outcome {
		t.Errorf("outcome = %q, want %q", got.Outcome, want.Outcome)
	}
	if got.PolicyMode != want.PolicyMode {
		t.Errorf("policyMode = %q, want %q", got.PolicyMode, want.PolicyMode)
	}
	if got.Reason != want.Reason {
		t.Errorf("reason = %q, want %q", got.Reason, want.Reason)
	}
	if !secureDefaultGateCountsEqual(got.Counts, want.Counts) {
		t.Errorf("counts = %#v, want %#v", got.Counts, want.Counts)
	}
	if t.Failed() {
		t.FailNow()
	}
}

func secureDefaultGateCountsEqual(got, want *SandboxSecurityCapabilityReadinessGateCounts) bool {
	if got == nil || want == nil {
		return got == want
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

func secureDefaultAssertReasonCodeCounts(t *testing.T, decision SandboxSecurityCapabilityReadinessGateDecision, want map[SandboxSecurityCapabilityReasonCode]int) {
	t.Helper()

	object := secureDefaultMustMarshalObject(t, decision)
	rawCounts, ok := object["counts"].(map[string]any)
	if !ok {
		t.Fatalf("decision counts = %#v, want object with reasonCodeCounts", object["counts"])
	}
	rawReasonCounts, ok := rawCounts["reasonCodeCounts"].(map[string]any)
	if !ok {
		t.Fatalf("decision counts missing reasonCodeCounts: %#v", rawCounts)
	}
	if len(rawReasonCounts) != len(want) {
		t.Fatalf("reasonCodeCounts = %#v, want %d entries", rawReasonCounts, len(want))
	}
	for reason, rawWantCount := range want {
		got, ok := rawReasonCounts[string(reason)].(float64)
		if !ok {
			t.Fatalf("reasonCodeCounts[%q] = %#v, want JSON number", reason, rawReasonCounts[string(reason)])
		}
		if got != float64(rawWantCount) {
			t.Fatalf("reasonCodeCounts[%q] = %#v, want %d", reason, got, rawWantCount)
		}
	}
}

func secureDefaultMustMarshalObject(t *testing.T, value any) map[string]any {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(value) error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(value) error = %v; payload=%s", err, data)
	}
	return decoded
}
