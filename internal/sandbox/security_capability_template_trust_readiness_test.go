package sandbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestUS006SelectedTemplateTrustReadinessInput(t *testing.T) {
	tests := []struct {
		name            string
		lock            *SandboxTemplateLockMetadata
		wantState       SandboxSecurityCapabilityReadinessState
		wantReason      SandboxSecurityCapabilityReasonCode
		wantGateOutcome SandboxSecurityCapabilityReadinessGateOutcome
	}{
		{
			name:            "trusted selected template is strict-ready input",
			lock:            us006SelectedTemplateTrustedLock(),
			wantState:       SandboxSecurityCapabilityReadinessReady,
			wantReason:      SandboxSecurityCapabilityReasonSelectedTemplateTrustConfirmed,
			wantGateOutcome: SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
		},
		{
			name:            "missing selected-template evidence blocks strict readiness",
			lock:            nil,
			wantState:       SandboxSecurityCapabilityReadinessUnsupported,
			wantReason:      SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing,
			wantGateOutcome: SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		},
		{
			name:            "advisory trust remains advisory-only and blocks strict readiness",
			lock:            us006SelectedTemplateAdvisoryLock(),
			wantState:       SandboxSecurityCapabilityReadinessMetadataOnly,
			wantReason:      SandboxSecurityCapabilityReasonSelectedTemplateTrustAdvisoryOnly,
			wantGateOutcome: SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		},
		{
			name:            "rejected trust blocks strict readiness",
			lock:            us006SelectedTemplateRejectedLock(),
			wantState:       SandboxSecurityCapabilityReadinessBlocked,
			wantReason:      SandboxSecurityCapabilityReasonSelectedTemplateTrustRejected,
			wantGateOutcome: SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		},
		{
			name:            "unavailable trust blocks strict readiness",
			lock:            us006SelectedTemplateUnavailableLock(),
			wantState:       SandboxSecurityCapabilityReadinessUnsupported,
			wantReason:      SandboxSecurityCapabilityReasonSelectedTemplateTrustUnavailable,
			wantGateOutcome: SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		},
		{
			name:            "unresolved provenance blocks strict readiness",
			lock:            us006SelectedTemplateUnresolvedLock(),
			wantState:       SandboxSecurityCapabilityReadinessBlocked,
			wantReason:      SandboxSecurityCapabilityReasonSelectedTemplateProvenanceUnresolved,
			wantGateOutcome: SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		},
		{
			name:            "provenance mismatch blocks strict readiness",
			lock:            us006SelectedTemplateMismatchedLock(),
			wantState:       SandboxSecurityCapabilityReadinessBlocked,
			wantReason:      SandboxSecurityCapabilityReasonSelectedTemplateProvenanceMismatch,
			wantGateOutcome: SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
				us006SelectedTemplateRequirement(),
				ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
					TemplateLock: tt.lock,
				}),
			)
			requireUS006SelectedTemplateResult(t, output, tt.wantState, tt.wantReason)
			diagnostics := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*output)
			decision := EvaluateSandboxSecurityCapabilityReadinessGate(SandboxSecurityCapabilityReadinessGatePolicyModeStrict, diagnostics)
			if decision.Outcome != tt.wantGateOutcome {
				t.Fatalf("strict gate outcome = %q, want %q; decision=%#v diagnostics=%#v", decision.Outcome, tt.wantGateOutcome, decision, diagnostics)
			}
			if got := decision.Counts.ReasonCodeCounts[tt.wantReason]; got != 1 {
				t.Fatalf("strict gate reason count[%s] = %d, want 1; counts=%#v", tt.wantReason, got, decision.Counts)
			}
			if tt.wantGateOutcome == SandboxSecurityCapabilityReadinessGateOutcomeBlocked &&
				decision.Reason != SandboxSecurityCapabilityReadinessGateReasonCode(tt.wantReason) {
				t.Fatalf("strict gate reason = %q, want %q; decision=%#v", decision.Reason, tt.wantReason, decision)
			}
			requireUS006NoNonTemplateReadiness(t, output)
			assertUS006SelectedTemplateJSONSafe(t, output, diagnostics, decision)
		})
	}
}

func TestUS006SelectedTemplateTrustAdvisoryModesExposeDiagnosticsOnly(t *testing.T) {
	output := EvaluateProjectedSandboxSecurityCapabilityReadiness(
		us006SelectedTemplateRequirement(),
		ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
			TemplateLock: us006SelectedTemplateRejectedLock(),
		}),
	)
	diagnostics := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*output)

	for _, mode := range []SandboxSecurityCapabilityReadinessGatePolicyMode{
		SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
		SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory,
	} {
		t.Run(string(mode), func(t *testing.T) {
			decision := EvaluateSandboxSecurityCapabilityReadinessGate(mode, diagnostics)
			if decision.Outcome != SandboxSecurityCapabilityReadinessGateOutcomeAdvisory {
				t.Fatalf("%s gate outcome = %q, want advisory; decision=%#v", mode, decision.Outcome, decision)
			}
			if decision.Code != SandboxSecurityCapabilityReadinessGateCodeAdvisory {
				t.Fatalf("%s gate code = %q, want advisory code; decision=%#v", mode, decision.Code, decision)
			}
			if got := decision.Counts.ReasonCodeCounts[SandboxSecurityCapabilityReasonSelectedTemplateTrustRejected]; got != 1 {
				t.Fatalf("%s reason count rejected = %d, want 1; counts=%#v", mode, got, decision.Counts)
			}
		})
	}
}

func TestUS006SelectedTemplateReasonCodesAreStable(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "capability selected template trust", got: string(SandboxSecurityCapabilitySelectedTemplateTrust), want: "selected_template_trust"},
		{name: "reason selected template evidence missing", got: string(SandboxSecurityCapabilityReasonSelectedTemplateEvidenceMissing), want: "selected_template_evidence_missing"},
		{name: "reason selected template trust advisory only", got: string(SandboxSecurityCapabilityReasonSelectedTemplateTrustAdvisoryOnly), want: "selected_template_trust_advisory_only"},
		{name: "reason selected template trust rejected", got: string(SandboxSecurityCapabilityReasonSelectedTemplateTrustRejected), want: "selected_template_trust_rejected"},
		{name: "reason selected template trust unavailable", got: string(SandboxSecurityCapabilityReasonSelectedTemplateTrustUnavailable), want: "selected_template_trust_unavailable"},
		{name: "reason selected template provenance unresolved", got: string(SandboxSecurityCapabilityReasonSelectedTemplateProvenanceUnresolved), want: "selected_template_provenance_unresolved"},
		{name: "reason selected template provenance mismatch", got: string(SandboxSecurityCapabilityReasonSelectedTemplateProvenanceMismatch), want: "selected_template_provenance_mismatch"},
		{name: "reason selected template trust confirmed", got: string(SandboxSecurityCapabilityReasonSelectedTemplateTrustConfirmed), want: "selected_template_trust_confirmed"},
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

func requireUS006SelectedTemplateResult(t *testing.T, output *SandboxSecurityCapabilityReadinessOutput, state SandboxSecurityCapabilityReadinessState, reason SandboxSecurityCapabilityReasonCode) {
	t.Helper()
	if output == nil {
		t.Fatal("readiness output = nil, want selected-template result")
	}
	if len(output.Results) != 1 {
		t.Fatalf("readiness result count = %d, want 1: %#v", len(output.Results), output.Results)
	}
	result := output.Results[0]
	if result.State != state {
		t.Fatalf("selected-template state = %q, want %q; result=%#v", result.State, state, result)
	}
	if result.ReasonCode != reason {
		t.Fatalf("selected-template reason = %q, want %q; result=%#v", result.ReasonCode, reason, result)
	}
	if state == SandboxSecurityCapabilityReadinessReady {
		if result.Ready == nil || result.Ready.Capability != SandboxSecurityCapabilitySelectedTemplateTrust {
			t.Fatalf("ready selected-template context = %#v, want selected-template trust", result.Ready)
		}
		return
	}
	if state == SandboxSecurityCapabilityReadinessMetadataOnly {
		if result.Metadata == nil || result.Metadata.Capability != SandboxSecurityCapabilitySelectedTemplateTrust {
			t.Fatalf("metadata selected-template context = %#v, want selected-template trust", result.Metadata)
		}
		return
	}
	if result.Requested == nil || result.Requested.Capability != SandboxSecurityCapabilitySelectedTemplateTrust {
		t.Fatalf("requested selected-template context = %#v, want selected-template trust", result.Requested)
	}
}

func requireUS006NoNonTemplateReadiness(t *testing.T, output *SandboxSecurityCapabilityReadinessOutput) {
	t.Helper()
	if output == nil {
		return
	}
	for _, result := range output.Results {
		for _, metadata := range []*SandboxSecurityCapabilityMetadata{result.Metadata, result.Requested, result.Ready} {
			if metadata == nil {
				continue
			}
			if metadata.Family != SandboxSecurityCapabilityFamilyTemplate {
				t.Fatalf("selected-template readiness emitted non-template metadata: %#v", metadata)
			}
		}
	}
}

func assertUS006SelectedTemplateJSONSafe(t *testing.T, values ...any) {
	t.Helper()
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("Marshal(selected-template readiness values) error = %v", err)
	}
	payload := string(data)
	for _, forbidden := range []string{
		"registry.example.test",
		"token=",
		"ghp_us006_secret",
		"/Users/",
		"/tmp/",
		".sock",
		"unix://",
		"Authorization",
		"secret",
		"api.internal.example.com",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("selected-template readiness leaked %q: %s", forbidden, payload)
		}
	}
}

func us006SelectedTemplateRequirement() SandboxSecurityCapabilityReadinessInput {
	return SandboxSecurityCapabilityReadinessInput{
		Requested: []SandboxSecurityCapabilityMetadata{{
			Family:     SandboxSecurityCapabilityFamilyTemplate,
			Capability: SandboxSecurityCapabilitySelectedTemplateTrust,
			Source:     SandboxSecurityCapabilitySourceRequested,
		}},
	}
}

func us006SelectedTemplateTrustedLock() *SandboxTemplateLockMetadata {
	return us006SelectedTemplateLock(SandboxTemplateTrustPolicyModeStrict, SandboxTemplateTrustPolicyDecisionTrusted, SandboxTemplateLockStatusLocked, nil, nil, nil)
}

func us006SelectedTemplateAdvisoryLock() *SandboxTemplateLockMetadata {
	return us006SelectedTemplateLock(SandboxTemplateTrustPolicyModeAdvisory, SandboxTemplateTrustPolicyDecisionAdvisory, SandboxTemplateLockStatusLocked, nil, nil, []string{
		SandboxTemplateTrustPolicyCodeMutableReference,
	})
}

func us006SelectedTemplateRejectedLock() *SandboxTemplateLockMetadata {
	return us006SelectedTemplateLock(SandboxTemplateTrustPolicyModeStrict, SandboxTemplateTrustPolicyDecisionRejected, SandboxTemplateLockStatusLocked, []string{
		SandboxTemplateTrustPolicyCodeMutableReference,
		"https://registry.example.test/template:latest?token=ghp_us006_secret",
	}, []string{
		SandboxTemplateTrustPolicyCodeMissingDigestPin,
		"/Users/alice/private/template.yaml",
	}, nil)
}

func us006SelectedTemplateUnavailableLock() *SandboxTemplateLockMetadata {
	return us006SelectedTemplateLock(SandboxTemplateTrustPolicyModeStrict, SandboxTemplateTrustPolicyDecisionUnavailable, SandboxTemplateLockStatusLocked, []string{
		SandboxTemplateTrustPolicyCodeResolverUnavailable,
	}, []string{
		SandboxTemplateTrustPolicyCodeResolverUnavailable,
	}, nil)
}

func us006SelectedTemplateUnresolvedLock() *SandboxTemplateLockMetadata {
	lock := us006SelectedTemplateTrustedLock()
	lock.RuntimeImage = &SandboxTemplateLockEntryMetadata{
		SourceKind:    SandboxTemplateLockSourceKindRuntimeImage,
		ReferenceKind: SandboxTemplateLockReferenceKindOCIImage,
		Status:        SandboxTemplateLockStatusUnresolved,
		ReasonCode:    SandboxTemplateLockReasonUnresolvedMutableReference,
		WarningCodes: []string{
			SandboxTemplateLockReasonUnresolvedMutableReference,
			"https://registry.example.test/image:latest?token=ghp_us006_secret",
		},
	}
	lock.TrustPolicy.Status = SandboxTemplateLockStatusUnresolved
	lock.TrustPolicy.Decision = SandboxTemplateTrustPolicyDecisionTrusted
	lock.TrustPolicy.ReasonCodes = []string{SandboxTemplateTrustPolicyCodeUnresolvedLockEntry}
	return SanitizeSandboxTemplateLockMetadata(lock)
}

func us006SelectedTemplateMismatchedLock() *SandboxTemplateLockMetadata {
	return us006SelectedTemplateLock(SandboxTemplateTrustPolicyModeStrict, SandboxTemplateTrustPolicyDecisionRejected, SandboxTemplateLockStatusLocked, []string{
		SandboxTemplateTrustPolicyCodeLockProvenanceMismatch,
	}, []string{
		SandboxTemplateTrustPolicyCodeLockProvenanceMismatch,
		"Authorization: Bearer ghp_us006_secret",
	}, []string{
		SandboxTemplateTrustPolicyCodeLockProvenanceMismatch,
	})
}

func us006SelectedTemplateLock(mode, decision, status string, reasonCodes, errorCodes, warningCodes []string) *SandboxTemplateLockMetadata {
	lock := &SandboxTemplateLockMetadata{
		Document:          us006SelectedTemplateLockEntry(SandboxTemplateLockSourceKindLocalFile, SandboxTemplateLockReferenceKindLocal, SandboxTemplateLockReasonDocumentDigest, "a"),
		TemplateReference: us006SelectedTemplateLockEntry(SandboxTemplateLockSourceKindTemplateReference, SandboxTemplateLockReferenceKindOCIArtifact, SandboxTemplateLockReasonTemplateReferenceDigest, "b"),
		RuntimeImage:      us006SelectedTemplateLockEntry(SandboxTemplateLockSourceKindRuntimeImage, SandboxTemplateLockReferenceKindOCIImage, SandboxTemplateLockReasonRuntimeImageDigest, "c"),
		SourceArtifact:    us006SelectedTemplateLockEntry(SandboxTemplateLockSourceKindSourceArtifact, SandboxTemplateLockReferenceKindGit, SandboxTemplateLockReasonSourceArtifactDigest, "d"),
		TrustPolicy: &SandboxTemplateTrustPolicyMetadata{
			Mode:            mode,
			Decision:        decision,
			SourceKind:      SandboxTemplateLockSourceKindLocalFile,
			ReferenceKind:   SandboxTemplateLockReferenceKindLocal,
			Status:          status,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("e", 64),
			ReasonCodes:     reasonCodes,
			ErrorCodes:      errorCodes,
			WarningCodes:    warningCodes,
		},
	}
	return SanitizeSandboxTemplateLockMetadata(lock)
}

func us006SelectedTemplateLockEntry(sourceKind, referenceKind, reasonCode, digestSeed string) *SandboxTemplateLockEntryMetadata {
	return &SandboxTemplateLockEntryMetadata{
		SourceKind:      sourceKind,
		ReferenceKind:   referenceKind,
		Status:          SandboxTemplateLockStatusLocked,
		DigestAlgorithm: "sha256",
		DigestValue:     strings.Repeat(digestSeed, 64),
		LockedAt:        "2026-07-04T06:18:17Z",
		ReasonCode:      reasonCode,
		WarningCodes: []string{
			reasonCode,
			"token=ghp_us006_secret",
		},
	}
}

func TestUS006SelectedTemplateTrustReadinessInputIsDeterministic(t *testing.T) {
	input := MergeSandboxSecurityCapabilityReadinessInputs(
		us006SelectedTemplateRequirement(),
		ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
			TemplateLock: us006SelectedTemplateMismatchedLock(),
		}),
	)
	first := EvaluateProjectedSandboxSecurityCapabilityReadiness(input)
	second := EvaluateProjectedSandboxSecurityCapabilityReadiness(input)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("selected-template readiness was not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
}
