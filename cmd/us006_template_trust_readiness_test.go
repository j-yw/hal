package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestUS006RuntimeStatusProjectsSelectedTemplateTrustReadinessInput(t *testing.T) {
	tests := []struct {
		name           string
		lock           *sandbox.SandboxTemplateLockMetadata
		wantState      sandbox.SandboxSecurityCapabilityReadinessState
		wantReason     sandbox.SandboxSecurityCapabilityReasonCode
		wantGate       sandbox.SandboxSecurityCapabilityReadinessGateOutcome
		wantGateCode   sandbox.SandboxSecurityCapabilityReadinessGateCode
		wantNetwork    bool
		wantCredential bool
	}{
		{
			name:         "trusted selected-template metadata is readiness input",
			lock:         us006CommandSelectedTemplateTrustedLock(),
			wantState:    sandbox.SandboxSecurityCapabilityReadinessReady,
			wantReason:   sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustConfirmed,
			wantGate:     sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
			wantGateCode: sandbox.SandboxSecurityCapabilityReadinessGateCodeAllowed,
		},
		{
			name:         "rejected selected-template metadata is diagnostic-only compatibility readiness input",
			lock:         us006CommandSelectedTemplateRejectedLock(),
			wantState:    sandbox.SandboxSecurityCapabilityReadinessBlocked,
			wantReason:   sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustRejected,
			wantGate:     sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
			wantGateCode: sandbox.SandboxSecurityCapabilityReadinessGateCodeAdvisory,
		},
		{
			name:         "unresolved selected-template provenance is diagnostic-only compatibility readiness input",
			lock:         us006CommandSelectedTemplateUnresolvedLock(),
			wantState:    sandbox.SandboxSecurityCapabilityReadinessBlocked,
			wantReason:   sandbox.SandboxSecurityCapabilityReasonSelectedTemplateProvenanceUnresolved,
			wantGate:     sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
			wantGateCode: sandbox.SandboxSecurityCapabilityReadinessGateCodeAdvisory,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := newSandboxRuntimeSecuritySummaryFromWorkerDriver(sandboxworker.RuntimeDriver{
				ID:         sandboxworker.RuntimeDriverRootlessPodman,
				HostKind:   sandboxworker.HostKindLocal,
				Operations: []string{sandboxworker.OperationStatus},
				Metadata:   us006CommandRuntimeMetadataFromSandboxLock(tt.lock),
			})
			requireUS006RuntimeSelectedTemplateReadiness(t, summary, tt.wantState, tt.wantReason)
			if summary.SecurityReadinessGate == nil {
				t.Fatalf("SecurityReadinessGate = nil, want compatibility gate decision")
			}
			if summary.SecurityReadinessGate.Outcome != tt.wantGate || summary.SecurityReadinessGate.Code != tt.wantGateCode {
				t.Fatalf("security readiness gate = %#v, want outcome=%s code=%s", summary.SecurityReadinessGate, tt.wantGate, tt.wantGateCode)
			}
			if got := summary.SecurityReadinessGate.Counts.ReasonCodeCounts[tt.wantReason]; got != 1 {
				t.Fatalf("reason count[%s] = %d, want 1; counts=%#v", tt.wantReason, got, summary.SecurityReadinessGate.Counts)
			}
			if summary.Enforced.NetworkPolicy != nil || summary.Enforced.NetworkEnforcement != nil || len(summary.Enforced.CredentialModes) > 0 || summary.Enforced.CredentialProxyMode != nil {
				t.Fatalf("template readiness implied unrelated enforced controls: %#v", summary.Enforced)
			}
			requireUS006RuntimeSummaryJSONSafe(t, summary)
		})
	}
}

func requireUS006RuntimeSelectedTemplateReadiness(t *testing.T, summary SandboxRuntimeSecuritySummary, state sandbox.SandboxSecurityCapabilityReadinessState, reason sandbox.SandboxSecurityCapabilityReasonCode) {
	t.Helper()
	if summary.CapabilityReadiness == nil {
		t.Fatalf("CapabilityReadiness = nil, want selected-template readiness")
	}
	if len(summary.CapabilityReadiness.Results) != 1 {
		t.Fatalf("CapabilityReadiness results = %#v, want one selected-template result", summary.CapabilityReadiness.Results)
	}
	result := summary.CapabilityReadiness.Results[0]
	if result.State != state || result.ReasonCode != reason {
		t.Fatalf("selected-template result = %#v, want state=%s reason=%s", result, state, reason)
	}
	for _, metadata := range []*sandbox.SandboxSecurityCapabilityMetadata{result.Metadata, result.Requested, result.Ready} {
		if metadata == nil {
			continue
		}
		if metadata.Family != sandbox.SandboxSecurityCapabilityFamilyTemplate || metadata.Capability != sandbox.SandboxSecurityCapabilitySelectedTemplateTrust {
			t.Fatalf("selected-template result context = %#v, want selected-template trust only", metadata)
		}
	}
	if summary.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("CapabilityReadinessDiagnostics = nil, want diagnostics")
	}
	if got := summary.CapabilityReadinessDiagnostics.Items[0].ReasonCode; got != reason {
		t.Fatalf("diagnostic reason = %s, want %s; diagnostics=%#v", got, reason, summary.CapabilityReadinessDiagnostics)
	}
}

func requireUS006RuntimeSummaryJSONSafe(t *testing.T, summary SandboxRuntimeSecuritySummary) {
	t.Helper()
	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Marshal(runtime security summary) error = %v", err)
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
		"api.internal.example.com",
		"Authorization",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("runtime selected-template readiness leaked %q: %s", forbidden, payload)
		}
	}
}

func us006CommandRuntimeMetadataFromSandboxLock(lock *sandbox.SandboxTemplateLockMetadata) *sandboxruntime.RuntimeMetadata {
	return &sandboxruntime.RuntimeMetadata{
		TemplateLock: sandboxRuntimeTemplateLockFromSandbox(lock),
	}
}

func us006CommandSelectedTemplateTrustedLock() *sandbox.SandboxTemplateLockMetadata {
	return us006CommandSelectedTemplateLock(sandbox.SandboxTemplateTrustPolicyDecisionTrusted, sandbox.SandboxTemplateLockStatusLocked, nil, nil, nil)
}

func us006CommandSelectedTemplateRejectedLock() *sandbox.SandboxTemplateLockMetadata {
	return us006CommandSelectedTemplateLock(sandbox.SandboxTemplateTrustPolicyDecisionRejected, sandbox.SandboxTemplateLockStatusLocked, []string{
		sandbox.SandboxTemplateTrustPolicyCodeMutableReference,
		"https://registry.example.test/template:latest?token=ghp_us006_secret",
	}, []string{
		sandbox.SandboxTemplateTrustPolicyCodeMissingDigestPin,
		"/Users/alice/template.yaml",
	}, nil)
}

func us006CommandSelectedTemplateUnresolvedLock() *sandbox.SandboxTemplateLockMetadata {
	lock := us006CommandSelectedTemplateTrustedLock()
	lock.SourceArtifact = &sandbox.SandboxTemplateLockEntryMetadata{
		SourceKind:    sandbox.SandboxTemplateLockSourceKindSourceArtifact,
		ReferenceKind: sandbox.SandboxTemplateLockReferenceKindGit,
		Status:        sandbox.SandboxTemplateLockStatusUnresolved,
		ReasonCode:    sandbox.SandboxTemplateLockReasonUnresolvedMutableReference,
		WarningCodes:  []string{sandbox.SandboxTemplateLockReasonUnresolvedMutableReference, "token=ghp_us006_secret"},
	}
	lock.TrustPolicy.Status = sandbox.SandboxTemplateLockStatusUnresolved
	lock.TrustPolicy.ReasonCodes = []string{sandbox.SandboxTemplateTrustPolicyCodeUnresolvedLockEntry}
	return sandbox.SanitizeSandboxTemplateLockMetadata(lock)
}

func us006CommandSelectedTemplateLock(decision, status string, reasonCodes, errorCodes, warningCodes []string) *sandbox.SandboxTemplateLockMetadata {
	return sandbox.SanitizeSandboxTemplateLockMetadata(&sandbox.SandboxTemplateLockMetadata{
		Document:          us006CommandTemplateLockEntry(sandbox.SandboxTemplateLockSourceKindLocalFile, sandbox.SandboxTemplateLockReferenceKindLocal, sandbox.SandboxTemplateLockReasonDocumentDigest, "a"),
		TemplateReference: us006CommandTemplateLockEntry(sandbox.SandboxTemplateLockSourceKindTemplateReference, sandbox.SandboxTemplateLockReferenceKindOCIArtifact, sandbox.SandboxTemplateLockReasonTemplateReferenceDigest, "b"),
		RuntimeImage:      us006CommandTemplateLockEntry(sandbox.SandboxTemplateLockSourceKindRuntimeImage, sandbox.SandboxTemplateLockReferenceKindOCIImage, sandbox.SandboxTemplateLockReasonRuntimeImageDigest, "c"),
		SourceArtifact:    us006CommandTemplateLockEntry(sandbox.SandboxTemplateLockSourceKindSourceArtifact, sandbox.SandboxTemplateLockReferenceKindGit, sandbox.SandboxTemplateLockReasonSourceArtifactDigest, "d"),
		TrustPolicy: &sandbox.SandboxTemplateTrustPolicyMetadata{
			Mode:            sandbox.SandboxTemplateTrustPolicyModeStrict,
			Decision:        decision,
			SourceKind:      sandbox.SandboxTemplateLockSourceKindLocalFile,
			ReferenceKind:   sandbox.SandboxTemplateLockReferenceKindLocal,
			Status:          status,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("e", 64),
			ReasonCodes:     reasonCodes,
			ErrorCodes:      errorCodes,
			WarningCodes:    warningCodes,
		},
	})
}

func us006CommandTemplateLockEntry(sourceKind, referenceKind, reasonCode, digestSeed string) *sandbox.SandboxTemplateLockEntryMetadata {
	return &sandbox.SandboxTemplateLockEntryMetadata{
		SourceKind:      sourceKind,
		ReferenceKind:   referenceKind,
		Status:          sandbox.SandboxTemplateLockStatusLocked,
		DigestAlgorithm: "sha256",
		DigestValue:     strings.Repeat(digestSeed, 64),
		LockedAt:        "2026-07-04T06:18:17Z",
		ReasonCode:      reasonCode,
		WarningCodes:    []string{reasonCode, "token=ghp_us006_secret"},
	}
}
