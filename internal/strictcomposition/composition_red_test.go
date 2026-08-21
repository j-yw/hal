package strictcomposition

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestL10EvaluateActiveAcceptsOnlyCompleteCorrelatedEvidence(t *testing.T) {
	request := l10CompleteActiveRequest(t)
	attestation, decision := EvaluateActive(context.Background(), request)
	if decision.State != sandbox.SandboxStrictCompositionStateActive || decision.Code != sandbox.SandboxStrictCompositionCodeReady {
		t.Fatalf("EvaluateActive() decision = %#v, want active strict_ready", decision)
	}
	if !AttestationValid(attestation, request.Identity.SandboxID, request.Identity.ExecutionID, request.Identity.RuntimeID, request.Now) {
		t.Fatal("EvaluateActive() attestation is not valid for the exact active identity")
	}
	if AttestationValid(attestation, request.Identity.SandboxID+"-other", request.Identity.ExecutionID, request.Identity.RuntimeID, request.Now) {
		t.Fatal("active attestation accepted a different sandbox")
	}
	if AttestationValid(attestation, request.Identity.SandboxID, request.Identity.ExecutionID, request.Identity.RuntimeID, request.Now.Add(MaxActiveAttestationAge+time.Nanosecond)) {
		t.Fatal("active attestation remained valid after its bounded horizon")
	}
	if !AttestationMatchesDecision(attestation, decision) {
		t.Fatal("active attestation did not match its exact emitted decision")
	}
	tampered := decision
	tampered.Evidence = append([]sandbox.SandboxStrictCompositionEvidence(nil), decision.Evidence[1:]...)
	if AttestationMatchesDecision(attestation, tampered) {
		t.Fatal("active attestation matched a decision missing runtime evidence")
	}
}

func TestL10ActiveAttestationCannotBeSerializedOrRecreatedFromDecision(t *testing.T) {
	request := l10CompleteActiveRequest(t)
	attestation, decision := EvaluateActive(context.Background(), request)
	if _, err := json.Marshal(attestation); !errors.Is(err, ErrAttestationSerialization) {
		t.Fatalf("json.Marshal(attestation) error = %v, want ErrAttestationSerialization", err)
	}
	payload, err := json.Marshal(decision)
	if err != nil {
		t.Fatalf("json.Marshal(decision) error = %v", err)
	}
	var restored sandbox.SandboxStrictCompositionDecision
	if err := json.Unmarshal(payload, &restored); err != nil {
		t.Fatalf("json.Unmarshal(decision) error = %v", err)
	}
	if restored.State != sandbox.SandboxStrictCompositionStateActive {
		t.Fatalf("restored decision = %#v, want informational active state", restored)
	}
	if AttestationValid(ActiveAttestation{}, request.Identity.SandboxID, request.Identity.ExecutionID, request.Identity.RuntimeID, request.Now) {
		t.Fatal("durable decision recreated live authority")
	}
}

func TestL10TerminalAttestationIsSingleUseUnderConcurrency(t *testing.T) {
	activeRequest := l10CompleteActiveRequest(t)
	attestation, active := EvaluateActive(context.Background(), activeRequest)
	if active.State != sandbox.SandboxStrictCompositionStateActive {
		t.Fatalf("active decision = %#v, want active", active)
	}
	now := activeRequest.Now.Add(time.Second)
	request := TerminalRequest{
		Now: now, Identity: activeRequest.Identity, CredentialRevision: activeRequest.CredentialRevision,
		Attestation: attestation, CredentialCleanup: l10CleanupProof(t, activeRequest.Identity, activeRequest.CredentialRevision, now),
		TemplatePolicyID: activeRequest.TemplatePolicyID, Template: activeRequest.Template,
		TemplateBinding: activeRequest.TemplateBinding, Workspace: activeRequest.Workspace,
	}
	start := make(chan struct{})
	results := make(chan sandbox.SandboxStrictCompositionDecision, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	for range 2 {
		go func() {
			defer workers.Done()
			<-start
			results <- EvaluateTerminal(context.Background(), request)
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	var complete, stale int
	for result := range results {
		switch result.Code {
		case sandbox.SandboxStrictCompositionCodeComplete:
			complete++
		case sandbox.SandboxStrictCompositionCodeAttestationStale:
			stale++
		default:
			t.Fatalf("concurrent terminal result = %#v", result)
		}
	}
	if complete != 1 || stale != 1 {
		t.Fatalf("concurrent terminal results complete/stale = %d/%d, want 1/1", complete, stale)
	}
}

func TestL10TerminalCorrelationSurvivesSelectionAndActiveProofExpiry(t *testing.T) {
	activeRequest := l10CompleteActiveRequest(t)
	attestation, active := EvaluateActive(context.Background(), activeRequest)
	if active.State != sandbox.SandboxStrictCompositionStateActive {
		t.Fatalf("active decision = %#v, want active", active)
	}
	terminalNow := activeRequest.Now.Add(10 * time.Minute)
	workspace := activeRequest.Workspace
	workspace.ObservedAt = terminalNow
	terminal := EvaluateTerminal(context.Background(), TerminalRequest{
		Now: terminalNow, Identity: activeRequest.Identity, CredentialRevision: activeRequest.CredentialRevision,
		Attestation: attestation, CredentialCleanup: l10CleanupProof(t, activeRequest.Identity, activeRequest.CredentialRevision, terminalNow),
		TemplatePolicyID: activeRequest.TemplatePolicyID, Template: activeRequest.Template,
		TemplateBinding: activeRequest.TemplateBinding, Workspace: workspace,
	})
	if terminal.State != sandbox.SandboxStrictCompositionStateComplete || terminal.Code != sandbox.SandboxStrictCompositionCodeComplete {
		t.Fatalf("terminal after long execution = %#v, want complete", terminal)
	}
}

func TestL10EvaluateActiveRejectsEachMissingCorruptOrWeakProof(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ActiveRequest)
		code   sandbox.SandboxStrictCompositionCode
	}{
		{name: "missing runtime proof", mutate: func(r *ActiveRequest) { r.Runtime = nil }, code: sandbox.SandboxStrictCompositionCodeRuntimeProofMissing},
		{name: "runtime identity mismatch", mutate: func(r *ActiveRequest) { r.NetworkIdentity.ExecutionID = "execution-other" }, code: sandbox.SandboxStrictCompositionCodeRuntimeProofMismatch},
		{name: "rootless is advisory", mutate: func(r *ActiveRequest) { r.Identity.RuntimeDriver = sandbox.SandboxRuntimeDriverRootlessPodman }, code: sandbox.SandboxStrictCompositionCodeIdentityMismatch},
		{name: "missing active credential", mutate: func(r *ActiveRequest) { r.CredentialActive = sandboxruntime.JobCredentialActiveProof{} }, code: sandbox.SandboxStrictCompositionCodeCredentialActiveMissing},
		{name: "active and cleanup are mutually exclusive", mutate: func(r *ActiveRequest) {
			r.CredentialCleanup = l10CleanupProof(t, r.Identity, r.CredentialRevision, r.Now)
		}, code: sandbox.SandboxStrictCompositionCodeCredentialProofMismatch},
		{name: "expired active credential", mutate: func(r *ActiveRequest) { r.Now = r.Now.Add(2 * time.Hour) }, code: sandbox.SandboxStrictCompositionCodeCredentialProofStale},
		{name: "template execution mismatch", mutate: func(r *ActiveRequest) { r.TemplateBinding.ExecutionID = "execution-other" }, code: sandbox.SandboxStrictCompositionCodeTemplateProofMismatch},
		{name: "template advisory", mutate: func(r *ActiveRequest) {
			r.Template.Trust.Mode = acquisition.TrustPolicyModeAdvisory
			r.Template.Trust.Decision = acquisition.TrustPolicyDecisionAdvisory
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "template lock warning", mutate: func(r *ActiveRequest) {
			r.Template.Lock.Warnings = []acquisition.LockReasonCode{acquisition.LockReasonUnsupportedSource}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "template trust warning", mutate: func(r *ActiveRequest) {
			r.Template.Trust.Warnings = []acquisition.TrustPolicyWarning{{Code: acquisition.TrustPolicyWarningCode("unsafe_warning")}}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "template trust error", mutate: func(r *ActiveRequest) {
			r.Template.Trust.Errors = []acquisition.TrustPolicyError{{Code: acquisition.TrustPolicyErrorCode("unsafe_error")}}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "template trust enforcement missing", mutate: func(r *ActiveRequest) {
			r.Template.Trust.Enforcement = nil
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "template trust enforcement disabled", mutate: func(r *ActiveRequest) {
			r.Template.Trust.Enforcement.StrictlyEnforced = false
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "template provenance document warning", mutate: func(r *ActiveRequest) {
			r.Template.Provenance = &acquisition.TemplateProvenanceProjection{Document: &acquisition.TemplateProvenanceEntry{WarningCodes: []string{"unsafe_warning"}}}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "template provenance reference warning", mutate: func(r *ActiveRequest) {
			r.Template.Provenance = &acquisition.TemplateProvenanceProjection{TemplateReference: &acquisition.TemplateProvenanceEntry{WarningCodes: []string{"unsafe_warning"}}}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "template provenance runtime image warning", mutate: func(r *ActiveRequest) {
			r.Template.Provenance = &acquisition.TemplateProvenanceProjection{RuntimeImage: &acquisition.TemplateProvenanceEntry{WarningCodes: []string{"unsafe_warning"}}}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "template provenance source artifact warning", mutate: func(r *ActiveRequest) {
			r.Template.Provenance = &acquisition.TemplateProvenanceProjection{SourceArtifact: &acquisition.TemplateProvenanceEntry{WarningCodes: []string{"unsafe_warning"}}}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "runtime document warning", mutate: func(r *ActiveRequest) {
			r.Template.RuntimeMetadata.Document = &sandboxruntime.RuntimeTemplateLockEntryMetadata{WarningCodes: []string{"unsafe_warning"}}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "runtime template reference warning", mutate: func(r *ActiveRequest) {
			r.Template.RuntimeMetadata.TemplateReference.WarningCodes = []string{"unsafe_warning"}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "runtime image warning", mutate: func(r *ActiveRequest) {
			r.Template.RuntimeMetadata.RuntimeImage = &sandboxruntime.RuntimeTemplateLockEntryMetadata{WarningCodes: []string{"unsafe_warning"}}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "runtime source artifact warning", mutate: func(r *ActiveRequest) {
			r.Template.RuntimeMetadata.SourceArtifact = &sandboxruntime.RuntimeTemplateLockEntryMetadata{WarningCodes: []string{"unsafe_warning"}}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "runtime trust warning", mutate: func(r *ActiveRequest) {
			r.Template.RuntimeMetadata.TrustPolicy.WarningCodes = []string{"unsafe_warning"}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "runtime trust error", mutate: func(r *ActiveRequest) {
			r.Template.RuntimeMetadata.TrustPolicy.ErrorCodes = []string{"unsafe_error"}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "runtime trust reason", mutate: func(r *ActiveRequest) {
			r.Template.RuntimeMetadata.TrustPolicy.ReasonCodes = []string{"unsafe_reason"}
		}, code: sandbox.SandboxStrictCompositionCodeTemplateProofRejected},
		{name: "workspace identity mismatch", mutate: func(r *ActiveRequest) { r.Workspace.ExecutionID = "execution-other" }, code: sandbox.SandboxStrictCompositionCodeWorkspaceProofMismatch},
		{name: "direct workspace", mutate: func(r *ActiveRequest) {
			r.Workspace.Workspace.Mode = sandbox.SandboxWorkspaceModeDirect
			r.Workspace.SyncOut.Workspace.Mode = sandbox.SandboxWorkspaceModeDirect
		}, code: sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{name: "stale workspace", mutate: func(r *ActiveRequest) { r.Workspace.ObservedAt = r.Now.Add(-MaxWorkspaceEvidenceAge - time.Nanosecond) }, code: sandbox.SandboxStrictCompositionCodeWorkspaceProofStale},
		{name: "workspace mixed eligibility reasons", mutate: func(r *ActiveRequest) {
			r.Workspace.SyncOut.Apply.Reasons = append(r.Workspace.SyncOut.Apply.Reasons, sandboxworkspace.SyncOutApplyEligibilityReasonEligibleBundle)
		}, code: sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{name: "safe apply dirty worktree reason", mutate: func(r *ActiveRequest) {
			r.Workspace.SafeApply.Reasons = []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonDirtyWorktree}
		}, code: sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{name: "safe apply unsafe artifact reason", mutate: func(r *ActiveRequest) {
			r.Workspace.SafeApply.Reasons = []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonUnsafeArtifact}
		}, code: sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{name: "warning bearing", mutate: func(r *ActiveRequest) { r.WarningCodes = []string{"partial"} }, code: sandbox.SandboxStrictCompositionCodeWarningBearing},
		{name: "fallback", mutate: func(r *ActiveRequest) { r.FallbackUsed = true }, code: sandbox.SandboxStrictCompositionCodeFallbackForbidden},
		{name: "simulation", mutate: func(r *ActiveRequest) { r.Simulated = true }, code: sandbox.SandboxStrictCompositionCodeSimulationForbidden},
		{name: "cleanup incomplete", mutate: func(r *ActiveRequest) { r.CleanupIncomplete = true }, code: sandbox.SandboxStrictCompositionCodeCleanupIncomplete},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := l10CompleteActiveRequest(t)
			tt.mutate(&request)
			attestation, decision := EvaluateActive(context.Background(), request)
			if decision.State != sandbox.SandboxStrictCompositionStateBlocked || decision.Code != tt.code {
				t.Fatalf("EvaluateActive() decision = %#v, want blocked %q", decision, tt.code)
			}
			if AttestationValid(attestation, request.Identity.SandboxID, request.Identity.ExecutionID, request.Identity.RuntimeID, request.Now) {
				t.Fatal("blocked active evaluation returned a valid attestation")
			}
		})
	}
}

func TestL10EvaluateActiveCancellationAndSourceErrorsFailClosedWithoutLeaking(t *testing.T) {
	request := l10CompleteActiveRequest(t)
	request.Runtime = l10RuntimeProofSource{err: &l10UnsafeError{}}
	_, decision := EvaluateActive(context.Background(), request)
	if decision.State != sandbox.SandboxStrictCompositionStateBlocked || decision.Code != sandbox.SandboxStrictCompositionCodeRuntimeProofStale {
		t.Fatalf("runtime source error decision = %#v, want runtime_proof_stale", decision)
	}
	if strings.Contains(strings.ToLower(l10DecisionString(decision)), "token") || strings.Contains(l10DecisionString(decision), "/home/") {
		t.Fatalf("decision leaked source error data: %#v", decision)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request = l10CompleteActiveRequest(t)
	_, decision = EvaluateActive(ctx, request)
	if decision.State != sandbox.SandboxStrictCompositionStateBlocked || decision.Code != sandbox.SandboxStrictCompositionCodeRuntimeProofStale {
		t.Fatalf("canceled decision = %#v, want runtime_proof_stale", decision)
	}
}

func TestL10EvaluateActiveContainsRuntimeSourcePanic(t *testing.T) {
	defer func() {
		if value := recover(); value != nil {
			t.Fatalf("EvaluateActive() leaked runtime source panic: %T", value)
		}
	}()
	request := l10CompleteActiveRequest(t)
	request.Runtime = l10PanickingRuntimeProofSource{}
	attestation, decision := EvaluateActive(context.Background(), request)
	if decision.State != sandbox.SandboxStrictCompositionStateBlocked || decision.Code != sandbox.SandboxStrictCompositionCodeRuntimeProofStale {
		t.Fatalf("runtime source panic decision = %#v, want runtime_proof_stale", decision)
	}
	if AttestationValid(attestation, request.Identity.SandboxID, request.Identity.ExecutionID, request.Identity.RuntimeID, request.Now) {
		t.Fatal("runtime source panic returned a valid attestation")
	}
}

func TestL10EvaluateTerminalCancellationFailsWithoutConsumingAuthority(t *testing.T) {
	activeRequest := l10CompleteActiveRequest(t)
	attestation, active := EvaluateActive(context.Background(), activeRequest)
	if active.State != sandbox.SandboxStrictCompositionStateActive {
		t.Fatalf("active decision = %#v, want active", active)
	}
	terminalNow := activeRequest.Now.Add(2 * time.Second)
	request := TerminalRequest{
		Now: terminalNow, Identity: activeRequest.Identity, CredentialRevision: activeRequest.CredentialRevision,
		Attestation: attestation, CredentialCleanup: l10CleanupProof(t, activeRequest.Identity, activeRequest.CredentialRevision, terminalNow),
		TemplatePolicyID: activeRequest.TemplatePolicyID, Template: activeRequest.Template,
		TemplateBinding: activeRequest.TemplateBinding, Workspace: activeRequest.Workspace,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := EvaluateTerminal(ctx, request)
	if canceled.State != sandbox.SandboxStrictCompositionStateBlocked || canceled.Code != sandbox.SandboxStrictCompositionCodeAttestationStale {
		t.Fatalf("canceled EvaluateTerminal() = %#v, want blocked attestation_stale", canceled)
	}
	if !AttestationValid(attestation, activeRequest.Identity.SandboxID, activeRequest.Identity.ExecutionID, activeRequest.Identity.RuntimeID, terminalNow) {
		t.Fatal("canceled EvaluateTerminal() consumed the live authority")
	}

	completed := EvaluateTerminal(context.Background(), request)
	if completed.State != sandbox.SandboxStrictCompositionStateComplete || completed.Code != sandbox.SandboxStrictCompositionCodeComplete {
		t.Fatalf("retry EvaluateTerminal() = %#v, want complete", completed)
	}
}

func TestL10EvaluateTerminalRequiresExactPriorAttestationAndCleanupProof(t *testing.T) {
	activeRequest := l10CompleteActiveRequest(t)
	attestation, active := EvaluateActive(context.Background(), activeRequest)
	if active.State != sandbox.SandboxStrictCompositionStateActive {
		t.Fatalf("active decision = %#v, want active", active)
	}
	terminalNow := activeRequest.Now.Add(2 * time.Second)
	request := TerminalRequest{
		Now:                terminalNow,
		Identity:           activeRequest.Identity,
		CredentialRevision: activeRequest.CredentialRevision,
		Attestation:        attestation,
		CredentialCleanup:  l10CleanupProof(t, activeRequest.Identity, activeRequest.CredentialRevision, terminalNow),
		TemplatePolicyID:   activeRequest.TemplatePolicyID,
		Template:           activeRequest.Template,
		TemplateBinding:    activeRequest.TemplateBinding,
		Workspace:          activeRequest.Workspace,
	}
	decision := EvaluateTerminal(context.Background(), request)
	if decision.State != sandbox.SandboxStrictCompositionStateComplete || decision.Code != sandbox.SandboxStrictCompositionCodeComplete {
		t.Fatalf("EvaluateTerminal() = %#v, want complete", decision)
	}
	if AttestationValid(attestation, activeRequest.Identity.SandboxID, activeRequest.Identity.ExecutionID, activeRequest.Identity.RuntimeID, terminalNow) {
		t.Fatal("consumed attestation remained valid after terminal completion")
	}

	tests := []struct {
		name   string
		mutate func(*TerminalRequest)
		code   sandbox.SandboxStrictCompositionCode
	}{
		{name: "missing attestation", mutate: func(r *TerminalRequest) { r.Attestation = ActiveAttestation{} }, code: sandbox.SandboxStrictCompositionCodeAttestationStale},
		{name: "different execution", mutate: func(r *TerminalRequest) { r.Identity.ExecutionID = "execution-other" }, code: sandbox.SandboxStrictCompositionCodeIdentityMismatch},
		{name: "missing cleanup", mutate: func(r *TerminalRequest) { r.CredentialCleanup = sandboxruntime.JobCredentialCleanupProof{} }, code: sandbox.SandboxStrictCompositionCodeCredentialCleanupMissing},
		{name: "active retained", mutate: func(r *TerminalRequest) { r.CredentialActive = activeRequest.CredentialActive }, code: sandbox.SandboxStrictCompositionCodeCredentialProofMismatch},
		{name: "cleanup revision", mutate: func(r *TerminalRequest) { r.CredentialRevision++ }, code: sandbox.SandboxStrictCompositionCodeCredentialProofMismatch},
		{name: "template drift", mutate: func(r *TerminalRequest) { r.TemplateBinding.SandboxID = "sandbox-other" }, code: sandbox.SandboxStrictCompositionCodeTemplateProofMismatch},
		{name: "workspace drift", mutate: func(r *TerminalRequest) { r.Workspace.WorkspacePolicyID = "workspace-policy-other" }, code: sandbox.SandboxStrictCompositionCodeWorkspaceProofMismatch},
		{name: "warning", mutate: func(r *TerminalRequest) { r.WarningCodes = []string{"cleanup_warning"} }, code: sandbox.SandboxStrictCompositionCodeWarningBearing},
		{name: "cleanup incomplete", mutate: func(r *TerminalRequest) { r.CleanupIncomplete = true }, code: sandbox.SandboxStrictCompositionCodeCleanupIncomplete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			freshActive := l10CompleteActiveRequest(t)
			freshAttestation, freshDecision := EvaluateActive(context.Background(), freshActive)
			if freshDecision.State != sandbox.SandboxStrictCompositionStateActive {
				t.Fatalf("fresh active decision = %#v, want active", freshDecision)
			}
			freshTerminalNow := freshActive.Now.Add(2 * time.Second)
			current := TerminalRequest{
				Now: freshTerminalNow, Identity: freshActive.Identity,
				CredentialRevision: freshActive.CredentialRevision, Attestation: freshAttestation,
				CredentialCleanup: l10CleanupProof(t, freshActive.Identity, freshActive.CredentialRevision, freshTerminalNow),
				TemplatePolicyID:  freshActive.TemplatePolicyID, Template: freshActive.Template,
				TemplateBinding: freshActive.TemplateBinding, Workspace: freshActive.Workspace,
			}
			tt.mutate(&current)
			got := EvaluateTerminal(context.Background(), current)
			if got.State != sandbox.SandboxStrictCompositionStateBlocked || got.Code != tt.code {
				t.Fatalf("EvaluateTerminal() = %#v, want blocked %q", got, tt.code)
			}
		})
	}
}

func TestL10EvaluateTerminalRejectsFreshCleanupAtDifferentRevision(t *testing.T) {
	activeRequest := l10CompleteActiveRequest(t)
	attestation, active := EvaluateActive(context.Background(), activeRequest)
	if active.State != sandbox.SandboxStrictCompositionStateActive {
		t.Fatalf("active decision = %#v, want active", active)
	}
	terminalNow := activeRequest.Now.Add(2 * time.Second)
	cleanupRevision := activeRequest.CredentialRevision + 1
	decision := EvaluateTerminal(context.Background(), TerminalRequest{
		Now: terminalNow, Identity: activeRequest.Identity, CredentialRevision: cleanupRevision,
		Attestation: attestation, CredentialCleanup: l10CleanupProof(t, activeRequest.Identity, cleanupRevision, terminalNow),
		TemplatePolicyID: activeRequest.TemplatePolicyID, Template: activeRequest.Template,
		TemplateBinding: activeRequest.TemplateBinding, Workspace: activeRequest.Workspace,
	})
	if decision.State != sandbox.SandboxStrictCompositionStateBlocked || decision.Code != sandbox.SandboxStrictCompositionCodeCredentialProofMismatch {
		t.Fatalf("different-revision terminal decision = %#v, want credential_proof_mismatch", decision)
	}
	if !AttestationValid(attestation, activeRequest.Identity.SandboxID, activeRequest.Identity.ExecutionID, activeRequest.Identity.RuntimeID, terminalNow) {
		t.Fatal("different-revision terminal attempt consumed the active attestation")
	}
}

func TestL10EvaluateTerminalRejectsTemplateStrictStateDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*selection.Result)
	}{
		{name: "runtime trust error", mutate: func(template *selection.Result) {
			runtimeMetadata := *template.RuntimeMetadata
			trustPolicy := *runtimeMetadata.TrustPolicy
			trustPolicy.ErrorCodes = []string{"unsafe_error"}
			runtimeMetadata.TrustPolicy = &trustPolicy
			template.RuntimeMetadata = &runtimeMetadata
		}},
		{name: "runtime trust reason", mutate: func(template *selection.Result) {
			runtimeMetadata := *template.RuntimeMetadata
			trustPolicy := *runtimeMetadata.TrustPolicy
			trustPolicy.ReasonCodes = []string{"unsafe_reason"}
			runtimeMetadata.TrustPolicy = &trustPolicy
			template.RuntimeMetadata = &runtimeMetadata
		}},
		{name: "strict enforcement missing", mutate: func(template *selection.Result) {
			template.Trust.Enforcement = nil
		}},
		{name: "strict enforcement disabled", mutate: func(template *selection.Result) {
			template.Trust.Enforcement = &acquisition.TrustPolicyEnforcementMetadata{}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			activeRequest := l10CompleteActiveRequest(t)
			attestation, active := EvaluateActive(context.Background(), activeRequest)
			if active.State != sandbox.SandboxStrictCompositionStateActive {
				t.Fatalf("active decision = %#v, want active", active)
			}
			terminalNow := activeRequest.Now.Add(2 * time.Second)
			template := activeRequest.Template
			tt.mutate(&template)
			decision := EvaluateTerminal(context.Background(), TerminalRequest{
				Now: terminalNow, Identity: activeRequest.Identity, CredentialRevision: activeRequest.CredentialRevision,
				Attestation: attestation, CredentialCleanup: l10CleanupProof(t, activeRequest.Identity, activeRequest.CredentialRevision, terminalNow),
				TemplatePolicyID: activeRequest.TemplatePolicyID, Template: template,
				TemplateBinding: activeRequest.TemplateBinding, Workspace: activeRequest.Workspace,
			})
			if decision.State != sandbox.SandboxStrictCompositionStateBlocked || decision.Code != sandbox.SandboxStrictCompositionCodeTemplateProofRejected {
				t.Fatalf("template strict-state drift decision = %#v, want template_proof_rejected", decision)
			}
			if !AttestationValid(attestation, activeRequest.Identity.SandboxID, activeRequest.Identity.ExecutionID, activeRequest.Identity.RuntimeID, terminalNow) {
				t.Fatal("template strict-state drift consumed the active attestation")
			}
		})
	}
}

func TestL10EvaluateActiveAllowsNilAndExplicitEmptyTemplateFindingAliases(t *testing.T) {
	for _, explicitEmpty := range []bool{false, true} {
		t.Run(map[bool]string{false: "nil", true: "empty"}[explicitEmpty], func(t *testing.T) {
			request := l10CompleteActiveRequest(t)
			if explicitEmpty {
				request.Template.Lock.Warnings = []acquisition.LockReasonCode{}
				request.Template.Trust.Warnings = []acquisition.TrustPolicyWarning{}
				request.Template.Trust.Errors = []acquisition.TrustPolicyError{}
				request.Template.Provenance = &acquisition.TemplateProvenanceProjection{
					Document:          &acquisition.TemplateProvenanceEntry{WarningCodes: []string{}},
					TemplateReference: &acquisition.TemplateProvenanceEntry{WarningCodes: []string{}},
					RuntimeImage:      &acquisition.TemplateProvenanceEntry{WarningCodes: []string{}},
					SourceArtifact:    &acquisition.TemplateProvenanceEntry{WarningCodes: []string{}},
				}
				request.Template.RuntimeMetadata.Document = &sandboxruntime.RuntimeTemplateLockEntryMetadata{WarningCodes: []string{}}
				request.Template.RuntimeMetadata.TemplateReference.WarningCodes = []string{}
				request.Template.RuntimeMetadata.RuntimeImage = &sandboxruntime.RuntimeTemplateLockEntryMetadata{WarningCodes: []string{}}
				request.Template.RuntimeMetadata.SourceArtifact = &sandboxruntime.RuntimeTemplateLockEntryMetadata{WarningCodes: []string{}}
				request.Template.RuntimeMetadata.TrustPolicy.WarningCodes = []string{}
				request.Template.RuntimeMetadata.TrustPolicy.ErrorCodes = []string{}
				request.Template.RuntimeMetadata.TrustPolicy.ReasonCodes = []string{}
			}
			_, decision := EvaluateActive(context.Background(), request)
			if decision.State != sandbox.SandboxStrictCompositionStateActive || decision.Code != sandbox.SandboxStrictCompositionCodeReady {
				t.Fatalf("EvaluateActive() = %#v, want strict_ready", decision)
			}
		})
	}
}

type l10RuntimeProofSource struct {
	metadata l7network.Metadata
	err      error
}

type l10PanickingRuntimeProofSource struct{}

func (l10PanickingRuntimeProofSource) Inspect(context.Context, l7network.Identity) (l7network.Metadata, error) {
	panic(&l10UnsafeError{})
}

func (source l10RuntimeProofSource) Inspect(context.Context, l7network.Identity) (l7network.Metadata, error) {
	return source.metadata, source.err
}

type l10UnsafeError struct{}

func (*l10UnsafeError) Error() string { return "token=raw-secret /home/operator/private" }

func l10CompleteActiveRequest(t *testing.T) ActiveRequest {
	t.Helper()
	now := time.Unix(1_900_000_000, 0).UTC()
	identity := l10CredentialIdentity(now.Add(-time.Minute))
	revision := uint64(7)
	active, err := sandboxruntime.NewJobCredentialActiveProof(sandboxruntime.JobCredentialActiveProofInput{
		ProofID: "active-proof-primary", Identity: identity, Revision: revision,
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("NewJobCredentialActiveProof() error = %v", err)
	}
	networkIdentity := l10NetworkIdentity(identity)
	templateResult, templateBinding := l10TemplateEvidence(identity)
	workspace := l10WorkspaceEvidence(identity, now)
	return ActiveRequest{
		Now:                now,
		Identity:           identity,
		CredentialRevision: revision,
		Runtime: l10RuntimeProofSource{metadata: l7network.Metadata{
			Identity: networkIdentity, Status: l7network.StatusInspected,
			StructuralInspected: true, TAPInspected: true, RulesInspected: true,
			RawPacketIsolationVerified: true, RuleDigest: "rule-digest-primary",
		}},
		NetworkIdentity:  networkIdentity,
		CredentialActive: active,
		TemplatePolicyID: identity.TemplatePolicyID,
		Template:         templateResult,
		TemplateBinding:  templateBinding,
		Workspace:        workspace,
	}
}

func l10CredentialIdentity(issuedAt time.Time) sandboxruntime.JobCredentialIdentity {
	return sandboxruntime.JobCredentialIdentity{
		SandboxID: "sandbox-primary", ExecutionID: "execution-primary", WorkerID: "worker-primary", HostID: "host-primary",
		RuntimeDriver: sandbox.SandboxRuntimeDriverMicroVM, RuntimeID: "runtime-primary", RuntimeGeneration: "runtime-generation-primary",
		FirecrackerProcessGeneration: "process-generation-primary", VsockGeneration: "vsock-generation-primary",
		WorkerJobID: "worker-job-primary", SubmissionID: "submission-primary", PlanID: "credential-plan-primary",
		ActivationGeneration: "activation-primary", CredentialGeneration: "credential-generation-primary",
		NetworkPlanID: "network-plan-primary", PolicySnapshotID: "policy-snapshot-primary", ProxySessionID: "proxy-session-primary",
		ProxyGenerationID: "proxy-generation-primary", TopologyGenerationID: "topology-generation-primary", RuleGenerationID: "rule-generation-primary",
		AdmissionGrantID: "admission-grant-primary", PrincipalID: "principal-primary", TemplatePolicyID: "template-policy-primary",
		WorkspacePolicyID: "workspace-policy-primary", ControllerKeyGeneration: "controller-key-primary",
		GuestBootGeneration: "guest-boot-primary", GuestImageGeneration: "guest-image-primary",
		GuestImageDigest:       "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		GuestSessionGeneration: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", GuestHelperGeneration: "helper-generation-primary",
		AdmissionGrantRevision: 11, BindingIDs: []string{"binding-http"},
		DeliveryModes: []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy}, IssuedAt: issuedAt,
	}
}

func l10NetworkIdentity(identity sandboxruntime.JobCredentialIdentity) l7network.Identity {
	return l7network.Identity{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeGenerationID: identity.RuntimeGeneration, PlanID: identity.NetworkPlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
	}
}

func l10TemplateEvidence(identity sandboxruntime.JobCredentialIdentity) (selection.Result, selection.BindingRequest) {
	digest := &sandboxtemplate.DigestMetadata{Algorithm: sandboxtemplate.DigestAlgorithmSHA256, Value: strings.Repeat("a", 64)}
	result := selection.Result{
		ManifestDigest: digest, RuntimeDriver: sandbox.SandboxRuntimeDriverMicroVM, IsolationLevel: sandbox.SandboxIsolationLevelVM,
		Template: sandboxtemplate.Template{
			Metadata: sandboxtemplate.TemplateMetadata{Reference: &sandboxtemplate.ImmutableRef{Kind: sandboxtemplate.ReferenceKindOCIArtifact, Digest: digest}},
			Runtime:  &sandboxtemplate.RuntimeRequirements{Driver: sandboxtemplate.RuntimeDriverMicroVM, IsolationLevel: sandboxtemplate.IsolationLevelVM},
		},
		Lock: acquisition.TemplateLock{
			SourceKind: acquisition.SourceKindOCIArtifact, ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact, Status: acquisition.LockStatusLocked,
			References: []acquisition.ReferenceLock{{Field: "metadata.reference", Kind: sandboxtemplate.ReferenceKindOCIArtifact, Status: acquisition.LockStatusLocked, Digest: digest}},
		},
		Trust: acquisition.TrustPolicyResult{
			Mode: acquisition.TrustPolicyModeStrict, Decision: acquisition.TrustPolicyDecisionTrusted,
			Enforcement: &acquisition.TrustPolicyEnforcementMetadata{StrictlyEnforced: true},
		},
		RuntimeMetadata: &sandboxruntime.RuntimeTemplateLockMetadata{
			TemplateReference: &sandboxruntime.RuntimeTemplateLockEntryMetadata{SourceKind: "template_reference", ReferenceKind: "oci_artifact", Status: "locked", DigestAlgorithm: "sha256", DigestValue: digest.Value},
			TrustPolicy:       &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{Mode: "strict", Decision: "trusted", SourceKind: "oci_artifact", ReferenceKind: "oci_artifact", Status: "locked", DigestAlgorithm: "sha256", DigestValue: digest.Value},
		},
	}
	return result, selection.BindingRequest{
		ExecutionID: identity.ExecutionID, SandboxID: identity.SandboxID, RuntimeID: identity.RuntimeID,
		RuntimeDriver: identity.RuntimeDriver, IsolationLevel: sandbox.SandboxIsolationLevelVM, ManifestDigest: digest,
	}
}

func l10WorkspaceEvidence(identity sandboxruntime.JobCredentialIdentity, observedAt time.Time) WorkspaceEvidence {
	artifact := sandboxworkspace.SyncOutArtifact{
		ID: "artifact-patch-primary", DisplayName: "workspace patch", Kind: sandboxworkspace.SyncOutArtifactKindPatch,
		DisplayPath: "artifacts/workspace.patch", StoredPath: "payloads/workspace.patch",
		ApplyEligibility: &sandboxworkspace.SyncOutApplyEligibility{Eligible: true, Mode: sandboxworkspace.SyncOutApplyModePatch, Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonEligiblePatch}},
	}
	return WorkspaceEvidence{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkspacePolicyID: identity.WorkspacePolicyID, ObservedAt: observedAt,
		Workspace: sandbox.SandboxWorkspace{Mode: sandbox.SandboxWorkspaceModeClone, InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef, Branch: "feature-primary", SyncRef: "refs/heads/feature-primary"},
		SyncOut: sandboxworkspace.SyncOutSummary{
			Workspace: sandboxworkspace.SyncOutWorkspaceRef{Mode: sandbox.SandboxWorkspaceModeClone, InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef, Branch: "feature-primary", SyncRef: "refs/heads/feature-primary"},
			Committed: sandboxworkspace.SyncOutCommittedArtifacts{Patch: &artifact},
			Recovery:  sandboxworkspace.SyncOutRecoveryState{Status: sandboxworkspace.SyncOutRecoveryStatusCollected},
			Apply:     sandboxworkspace.SyncOutApplyDecision{Eligible: true, Mode: sandboxworkspace.SyncOutApplyModePatch, ArtifactID: artifact.ID, Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonEligiblePatch}},
		},
		SafeApply: &sandboxworkspace.SafeApplyResult{
			Status: sandboxworkspace.SafeApplyStatusDryRunPassed, DryRunPassed: true,
			Mode: sandboxworkspace.SyncOutApplyModePatch, ArtifactID: artifact.ID,
			DisplayName: artifact.DisplayName, DisplayPath: artifact.DisplayPath,
			Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonEligiblePatch},
		},
	}
}

func l10CleanupProof(t *testing.T, identity sandboxruntime.JobCredentialIdentity, revision uint64, observedAt time.Time) sandboxruntime.JobCredentialCleanupProof {
	t.Helper()
	proof, err := sandboxruntime.NewJobCredentialCleanupProof(sandboxruntime.JobCredentialCleanupProofInput{
		ProofID: "cleanup-proof-primary", Identity: identity, Revision: revision,
		RevokedAt: observedAt.Add(-time.Second), AbsenceInspectedAt: observedAt,
		AuthorityAbsent: true, ResourcesAbsent: true,
	})
	if err != nil {
		t.Fatalf("NewJobCredentialCleanupProof() error = %v", err)
	}
	return proof
}

func l10DecisionString(decision sandbox.SandboxStrictCompositionDecision) string {
	return string(decision.State) + " " + string(decision.Code) + " " + decision.CompositionID
}
