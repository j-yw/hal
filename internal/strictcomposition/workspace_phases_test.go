package strictcomposition

import (
	"context"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestL10WorkspaceActiveAdmissionDoesNotRequireFutureOutputs(t *testing.T) {
	for _, mode := range []string{sandbox.SandboxWorkspaceModeClone, sandbox.SandboxWorkspaceModeCopy} {
		t.Run(mode, func(t *testing.T) {
			request := l10CompleteActiveRequest(t)
			request.Workspace.SyncOut = sandboxworkspace.SyncOutSummary{}
			request.Workspace.SafeApply = nil
			if mode == sandbox.SandboxWorkspaceModeCopy {
				request.Workspace.Workspace.Mode = mode
				request.Workspace.Workspace.InputSource = sandbox.SandboxWorkspaceInputSourceCopy
				request.Workspace.Workspace.SyncRef = "working_tree"
			}
			attestation, decision := EvaluateActive(context.Background(), request)
			if decision.State != sandbox.SandboxStrictCompositionStateActive || !AttestationValid(attestation, request.Identity.SandboxID, request.Identity.ExecutionID, request.Identity.RuntimeID, request.Now) {
				t.Fatalf("input-only admission = %#v, want active without fabricated output", decision)
			}
		})
	}
}

func TestL10WorkspaceTerminalAcceptsOutputsCreatedAfterAdmission(t *testing.T) {
	for _, scenario := range []string{"new_patch", "changed_patch", "new_bundle", "no_changes"} {
		t.Run(scenario, func(t *testing.T) {
			active := l10CompleteActiveRequest(t)
			if scenario != "changed_patch" {
				active.Workspace.SyncOut = sandboxworkspace.SyncOutSummary{}
				active.Workspace.SafeApply = nil
			}
			attestation, decision := EvaluateActive(context.Background(), active)
			if decision.State != sandbox.SandboxStrictCompositionStateActive {
				t.Fatalf("admission = %#v, want active", decision)
			}
			now := active.Now.Add(10 * time.Minute)
			output := l10WorkspaceEvidence(active.Identity, now)
			output.SafeApply = nil
			switch scenario {
			case "new_patch", "changed_patch":
				output.SyncOut.Committed.Patch.ID = "artifact-patch-after-work"
				output.SyncOut.Committed.Patch.StoredPath = "payloads/after-work.patch"
				output.SyncOut.Apply.ArtifactID = output.SyncOut.Committed.Patch.ID
			case "new_bundle":
				bundle := *output.SyncOut.Committed.Patch
				bundle.ID = "artifact-bundle-after-work"
				bundle.Kind = sandboxworkspace.SyncOutArtifactKindBundle
				bundle.DisplayName = "workspace bundle"
				bundle.DisplayPath = "artifacts/workspace.bundle"
				bundle.StoredPath = "payloads/workspace.bundle"
				bundle.ApplyEligibility = &sandboxworkspace.SyncOutApplyEligibility{Eligible: true, Mode: sandboxworkspace.SyncOutApplyModeBundle, Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonEligibleBundle}}
				output.SyncOut.Committed = sandboxworkspace.SyncOutCommittedArtifacts{Bundle: &bundle}
				output.SyncOut.Apply = sandboxworkspace.SyncOutApplyDecision{Eligible: true, Mode: sandboxworkspace.SyncOutApplyModeBundle, ArtifactID: bundle.ID, Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonEligibleBundle}}
			case "no_changes":
				l10WorkspaceNoChanges(&output)
			}
			terminal := l10WorkspaceTerminalRequest(t, active, attestation, output, now)
			completed := EvaluateTerminal(context.Background(), terminal)
			if completed.State != sandbox.SandboxStrictCompositionStateComplete {
				t.Fatalf("post-execution output = %#v, want complete", completed)
			}
			if replay := EvaluateTerminal(context.Background(), terminal); replay.Code != sandbox.SandboxStrictCompositionCodeAttestationStale {
				t.Fatalf("replayed output completion = %#v, want stale", replay)
			}
		})
	}
}

func TestL10WorkspaceTerminalRejectsMissingInconsistentOrUncorrelatedOutputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*WorkspaceEvidence)
		code   sandbox.SandboxStrictCompositionCode
	}{
		{"missing output", func(w *WorkspaceEvidence) { w.SyncOut = sandboxworkspace.SyncOutSummary{}; w.SafeApply = nil }, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{"changed input", func(w *WorkspaceEvidence) {
			w.Workspace.SyncRef = "refs/heads/other"
			w.SyncOut.Workspace.SyncRef = w.Workspace.SyncRef
		}, sandbox.SandboxStrictCompositionCodeWorkspaceProofMismatch},
		{"wrong policy", func(w *WorkspaceEvidence) { w.WorkspacePolicyID = "workspace-policy-other" }, sandbox.SandboxStrictCompositionCodeWorkspaceProofMismatch},
		{"partial recovery", func(w *WorkspaceEvidence) { w.SyncOut.Recovery.Status = sandboxworkspace.SyncOutRecoveryStatusPartial }, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{"unsafe payload", func(w *WorkspaceEvidence) { w.SyncOut.Committed.Patch.StoredPath = "../outside.patch" }, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{"missing stored payload", func(w *WorkspaceEvidence) { w.SyncOut.Committed.Patch.StoredPath = "" }, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{"wrong artifact kind", func(w *WorkspaceEvidence) {
			w.SyncOut.Committed.Patch.Kind = sandboxworkspace.SyncOutArtifactKindArchive
		}, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{"no-change with patch", func(w *WorkspaceEvidence) {
			w.SyncOut.Apply = sandboxworkspace.SyncOutApplyDecision{Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact}}
			w.SafeApply = nil
		}, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{"summary warning", func(w *WorkspaceEvidence) { w.SyncOut.Warnings = []sandboxworkspace.SyncOutWarning{{Code: "partial"}} }, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe},
		{"output older than admission", func(w *WorkspaceEvidence) { w.ObservedAt = w.ObservedAt.Add(-3 * time.Second) }, sandbox.SandboxStrictCompositionCodeWorkspaceProofStale},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			active := l10CompleteActiveRequest(t)
			attestation, admitted := EvaluateActive(context.Background(), active)
			if admitted.State != sandbox.SandboxStrictCompositionStateActive {
				t.Fatalf("admission = %#v", admitted)
			}
			now := active.Now.Add(2 * time.Second)
			output := l10WorkspaceEvidence(active.Identity, now)
			tt.mutate(&output)
			decision := EvaluateTerminal(context.Background(), l10WorkspaceTerminalRequest(t, active, attestation, output, now))
			if decision.State != sandbox.SandboxStrictCompositionStateBlocked || decision.Code != tt.code {
				t.Fatalf("terminal = %#v, want blocked %s", decision, tt.code)
			}
			if !AttestationValid(attestation, active.Identity.SandboxID, active.Identity.ExecutionID, active.Identity.RuntimeID, now) {
				t.Fatal("rejected output consumed admission")
			}
		})
	}
}

func TestL10WorkspaceNoChangeRequiresExplicitConsistentCollection(t *testing.T) {
	for _, scenario := range []string{"missing_recovery_payload", "unavailable", "unknown", "missing_reason", "mixed_reasons", "apply_mode", "apply_artifact", "safe_apply", "untracked", "duplicate_payload_id", "unknown_eligibility"} {
		t.Run(scenario, func(t *testing.T) {
			active := l10CompleteActiveRequest(t)
			attestation, _ := EvaluateActive(context.Background(), active)
			now := active.Now.Add(time.Second)
			output := l10WorkspaceEvidence(active.Identity, now)
			l10WorkspaceNoChanges(&output)
			switch scenario {
			case "missing_recovery_payload":
				output.SyncOut.Recovery.Artifacts = nil
			case "unavailable":
				output.SyncOut.Recovery.Status = sandboxworkspace.SyncOutRecoveryStatusUnavailable
			case "unknown":
				output.SyncOut.Recovery.Status = "unknown"
			case "missing_reason":
				output.SyncOut.Apply.Reasons = nil
			case "mixed_reasons":
				output.SyncOut.Apply.Reasons = append(output.SyncOut.Apply.Reasons, sandboxworkspace.SyncOutApplyEligibilityReasonManualReviewRequired)
			case "apply_mode":
				output.SyncOut.Apply.Mode = sandboxworkspace.SyncOutApplyModePatch
			case "apply_artifact":
				output.SyncOut.Apply.ArtifactID = "phantom-patch"
			case "safe_apply":
				output.SafeApply = l10WorkspaceEvidence(active.Identity, now).SafeApply
			case "untracked":
				output.SyncOut.Untracked.List = &sandboxworkspace.SyncOutArtifact{ID: "untracked", Kind: sandboxworkspace.SyncOutArtifactKindFileList, DisplayPath: "artifacts/untracked.txt", StoredPath: "payloads/untracked.txt"}
			case "duplicate_payload_id":
				output.SyncOut.Recovery.Artifacts = append(output.SyncOut.Recovery.Artifacts, output.SyncOut.Recovery.Artifacts[0])
			case "unknown_eligibility":
				output.SyncOut.Recovery.Artifacts[0].ApplyEligibility = &sandboxworkspace.SyncOutApplyEligibility{Mode: "unknown"}
			}
			decision := EvaluateTerminal(context.Background(), l10WorkspaceTerminalRequest(t, active, attestation, output, now))
			if decision.Code != sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe {
				t.Fatalf("inconsistent no-change output = %#v, want workspace_proof_unsafe", decision)
			}
		})
	}
}

func TestL10WorkspaceInputOnlyStillRejectsUnsafeReferences(t *testing.T) {
	for _, scenario := range []string{"raw_repo", "unsafe_ref", "missing_ref", "unknown_input", "warning"} {
		t.Run(scenario, func(t *testing.T) {
			request := l10CompleteActiveRequest(t)
			request.Workspace.SyncOut = sandboxworkspace.SyncOutSummary{}
			request.Workspace.SafeApply = nil
			switch scenario {
			case "raw_repo":
				request.Workspace.Workspace.Repo = "https://private.example/repo"
			case "unsafe_ref":
				request.Workspace.Workspace.SyncRef = "token=secret-value"
			case "missing_ref":
				request.Workspace.Workspace.SyncRef = ""
			case "unknown_input":
				request.Workspace.Workspace.InputSource = "unknown"
			case "warning":
				request.Workspace.WarningCodes = []string{"partial"}
			}
			_, decision := EvaluateActive(context.Background(), request)
			if decision.Code != sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe {
				t.Fatalf("unsafe input-only admission = %#v", decision)
			}
		})
	}
}

func l10WorkspaceNoChanges(output *WorkspaceEvidence) {
	output.SyncOut.Committed = sandboxworkspace.SyncOutCommittedArtifacts{}
	output.SyncOut.Apply = sandboxworkspace.SyncOutApplyDecision{Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact}}
	output.SyncOut.Recovery.Artifacts = []sandboxworkspace.SyncOutArtifact{{ID: "recovery-after-work", Kind: sandboxworkspace.SyncOutArtifactKindRecovery, DisplayPath: "artifacts/recovery.patch", StoredPath: "payloads/recovery.patch"}}
	output.SafeApply = nil
}

func l10WorkspaceTerminalRequest(t *testing.T, active ActiveRequest, attestation ActiveAttestation, output WorkspaceEvidence, now time.Time) TerminalRequest {
	t.Helper()
	return TerminalRequest{
		Now: now, Identity: active.Identity, CredentialRevision: active.CredentialRevision,
		Attestation: attestation, CredentialCleanup: l10CleanupProof(t, active.Identity, active.CredentialRevision, now),
		TemplatePolicyID: active.TemplatePolicyID, Template: active.Template, TemplateBinding: active.TemplateBinding,
		Workspace: output,
	}
}
