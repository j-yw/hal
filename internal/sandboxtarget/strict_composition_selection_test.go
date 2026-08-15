package sandboxtarget

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/strictcomposition"
)

func TestL10StrictSelectionRequiresLiveCompositionAttestation(t *testing.T) {
	target := strictSecureDefaultProofCompleteSandbox("sandbox-l10-strict")
	target.ID = target.Name
	authority, decision := l10TargetSelectionAuthority(t, target)
	target.Security.StrictComposition = &decision

	withoutLive := l10SelectStrictTarget(t, target, nil)
	if !withoutLive.Failed() || withoutLive.Sandbox != nil {
		t.Fatalf("durable strict decision selected without live authority: %#v", withoutLive)
	}

	withLive := l10SelectStrictTarget(t, target, authority)
	if withLive.Failed() || withLive.Sandbox != target {
		t.Fatalf("exact live strict authority result = %#v, want selected target", withLive)
	}

	wrong := *authority
	wrong.ExecutionID = "execution-other"
	if result := l10SelectStrictTarget(t, target, &wrong); !result.Failed() || result.Sandbox != nil {
		t.Fatalf("different execution live authority selected target: %#v", result)
	}

	expired := *authority
	expired.Now = expired.Now.Add(strictcomposition.MaxActiveAttestationAge + time.Nanosecond)
	if result := l10SelectStrictTarget(t, target, &expired); !result.Failed() || result.Sandbox != nil {
		t.Fatalf("expired live authority selected target: %#v", result)
	}
}

func l10SelectStrictTarget(t *testing.T, target *sandbox.SandboxState, authority *StrictCompositionAuthority) Result {
	t.Helper()
	return Select(Request{
		SandboxName: target.Name, SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		StrictComposition: authority, Fallback: FallbackPolicy{Disabled: true},
	}, CachedState{LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
		if name != target.Name {
			t.Fatalf("LoadSandbox(%q), want %q", name, target.Name)
		}
		return target, nil
	}})
}

type l10SelectionRuntimeSource struct{ metadata l7network.Metadata }

func (source l10SelectionRuntimeSource) Inspect(context.Context, l7network.Identity) (l7network.Metadata, error) {
	return source.metadata, nil
}

func l10TargetSelectionAuthority(t *testing.T, target *sandbox.SandboxState) (*StrictCompositionAuthority, sandbox.SandboxStrictCompositionDecision) {
	t.Helper()
	now := time.Unix(1_900_100_000, 0).UTC()
	identity := sandboxruntime.JobCredentialIdentity{
		SandboxID: target.ID, ExecutionID: "execution-l10-strict", WorkerID: "worker-l10-strict", HostID: target.Host.ID,
		RuntimeDriver: sandbox.SandboxRuntimeDriverMicroVM, RuntimeID: target.Runtime.RuntimeID, RuntimeGeneration: "runtime-generation-l10-strict",
		FirecrackerProcessGeneration: "process-generation-l10-strict", VsockGeneration: "vsock-generation-l10-strict",
		WorkerJobID: "worker-job-l10-strict", SubmissionID: "submission-l10-strict", PlanID: "credential-plan-l10-strict",
		ActivationGeneration: "activation-l10-strict", CredentialGeneration: "credential-generation-l10-strict",
		NetworkPlanID: "network-plan-l10-strict", PolicySnapshotID: "policy-snapshot-l10-strict", ProxySessionID: "proxy-session-l10-strict",
		ProxyGenerationID: "proxy-generation-l10-strict", TopologyGenerationID: "topology-generation-l10-strict", RuleGenerationID: "rule-generation-l10-strict",
		AdmissionGrantID: "admission-grant-l10-strict", PrincipalID: "principal-l10-strict", TemplatePolicyID: "template-policy-l10-strict",
		WorkspacePolicyID: "workspace-policy-l10-strict", ControllerKeyGeneration: "controller-key-l10-strict",
		GuestBootGeneration: "guest-boot-l10-strict", GuestImageGeneration: "guest-image-l10-strict",
		GuestImageDigest:       "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		GuestSessionGeneration: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", GuestHelperGeneration: "helper-generation-l10-strict",
		AdmissionGrantRevision: 1, BindingIDs: []string{"binding-l10-strict"},
		DeliveryModes: []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy}, IssuedAt: now.Add(-time.Minute),
	}
	revision := uint64(1)
	active, err := sandboxruntime.NewJobCredentialActiveProof(sandboxruntime.JobCredentialActiveProofInput{
		ProofID: "active-proof-l10-strict", Identity: identity, Revision: revision,
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("NewJobCredentialActiveProof() error = %v", err)
	}
	networkIdentity := l7network.Identity{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeGenerationID: identity.RuntimeGeneration, PlanID: identity.NetworkPlanID, PolicySnapshotID: identity.PolicySnapshotID,
		ProxySessionID: identity.ProxySessionID, ProxyGenerationID: identity.ProxyGenerationID,
		TopologyGenerationID: identity.TopologyGenerationID, RuleGenerationID: identity.RuleGenerationID,
	}
	digest := &sandboxtemplate.DigestMetadata{Algorithm: sandboxtemplate.DigestAlgorithmSHA256, Value: strings.Repeat("b", 64)}
	templateResult := selection.Result{
		ManifestDigest: digest, RuntimeDriver: sandbox.SandboxRuntimeDriverMicroVM, IsolationLevel: sandbox.SandboxIsolationLevelVM,
		Template: sandboxtemplate.Template{
			Metadata: sandboxtemplate.TemplateMetadata{Reference: &sandboxtemplate.ImmutableRef{Kind: sandboxtemplate.ReferenceKindOCIArtifact, Digest: digest}},
			Runtime:  &sandboxtemplate.RuntimeRequirements{Driver: sandboxtemplate.RuntimeDriverMicroVM, IsolationLevel: sandboxtemplate.IsolationLevelVM},
		},
		Lock: acquisition.TemplateLock{SourceKind: acquisition.SourceKindOCIArtifact, ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact, Status: acquisition.LockStatusLocked,
			References: []acquisition.ReferenceLock{{Field: "metadata.reference", Kind: sandboxtemplate.ReferenceKindOCIArtifact, Status: acquisition.LockStatusLocked, Digest: digest}}},
		Trust: acquisition.TrustPolicyResult{Mode: acquisition.TrustPolicyModeStrict, Decision: acquisition.TrustPolicyDecisionTrusted},
		RuntimeMetadata: &sandboxruntime.RuntimeTemplateLockMetadata{
			TemplateReference: &sandboxruntime.RuntimeTemplateLockEntryMetadata{SourceKind: "template_reference", ReferenceKind: "oci_artifact", Status: "locked", DigestAlgorithm: "sha256", DigestValue: digest.Value},
			TrustPolicy:       &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{Mode: "strict", Decision: "trusted", SourceKind: "oci_artifact", ReferenceKind: "oci_artifact", Status: "locked", DigestAlgorithm: "sha256", DigestValue: digest.Value},
		},
	}
	artifact := sandboxworkspace.SyncOutArtifact{ID: "artifact-l10-strict", DisplayName: "workspace patch", Kind: sandboxworkspace.SyncOutArtifactKindPatch,
		DisplayPath: "artifacts/workspace.patch", StoredPath: "payloads/workspace.patch",
		ApplyEligibility: &sandboxworkspace.SyncOutApplyEligibility{Eligible: true, Mode: sandboxworkspace.SyncOutApplyModePatch, Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonEligiblePatch}}}
	workspace := strictcomposition.WorkspaceEvidence{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkspacePolicyID: identity.WorkspacePolicyID, ObservedAt: now,
		Workspace: sandbox.SandboxWorkspace{Mode: sandbox.SandboxWorkspaceModeClone, InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef, Branch: "feature-l10", SyncRef: "refs/heads/feature-l10"},
		SyncOut: sandboxworkspace.SyncOutSummary{
			Workspace: sandboxworkspace.SyncOutWorkspaceRef{Mode: sandbox.SandboxWorkspaceModeClone, InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef, Branch: "feature-l10", SyncRef: "refs/heads/feature-l10"},
			Committed: sandboxworkspace.SyncOutCommittedArtifacts{Patch: &artifact}, Recovery: sandboxworkspace.SyncOutRecoveryState{Status: sandboxworkspace.SyncOutRecoveryStatusCollected},
			Apply: sandboxworkspace.SyncOutApplyDecision{Eligible: true, Mode: sandboxworkspace.SyncOutApplyModePatch, ArtifactID: artifact.ID, Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonEligiblePatch}},
		},
		SafeApply: &sandboxworkspace.SafeApplyResult{Status: sandboxworkspace.SafeApplyStatusDryRunPassed, DryRunPassed: true, Mode: sandboxworkspace.SyncOutApplyModePatch, ArtifactID: artifact.ID},
	}
	attestation, decision := strictcomposition.EvaluateActive(context.Background(), strictcomposition.ActiveRequest{
		Now: now, Identity: identity, CredentialRevision: revision,
		Runtime:         l10SelectionRuntimeSource{metadata: l7network.Metadata{Identity: networkIdentity, Status: l7network.StatusInspected, StructuralInspected: true, TAPInspected: true, RulesInspected: true, RawPacketIsolationVerified: true, RuleDigest: "rule-digest-l10-strict"}},
		NetworkIdentity: networkIdentity, CredentialActive: active, TemplatePolicyID: identity.TemplatePolicyID,
		Template:        templateResult,
		TemplateBinding: selection.BindingRequest{ExecutionID: identity.ExecutionID, SandboxID: identity.SandboxID, RuntimeID: identity.RuntimeID, RuntimeDriver: identity.RuntimeDriver, IsolationLevel: sandbox.SandboxIsolationLevelVM, ManifestDigest: digest},
		Workspace:       workspace,
	})
	if decision.State != sandbox.SandboxStrictCompositionStateActive {
		t.Fatalf("EvaluateActive() decision = %#v, want active", decision)
	}
	return &StrictCompositionAuthority{Attestation: attestation, SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, RuntimeID: identity.RuntimeID, Now: now}, decision
}
