// Package strictcomposition owns the live L10 proof conjunction.
package strictcomposition

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
	"github.com/jywlabs/hal/internal/sandboxtemplate/selection"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

const (
	MaxActiveAttestationAge = sandbox.SandboxStrictCompositionMaxActiveAge
	MaxWorkspaceEvidenceAge = 5 * time.Minute
)

var ErrAttestationSerialization = errors.New("strict composition live attestation is not serializable")

// RuntimeProofSource freshly inspects the exact retained L5/L7 authority.
type RuntimeProofSource interface {
	Inspect(context.Context, l7network.Identity) (l7network.Metadata, error)
}

// WorkspaceEvidence minimally correlates existing workspace and sync-out
// contracts to the exact sandbox execution and workspace policy.
type WorkspaceEvidence struct {
	SandboxID         string
	ExecutionID       string
	WorkspacePolicyID string
	ObservedAt        time.Time
	Workspace         sandbox.SandboxWorkspace
	SyncOut           sandboxworkspace.SyncOutSummary
	SafeApply         *sandboxworkspace.SafeApplyResult
	WarningCodes      []string
}

// ActiveRequest is live-only and intentionally has no JSON tags.
type ActiveRequest struct {
	Now                time.Time
	Identity           sandboxruntime.JobCredentialIdentity
	CredentialRevision uint64
	Runtime            RuntimeProofSource
	NetworkIdentity    l7network.Identity
	CredentialActive   sandboxruntime.JobCredentialActiveProof
	CredentialCleanup  sandboxruntime.JobCredentialCleanupProof
	TemplatePolicyID   string
	Template           selection.Result
	TemplateBinding    selection.BindingRequest
	Workspace          WorkspaceEvidence
	FallbackUsed       bool
	Simulated          bool
	WarningCodes       []string
	CleanupIncomplete  bool
}

type attestationState struct {
	mu                   sync.Mutex
	token                [32]byte
	identity             sandboxruntime.JobCredentialIdentity
	identityDigest       [32]byte
	credentialRevision   uint64
	credentialProof      sandboxruntime.JobCredentialActiveProof
	templatePolicyID     string
	templateFingerprint  [32]byte
	workspacePolicyID    string
	workspaceFingerprint [32]byte
	observedAt           time.Time
	expiresAt            time.Time
	consumed             bool
}

// ActiveAttestation is an opaque live token. Copies share one consumption
// state, so terminal completion cannot be replayed through a copied value.
type ActiveAttestation struct {
	token [32]byte
	state *attestationState
}

func (ActiveAttestation) String() string   { return "<strictcomposition.ActiveAttestation>" }
func (ActiveAttestation) GoString() string { return "<strictcomposition.ActiveAttestation>" }

func (ActiveAttestation) MarshalJSON() ([]byte, error) { return nil, ErrAttestationSerialization }
func (ActiveAttestation) MarshalText() ([]byte, error) { return nil, ErrAttestationSerialization }

// TerminalRequest closes the credential phase of one exact active decision.
type TerminalRequest struct {
	Now                time.Time
	Identity           sandboxruntime.JobCredentialIdentity
	CredentialRevision uint64
	Attestation        ActiveAttestation
	CredentialActive   sandboxruntime.JobCredentialActiveProof
	CredentialCleanup  sandboxruntime.JobCredentialCleanupProof
	TemplatePolicyID   string
	Template           selection.Result
	TemplateBinding    selection.BindingRequest
	Workspace          WorkspaceEvidence
	WarningCodes       []string
	CleanupIncomplete  bool
}

// EvaluateActive performs the live conjunction once and returns no authority
// when any input is missing, stale, weak, warning-bearing, or uncorrelated.
func EvaluateActive(ctx context.Context, request ActiveRequest) (ActiveAttestation, sandbox.SandboxStrictCompositionDecision) {
	if ctx == nil || request.Now.IsZero() || sandboxruntime.ValidateJobCredentialIdentity(request.Identity) != nil || request.CredentialRevision == 0 {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeIdentityInvalid)
	}
	if request.Identity.RuntimeDriver != sandbox.SandboxRuntimeDriverMicroVM {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeIdentityMismatch)
	}
	if request.FallbackUsed {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeFallbackForbidden)
	}
	if request.Simulated {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeSimulationForbidden)
	}
	if len(request.WarningCodes) != 0 {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeWarningBearing)
	}
	if request.CleanupIncomplete {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeCleanupIncomplete)
	}

	if runtimeSourceNil(request.Runtime) {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeRuntimeProofMissing)
	}
	expectedNetwork := networkIdentity(request.Identity)
	if request.NetworkIdentity != expectedNetwork {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeRuntimeProofMismatch)
	}
	if err := ctx.Err(); err != nil {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeRuntimeProofStale)
	}
	metadata, inspected := inspectRuntimeProof(ctx, request.Runtime, expectedNetwork)
	if !inspected || ctx.Err() != nil {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeRuntimeProofStale)
	}
	if !runtimeMetadataExact(metadata, expectedNetwork) {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeRuntimeProofMismatch)
	}

	if sandboxruntime.ActiveProofKind(request.CredentialActive) == "" {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeCredentialActiveMissing)
	}
	if sandboxruntime.CleanupProofKind(request.CredentialCleanup) != "" {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeCredentialProofMismatch)
	}
	if err := sandboxruntime.ValidateJobCredentialActiveProof(request.CredentialActive, request.Identity, request.CredentialRevision, request.Now); err != nil {
		return ActiveAttestation{}, blocked(activeProofFailureCode(err))
	}

	templateFingerprint, code := validateTemplate(request.Identity, request.TemplatePolicyID, request.Template, request.TemplateBinding)
	if code != "" {
		return ActiveAttestation{}, blocked(code)
	}
	workspaceFingerprint, code := validateWorkspace(request.Now, request.Identity, request.Workspace)
	if code != "" {
		return ActiveAttestation{}, blocked(code)
	}

	identityDigest, err := sandboxruntime.JobCredentialIdentityDigest(request.Identity)
	if err != nil {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeIdentityInvalid)
	}
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return ActiveAttestation{}, blocked(sandbox.SandboxStrictCompositionCodeAttestationStale)
	}
	expiresAt := request.Now.Add(MaxActiveAttestationAge)
	state := &attestationState{
		token: token, identity: cloneCredentialIdentity(request.Identity), identityDigest: identityDigest,
		credentialRevision: request.CredentialRevision, credentialProof: request.CredentialActive,
		templatePolicyID: request.TemplatePolicyID, templateFingerprint: templateFingerprint,
		workspacePolicyID: request.Workspace.WorkspacePolicyID, workspaceFingerprint: workspaceFingerprint,
		observedAt: request.Now.UTC(), expiresAt: expiresAt.UTC(),
	}
	attestation := ActiveAttestation{token: token, state: state}
	return attestation, decision(
		sandbox.SandboxStrictCompositionStateActive,
		sandbox.SandboxStrictCompositionCodeReady,
		compositionID(token), request.Now, expiresAt,
	)
}

// EvaluateTerminal consumes the exact active attestation only after fresh L8
// absence and unchanged template/workspace evidence are both established.
func EvaluateTerminal(ctx context.Context, request TerminalRequest) sandbox.SandboxStrictCompositionDecision {
	if ctx == nil || request.Now.IsZero() || sandboxruntime.ValidateJobCredentialIdentity(request.Identity) != nil || request.CredentialRevision == 0 {
		return blocked(sandbox.SandboxStrictCompositionCodeIdentityInvalid)
	}
	if ctx.Err() != nil {
		return blocked(sandbox.SandboxStrictCompositionCodeAttestationStale)
	}
	if request.Identity.RuntimeDriver != sandbox.SandboxRuntimeDriverMicroVM {
		return blocked(sandbox.SandboxStrictCompositionCodeIdentityMismatch)
	}
	state := request.Attestation.state
	if state == nil || !tokensEqual(request.Attestation.token, state.token) {
		return blocked(sandbox.SandboxStrictCompositionCodeAttestationStale)
	}
	identityDigest, err := sandboxruntime.JobCredentialIdentityDigest(request.Identity)
	if err != nil {
		return blocked(sandbox.SandboxStrictCompositionCodeIdentityInvalid)
	}
	state.mu.Lock()
	identityMismatch := state.identityDigest != identityDigest ||
		state.identity.SandboxID != request.Identity.SandboxID || state.identity.ExecutionID != request.Identity.ExecutionID ||
		state.identity.RuntimeID != request.Identity.RuntimeID
	revisionMismatch := state.credentialRevision != request.CredentialRevision
	stale := state.consumed || request.Now.Before(state.observedAt)
	state.mu.Unlock()
	if identityMismatch {
		return blocked(sandbox.SandboxStrictCompositionCodeIdentityMismatch)
	}
	if stale {
		return blocked(sandbox.SandboxStrictCompositionCodeAttestationStale)
	}
	if revisionMismatch {
		return blocked(sandbox.SandboxStrictCompositionCodeCredentialProofMismatch)
	}
	if len(request.WarningCodes) != 0 {
		return blocked(sandbox.SandboxStrictCompositionCodeWarningBearing)
	}
	if request.CleanupIncomplete {
		return blocked(sandbox.SandboxStrictCompositionCodeCleanupIncomplete)
	}
	if sandboxruntime.ActiveProofKind(request.CredentialActive) != "" {
		return blocked(sandbox.SandboxStrictCompositionCodeCredentialProofMismatch)
	}
	if sandboxruntime.CleanupProofKind(request.CredentialCleanup) == "" {
		return blocked(sandbox.SandboxStrictCompositionCodeCredentialCleanupMissing)
	}
	if err := sandboxruntime.ValidateJobCredentialCleanupProof(request.CredentialCleanup, request.Identity, request.CredentialRevision, request.Now); err != nil {
		return blocked(cleanupProofFailureCode(err))
	}

	templateFingerprint, code := validateTemplate(request.Identity, request.TemplatePolicyID, request.Template, request.TemplateBinding)
	if code != "" {
		return blocked(code)
	}
	workspaceFingerprint, code := validateWorkspace(request.Now, request.Identity, request.Workspace)
	if code != "" {
		return blocked(code)
	}
	if request.TemplatePolicyID != state.templatePolicyID || templateFingerprint != state.templateFingerprint {
		return blocked(sandbox.SandboxStrictCompositionCodeTemplateProofMismatch)
	}
	if request.Workspace.WorkspacePolicyID != state.workspacePolicyID || workspaceFingerprint != state.workspaceFingerprint {
		return blocked(sandbox.SandboxStrictCompositionCodeWorkspaceProofMismatch)
	}

	state.mu.Lock()
	if state.consumed || ctx.Err() != nil {
		state.mu.Unlock()
		return blocked(sandbox.SandboxStrictCompositionCodeAttestationStale)
	}
	state.consumed = true
	state.mu.Unlock()
	return decision(
		sandbox.SandboxStrictCompositionStateComplete,
		sandbox.SandboxStrictCompositionCodeComplete,
		compositionID(state.token), request.Now, time.Time{},
	)
}

// AttestationValid checks the exact live identity, freshness, active L8 proof,
// and single-use state. Durable decision data is deliberately insufficient.
func AttestationValid(attestation ActiveAttestation, sandboxID, executionID, runtimeID string, now time.Time) bool {
	state := attestation.state
	if state == nil || now.IsZero() || !tokensEqual(attestation.token, state.token) {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return !state.consumed && sandboxID == state.identity.SandboxID && executionID == state.identity.ExecutionID && runtimeID == state.identity.RuntimeID &&
		!now.Before(state.observedAt) && now.Before(state.expiresAt) &&
		sandboxruntime.ValidateJobCredentialActiveProof(state.credentialProof, state.identity, state.credentialRevision, now) == nil
}

// AttestationMatchesDecision proves that a sanitized active decision was
// emitted alongside this exact opaque authority. The decision remains
// informational and cannot satisfy this check without the live token.
func AttestationMatchesDecision(attestation ActiveAttestation, decision sandbox.SandboxStrictCompositionDecision) bool {
	state := attestation.state
	if state == nil || !tokensEqual(attestation.token, state.token) {
		return false
	}
	decision = sandbox.SanitizeSandboxStrictCompositionDecision(decision)
	state.mu.Lock()
	defer state.mu.Unlock()
	expected := decisionForActiveAttestation(state)
	return !state.consumed && reflect.DeepEqual(decision, expected)
}

func decisionForActiveAttestation(state *attestationState) sandbox.SandboxStrictCompositionDecision {
	return decision(
		sandbox.SandboxStrictCompositionStateActive,
		sandbox.SandboxStrictCompositionCodeReady,
		compositionID(state.token),
		state.observedAt,
		state.expiresAt,
	)
}

func validateTemplate(identity sandboxruntime.JobCredentialIdentity, policyID string, result selection.Result, bindingRequest selection.BindingRequest) ([32]byte, sandbox.SandboxStrictCompositionCode) {
	if strings.TrimSpace(policyID) == "" || result.ManifestDigest == nil {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeTemplateProofMissing
	}
	if policyID != identity.TemplatePolicyID || bindingRequest.ExecutionID != identity.ExecutionID || bindingRequest.SandboxID != identity.SandboxID ||
		bindingRequest.RuntimeID != identity.RuntimeID || bindingRequest.RuntimeDriver != sandbox.SandboxRuntimeDriverMicroVM ||
		bindingRequest.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeTemplateProofMismatch
	}
	if string(result.Trust.Mode) != "strict" || string(result.Trust.Decision) != "trusted" ||
		!templateFindingAliasesEmpty(result) {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeTemplateProofRejected
	}
	binding, err := selection.Bind(result, bindingRequest)
	if err != nil {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeTemplateProofRejected
	}
	if binding.ExecutionID != identity.ExecutionID || binding.SandboxID != identity.SandboxID || binding.RuntimeID != identity.RuntimeID ||
		binding.RuntimeDriver != sandbox.SandboxRuntimeDriverMicroVM || binding.IsolationLevel != sandbox.SandboxIsolationLevelVM || binding.ManifestDigest == nil {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeTemplateProofMismatch
	}
	digest := sha256.New()
	writeDigestString(digest, policyID)
	writeDigestString(digest, binding.ExecutionID)
	writeDigestString(digest, binding.SandboxID)
	writeDigestString(digest, binding.RuntimeID)
	writeDigestString(digest, binding.RuntimeDriver)
	writeDigestString(digest, binding.IsolationLevel)
	writeDigestString(digest, binding.RuntimeImage)
	writeDigestString(digest, string(binding.ManifestDigest.Algorithm))
	writeDigestString(digest, binding.ManifestDigest.Value)
	// Nil and explicit-empty finding lists represent the same canonical strict
	// state. Terminal evaluation revalidates this predicate before comparing the
	// fingerprint, so a post-active warning or error cannot reach completion.
	writeDigestString(digest, "template-finding-aliases-empty-v1")
	var fingerprint [32]byte
	copy(fingerprint[:], digest.Sum(nil))
	return fingerprint, ""
}

func templateFindingAliasesEmpty(result selection.Result) bool {
	if len(result.Lock.Warnings) != 0 || len(result.Trust.Warnings) != 0 || len(result.Trust.Errors) != 0 {
		return false
	}
	if provenance := result.Provenance; provenance != nil &&
		((provenance.Document != nil && len(provenance.Document.WarningCodes) != 0) ||
			(provenance.TemplateReference != nil && len(provenance.TemplateReference.WarningCodes) != 0) ||
			(provenance.RuntimeImage != nil && len(provenance.RuntimeImage.WarningCodes) != 0) ||
			(provenance.SourceArtifact != nil && len(provenance.SourceArtifact.WarningCodes) != 0)) {
		return false
	}
	return runtimeTemplateFindingsEmpty(result.RuntimeMetadata)
}

func runtimeTemplateFindingsEmpty(metadata *sandboxruntime.RuntimeTemplateLockMetadata) bool {
	if metadata == nil {
		return true
	}
	return runtimeTemplateEntryWarningsEmpty(metadata.Document) &&
		runtimeTemplateEntryWarningsEmpty(metadata.TemplateReference) &&
		runtimeTemplateEntryWarningsEmpty(metadata.RuntimeImage) &&
		runtimeTemplateEntryWarningsEmpty(metadata.SourceArtifact) &&
		(metadata.TrustPolicy == nil ||
			(len(metadata.TrustPolicy.WarningCodes) == 0 && len(metadata.TrustPolicy.ErrorCodes) == 0))
}

func runtimeTemplateEntryWarningsEmpty(entry *sandboxruntime.RuntimeTemplateLockEntryMetadata) bool {
	return entry == nil || len(entry.WarningCodes) == 0
}

func validateWorkspace(now time.Time, identity sandboxruntime.JobCredentialIdentity, evidence WorkspaceEvidence) ([32]byte, sandbox.SandboxStrictCompositionCode) {
	if strings.TrimSpace(evidence.SandboxID) == "" || strings.TrimSpace(evidence.ExecutionID) == "" ||
		strings.TrimSpace(evidence.WorkspacePolicyID) == "" || evidence.ObservedAt.IsZero() {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeWorkspaceProofMissing
	}
	if evidence.SandboxID != identity.SandboxID || evidence.ExecutionID != identity.ExecutionID || evidence.WorkspacePolicyID != identity.WorkspacePolicyID {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeWorkspaceProofMismatch
	}
	if evidence.ObservedAt.After(now) || now.Sub(evidence.ObservedAt) > MaxWorkspaceEvidenceAge {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeWorkspaceProofStale
	}
	workspace := evidence.Workspace
	if !reflect.DeepEqual(evidence.SyncOut, sandboxworkspace.SanitizeSyncOutSummary(evidence.SyncOut)) ||
		(evidence.SafeApply != nil && !reflect.DeepEqual(*evidence.SafeApply, sandboxworkspace.SanitizeSafeApplyResult(*evidence.SafeApply))) {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe
	}
	if workspace.Repo != "" || !isolatedWorkspace(workspace) ||
		workspace.Mode != evidence.SyncOut.Workspace.Mode || workspace.InputSource != evidence.SyncOut.Workspace.InputSource ||
		workspace.Branch != evidence.SyncOut.Workspace.Branch || workspace.SyncRef != evidence.SyncOut.Workspace.SyncRef {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe
	}
	if len(evidence.WarningCodes) != 0 || len(evidence.SyncOut.Warnings) != 0 ||
		evidence.SyncOut.Recovery.Status != sandboxworkspace.SyncOutRecoveryStatusCollected ||
		!evidence.SyncOut.Apply.Eligible {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe
	}
	artifact := workspaceApplyArtifact(evidence.SyncOut)
	if artifact == nil || artifact.ApplyEligibility == nil || artifact.ID == "" ||
		evidence.SyncOut.Apply.ArtifactID != artifact.ID || evidence.SyncOut.Apply.Mode == "" ||
		evidence.SyncOut.Apply.Mode != artifact.ApplyEligibility.Mode || !artifact.ApplyEligibility.Eligible ||
		!exactEligibleApplyReasons(evidence.SyncOut.Apply.Mode, evidence.SyncOut.Apply.Reasons) ||
		!exactEligibleApplyReasons(artifact.ApplyEligibility.Mode, artifact.ApplyEligibility.Reasons) {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe
	}
	if evidence.SafeApply != nil && !safeApplyExact(*evidence.SafeApply, evidence.SyncOut.Apply) {
		return [32]byte{}, sandbox.SandboxStrictCompositionCodeWorkspaceProofUnsafe
	}
	digest := sha256.New()
	for _, value := range []string{
		evidence.SandboxID, evidence.ExecutionID, evidence.WorkspacePolicyID,
		workspace.Mode, workspace.InputSource, workspace.Branch, workspace.SyncRef,
		string(evidence.SyncOut.Recovery.Status), string(evidence.SyncOut.Apply.Mode), evidence.SyncOut.Apply.ArtifactID,
		artifact.ID, string(artifact.Kind), artifact.DisplayName, artifact.DisplayPath, artifact.StoredPath,
	} {
		writeDigestString(digest, value)
	}
	if evidence.SafeApply != nil {
		for _, value := range []string{string(evidence.SafeApply.Status), string(evidence.SafeApply.Mode), evidence.SafeApply.ArtifactID} {
			writeDigestString(digest, value)
		}
	}
	var fingerprint [32]byte
	copy(fingerprint[:], digest.Sum(nil))
	return fingerprint, ""
}

func exactEligibleApplyReasons(mode sandboxworkspace.SyncOutApplyMode, reasons []sandboxworkspace.SyncOutApplyEligibilityReason) bool {
	if len(reasons) != 1 {
		return false
	}
	switch mode {
	case sandboxworkspace.SyncOutApplyModePatch:
		return reasons[0] == sandboxworkspace.SyncOutApplyEligibilityReasonEligiblePatch
	case sandboxworkspace.SyncOutApplyModeBundle:
		return reasons[0] == sandboxworkspace.SyncOutApplyEligibilityReasonEligibleBundle
	default:
		return false
	}
}

func isolatedWorkspace(workspace sandbox.SandboxWorkspace) bool {
	switch workspace.Mode {
	case sandbox.SandboxWorkspaceModeClone:
		return workspace.InputSource == sandbox.SandboxWorkspaceInputSourceRemoteRef || workspace.InputSource == sandbox.SandboxWorkspaceInputSourceGitBundle
	case sandbox.SandboxWorkspaceModeCopy:
		return workspace.InputSource == sandbox.SandboxWorkspaceInputSourceCopy
	default:
		return false
	}
}

func workspaceApplyArtifact(summary sandboxworkspace.SyncOutSummary) *sandboxworkspace.SyncOutArtifact {
	switch summary.Apply.Mode {
	case sandboxworkspace.SyncOutApplyModePatch:
		if summary.Committed.Patch != nil && summary.Committed.Patch.ApplyEligibility != nil {
			return summary.Committed.Patch
		}
	case sandboxworkspace.SyncOutApplyModeBundle:
		if summary.Committed.Bundle != nil && summary.Committed.Bundle.ApplyEligibility != nil {
			return summary.Committed.Bundle
		}
	}
	return nil
}

func safeApplyExact(result sandboxworkspace.SafeApplyResult, apply sandboxworkspace.SyncOutApplyDecision) bool {
	if len(result.Warnings) != 0 || len(result.HandoffInstructions) != 0 || !result.DryRunPassed ||
		result.Mode != apply.Mode || result.ArtifactID != apply.ArtifactID ||
		!exactEligibleApplyReasons(result.Mode, result.Reasons) {
		return false
	}
	switch result.Status {
	case sandboxworkspace.SafeApplyStatusDryRunPassed:
		return !result.Applied
	case sandboxworkspace.SafeApplyStatusApplied:
		return result.Applied
	default:
		return false
	}
}

func runtimeMetadataExact(metadata l7network.Metadata, identity l7network.Identity) bool {
	return metadata.Identity == identity && metadata.Status == l7network.StatusInspected &&
		metadata.StructuralInspected && metadata.TAPInspected && metadata.RulesInspected &&
		metadata.RawPacketIsolationVerified && strings.TrimSpace(metadata.RuleDigest) != ""
}

func networkIdentity(identity sandboxruntime.JobCredentialIdentity) l7network.Identity {
	return l7network.Identity{
		SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID, WorkerID: identity.WorkerID,
		RuntimeGenerationID: identity.RuntimeGeneration, PlanID: identity.NetworkPlanID,
		PolicySnapshotID: identity.PolicySnapshotID, ProxySessionID: identity.ProxySessionID,
		ProxyGenerationID: identity.ProxyGenerationID, TopologyGenerationID: identity.TopologyGenerationID,
		RuleGenerationID: identity.RuleGenerationID,
	}
}

func cloneCredentialIdentity(identity sandboxruntime.JobCredentialIdentity) sandboxruntime.JobCredentialIdentity {
	identity.BindingIDs = append([]string(nil), identity.BindingIDs...)
	identity.DeliveryModes = append([]sandboxruntime.JobCredentialDeliveryMode(nil), identity.DeliveryModes...)
	return identity
}

func runtimeSourceNil(source RuntimeProofSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	return (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface || value.Kind() == reflect.Map || value.Kind() == reflect.Func || value.Kind() == reflect.Slice) && value.IsNil()
}

func inspectRuntimeProof(ctx context.Context, source RuntimeProofSource, identity l7network.Identity) (metadata l7network.Metadata, inspected bool) {
	defer func() {
		if recover() != nil {
			metadata = l7network.Metadata{}
			inspected = false
		}
	}()
	metadata, err := source.Inspect(ctx, identity)
	return metadata, err == nil
}

func activeProofFailureCode(err error) sandbox.SandboxStrictCompositionCode {
	if errors.Is(err, sandboxruntime.ErrJobCredentialExpired) || errors.Is(err, sandboxruntime.ErrJobCredentialProofStale) {
		return sandbox.SandboxStrictCompositionCodeCredentialProofStale
	}
	return sandbox.SandboxStrictCompositionCodeCredentialProofMismatch
}

func cleanupProofFailureCode(err error) sandbox.SandboxStrictCompositionCode {
	if errors.Is(err, sandboxruntime.ErrJobCredentialProofStale) || errors.Is(err, sandboxruntime.ErrJobCredentialExpired) {
		return sandbox.SandboxStrictCompositionCodeCredentialProofStale
	}
	return sandbox.SandboxStrictCompositionCodeCredentialProofMismatch
}

func blocked(code sandbox.SandboxStrictCompositionCode) sandbox.SandboxStrictCompositionDecision {
	return sandbox.SanitizeSandboxStrictCompositionDecision(sandbox.SandboxStrictCompositionDecision{
		State: sandbox.SandboxStrictCompositionStateBlocked,
		Code:  code,
	})
}

func decision(state sandbox.SandboxStrictCompositionState, code sandbox.SandboxStrictCompositionCode, composition string, observedAt, expiresAt time.Time) sandbox.SandboxStrictCompositionDecision {
	evidence := make([]sandbox.SandboxStrictCompositionEvidence, 0, 4)
	for _, kind := range []sandbox.SandboxStrictCompositionEvidenceKind{
		sandbox.SandboxStrictCompositionEvidenceRuntime,
		sandbox.SandboxStrictCompositionEvidenceCredential,
		sandbox.SandboxStrictCompositionEvidenceTemplate,
		sandbox.SandboxStrictCompositionEvidenceWorkspace,
	} {
		evidence = append(evidence, sandbox.SandboxStrictCompositionEvidence{Kind: kind, State: state, Code: code})
	}
	return sandbox.SanitizeSandboxStrictCompositionDecision(sandbox.SandboxStrictCompositionDecision{
		State: state, Code: code, CompositionID: composition,
		ObservedAt: observedAt.UTC(), ExpiresAt: expiresAt.UTC(), Evidence: evidence,
	})
}

func compositionID(token [32]byte) string {
	digest := sha256.Sum256(token[:])
	return "composition-" + hex.EncodeToString(digest[:12])
}

func tokensEqual(left, right [32]byte) bool {
	return subtle.ConstantTimeCompare(left[:], right[:]) == 1
}

type digestWriter interface {
	Write([]byte) (int, error)
}

func writeDigestString(writer digestWriter, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = writer.Write([]byte(value))
}
