package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

type sandboxSyncOutApplier func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error)

type sandboxSyncOutApplyRequest struct {
	ExecutionID string
	Purpose     sandboxexecution.Purpose
	ProjectDir  string
	Options     sandboxSyncOutOptions
	Authorize   func(sandboxexecution.Store, *sandboxexecution.Manifest) error
	Store       sandboxexecution.Store
	Manifest    *sandboxexecution.Manifest
	Summary     sandboxworkspace.SyncOutSummary
	Artifact    *sandboxworkspace.SyncOutArtifact
	Payload     *os.File
	PayloadPath string
	Handoff     sandboxworkspace.SafeApplyResult
}

func sandboxCommittedSyncOutBaseRef(workspace *sandbox.SandboxWorkspace, fallback string) string {
	if workspace != nil {
		if syncRef := strings.TrimSpace(workspace.SyncRef); syncRef != "" {
			return syncRef
		}
	}
	return strings.TrimSpace(fallback)
}

func applyRunSandboxSyncOut(ctx context.Context, store sandboxexecution.Store, req runSandboxRequest, deps runSandboxDeps) error {
	if !req.SyncOut.Enabled {
		return nil
	}
	apply := deps.applySyncOut
	if apply == nil {
		apply = defaultSandboxSyncOutApplier
	}
	if _, err := applySandboxSyncOut(ctx, store, sandboxSyncOutApplyRequest{
		ExecutionID: req.ExecutionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  req.ProjectDir,
		Options:     req.SyncOut,
	}, apply); err != nil {
		return fmt.Errorf("apply run sandbox sync-out: %w", err)
	}
	return nil
}

func applyAutoSandboxSyncOut(ctx context.Context, store sandboxexecution.Store, req autoSandboxRequest, deps autoSandboxDeps) error {
	if !req.SyncOut.Enabled {
		return nil
	}
	apply := deps.applySyncOut
	if apply == nil {
		apply = defaultSandboxSyncOutApplier
	}
	if _, err := applySandboxSyncOut(ctx, store, sandboxSyncOutApplyRequest{
		ExecutionID: req.ExecutionID,
		Purpose:     sandboxexecution.PurposeAuto,
		ProjectDir:  req.ProjectDir,
		Options:     req.SyncOut,
	}, apply); err != nil {
		return fmt.Errorf("apply auto sandbox sync-out: %w", err)
	}
	return nil
}

func applySandboxSyncOut(ctx context.Context, store sandboxexecution.Store, req sandboxSyncOutApplyRequest, apply sandboxSyncOutApplier) (sandboxworkspace.SafeApplyResult, error) {
	if apply == nil {
		return sandboxworkspace.SafeApplyResult{}, nil
	}
	var result sandboxworkspace.SafeApplyResult
	err := store.WithLockedExecution(req.ExecutionID, func(lockedStore sandboxexecution.Store) error {
		var applyErr error
		result, applyErr = applySandboxSyncOutLocked(ctx, lockedStore, req, apply)
		return applyErr
	})
	return result, err
}

func applySandboxSyncOutLocked(ctx context.Context, store sandboxexecution.Store, req sandboxSyncOutApplyRequest, apply sandboxSyncOutApplier) (sandboxworkspace.SafeApplyResult, error) {
	manifest, err := store.LoadManifest(req.ExecutionID)
	if err != nil {
		return sandboxworkspace.SafeApplyResult{}, fmt.Errorf("load sandbox execution manifest before sync-out apply: %w", err)
	}
	if req.Authorize != nil {
		if err := req.Authorize(store, manifest); err != nil {
			return sandboxworkspace.SafeApplyResult{}, err
		}
	}
	if existing, handled, existingErr := sandboxSyncOutExistingApplyResult(manifest, req.Options.Apply); handled {
		return existing, existingErr
	}
	req.Store = store
	req.Manifest = manifest
	req.Summary = sandboxexecution.BuildSyncOutSummaryFromArtifacts(manifest)
	if err := populateSandboxSyncOutApplySelection(&req); err != nil {
		return sandboxworkspace.SafeApplyResult{}, err
	}
	if req.Payload != nil {
		defer req.Payload.Close()
	}
	intent := sandboxworkspace.SafeApplyResult{}
	hasMutationIntent := req.Options.Apply && req.Artifact != nil && req.Payload != nil
	if hasMutationIntent {
		intent = sandboxSyncOutUnknownApplyOutcome(req)
		if persistErr := persistSandboxSyncOutApplyMetadata(store, req.ExecutionID, req.Summary, intent); persistErr != nil {
			return sandboxworkspace.SafeApplyResult{}, fmt.Errorf("persist sandbox host apply intent: %w", persistErr)
		}
	}
	result, err := apply(ctx, req)
	result = sandboxworkspace.SanitizeSafeApplyResult(result)
	result = sandboxSyncOutNormalizeApplyResult(req, result)
	result = sandboxSyncOutApplyResultWithHandoffInstructions(req, result)
	result = sandboxworkspace.SanitizeSafeApplyResult(result)
	if hasMutationIntent && err != nil {
		return intent, err
	}
	if hasMutationIntent && !sandboxSyncOutApplyResultIsConclusive(result) {
		return intent, fmt.Errorf("sandbox host apply outcome is not conclusive; manual inspection is required before retry")
	}
	if persistErr := persistSandboxSyncOutApplyMetadataTransition(store, req.ExecutionID, req.Summary, result, hasMutationIntent); persistErr != nil {
		err = errors.Join(err, persistErr)
	}
	return result, err
}

func sandboxSyncOutExistingApplyResult(manifest *sandboxexecution.Manifest, mutationRequested bool) (sandboxworkspace.SafeApplyResult, bool, error) {
	if manifest == nil || manifest.SyncOutApply == nil {
		return sandboxworkspace.SafeApplyResult{}, false, nil
	}
	existing := sandboxworkspace.SanitizeSafeApplyResult(*cloneSandboxSafeApplyResult(manifest.SyncOutApply))
	if existing.Applied || existing.Status == sandboxworkspace.SafeApplyStatusApplied {
		if mutationRequested {
			return existing, true, fmt.Errorf("sandbox execution %q already records a successful host apply", manifest.ID)
		}
		return existing, true, nil
	}
	if sandboxSyncOutApplyHasReason(existing, sandboxworkspace.SyncOutApplyEligibilityReasonApplyOutcomeUnknown) {
		return existing, true, fmt.Errorf("sandbox execution %q has an unknown host apply outcome; manual inspection is required before retry", manifest.ID)
	}
	return sandboxworkspace.SafeApplyResult{}, false, nil
}

func sandboxSyncOutUnknownApplyOutcome(req sandboxSyncOutApplyRequest) sandboxworkspace.SafeApplyResult {
	result := sandboxworkspace.SafeApplyResult{
		Status:  sandboxworkspace.SafeApplyStatusHandoffRequired,
		Applied: false,
		Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{
			sandboxworkspace.SyncOutApplyEligibilityReasonApplyOutcomeUnknown,
		},
	}
	if req.Artifact != nil {
		result.Mode = sandboxSyncOutArtifactEligibilityMode(req.Artifact)
		result.ArtifactID = req.Artifact.ID
		result.DisplayName = req.Artifact.DisplayName
		result.DisplayPath = req.Artifact.DisplayPath
	}
	result = sandboxSyncOutApplyResultWithHandoffInstructions(req, result)
	return sandboxworkspace.SanitizeSafeApplyResult(result)
}

func sandboxSyncOutApplyResultIsConclusive(result sandboxworkspace.SafeApplyResult) bool {
	switch result.Status {
	case sandboxworkspace.SafeApplyStatusApplied:
		return result.Applied
	case sandboxworkspace.SafeApplyStatusDryRunPassed:
		return !result.Applied && result.DryRunPassed
	case sandboxworkspace.SafeApplyStatusHandoffRequired:
		return !result.Applied
	default:
		return false
	}
}

func sandboxSyncOutApplyHasReason(result sandboxworkspace.SafeApplyResult, want sandboxworkspace.SyncOutApplyEligibilityReason) bool {
	for _, reason := range result.Reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func defaultSandboxSyncOutApplier(ctx context.Context, req sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
	if req.Artifact == nil || (req.Payload == nil && strings.TrimSpace(req.PayloadPath) == "") {
		return req.Handoff, nil
	}
	return sandboxworkspace.SafeApply(ctx, sandboxworkspace.SafeApplyRequest{
		ProjectDir:  req.ProjectDir,
		Payload:     req.Payload,
		PayloadPath: req.PayloadPath,
		Artifact:    *req.Artifact,
		Mutate:      req.Options.Apply,
	})
}

func populateSandboxSyncOutApplySelection(req *sandboxSyncOutApplyRequest) error {
	if req == nil {
		return nil
	}
	req.Handoff = sandboxSyncOutApplyHandoff(req.Summary, []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact})
	if !req.Options.Apply {
		req.Handoff = sandboxSyncOutApplyHandoff(req.Summary, []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonApplyDisabled})
		return nil
	}
	artifact := selectSandboxSyncOutApplyArtifact(req.Summary)
	if artifact == nil {
		req.Handoff = sandboxSyncOutApplyHandoff(req.Summary, sandboxSyncOutNoCandidateReasons(req.Summary))
		return nil
	}
	payload, err := req.Store.OpenStoredFile(req.ExecutionID, artifact.StoredPath)
	if err != nil {
		return fmt.Errorf("open eligible sync-out artifact payload: %w", err)
	}
	artifactCopy := *artifact
	req.Artifact = &artifactCopy
	req.Payload = payload
	cleanStoredPath := filepath.FromSlash(pathpkg.Clean(artifact.StoredPath))
	req.PayloadPath = filepath.Join(req.Store.Root(), cleanStoredPath)
	req.Handoff = sandboxworkspace.SafeApplyResult{}
	return nil
}

func selectSandboxSyncOutApplyArtifact(summary sandboxworkspace.SyncOutSummary) *sandboxworkspace.SyncOutArtifact {
	candidates := []*sandboxworkspace.SyncOutArtifact{summary.Committed.Patch, summary.Committed.Bundle}
	if summary.Apply.Eligible {
		for _, candidate := range candidates {
			if sandboxSyncOutArtifactMatchesApplyDecision(candidate, summary.Apply) && sandboxSyncOutArtifactExplicitlyEligible(candidate) {
				return candidate
			}
		}
	}
	for _, candidate := range candidates {
		if sandboxSyncOutArtifactExplicitlyEligible(candidate) {
			return candidate
		}
	}
	return nil
}

func sandboxSyncOutArtifactMatchesApplyDecision(artifact *sandboxworkspace.SyncOutArtifact, decision sandboxworkspace.SyncOutApplyDecision) bool {
	if artifact == nil {
		return false
	}
	if strings.TrimSpace(decision.ArtifactID) != "" && strings.TrimSpace(artifact.ID) != strings.TrimSpace(decision.ArtifactID) {
		return false
	}
	if decision.Mode != "" && sandboxSyncOutArtifactEligibilityMode(artifact) != decision.Mode {
		return false
	}
	return true
}

func sandboxSyncOutArtifactExplicitlyEligible(artifact *sandboxworkspace.SyncOutArtifact) bool {
	if artifact == nil || artifact.ApplyEligibility == nil || !artifact.ApplyEligibility.Eligible || strings.TrimSpace(artifact.StoredPath) == "" {
		return false
	}
	mode := sandboxSyncOutArtifactEligibilityMode(artifact)
	switch mode {
	case sandboxworkspace.SyncOutApplyModePatch:
		return artifact.Kind == sandboxworkspace.SyncOutArtifactKindPatch
	case sandboxworkspace.SyncOutApplyModeBundle:
		return artifact.Kind == sandboxworkspace.SyncOutArtifactKindBundle
	default:
		return false
	}
}

func sandboxSyncOutArtifactEligibilityMode(artifact *sandboxworkspace.SyncOutArtifact) sandboxworkspace.SyncOutApplyMode {
	if artifact == nil || artifact.ApplyEligibility == nil {
		return ""
	}
	return artifact.ApplyEligibility.Mode
}

func sandboxSyncOutNoCandidateReasons(summary sandboxworkspace.SyncOutSummary) []sandboxworkspace.SyncOutApplyEligibilityReason {
	for _, artifact := range []*sandboxworkspace.SyncOutArtifact{summary.Committed.Patch, summary.Committed.Bundle} {
		if artifact != nil && artifact.ApplyEligibility != nil && len(artifact.ApplyEligibility.Reasons) > 0 {
			return append([]sandboxworkspace.SyncOutApplyEligibilityReason(nil), artifact.ApplyEligibility.Reasons...)
		}
	}
	if len(summary.Apply.Reasons) > 0 {
		return append([]sandboxworkspace.SyncOutApplyEligibilityReason(nil), summary.Apply.Reasons...)
	}
	return []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact}
}

func sandboxSyncOutApplyHandoff(summary sandboxworkspace.SyncOutSummary, reasons []sandboxworkspace.SyncOutApplyEligibilityReason) sandboxworkspace.SafeApplyResult {
	if len(reasons) == 0 {
		reasons = []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact}
	}
	return sandboxworkspace.SafeApplyResult{
		Status:   sandboxworkspace.SafeApplyStatusHandoffRequired,
		Applied:  false,
		Reasons:  append([]sandboxworkspace.SyncOutApplyEligibilityReason(nil), reasons...),
		Warnings: append([]sandboxworkspace.SyncOutWarning(nil), summary.Warnings...),
	}
}

func sandboxSyncOutApplyResultWithHandoffInstructions(req sandboxSyncOutApplyRequest, result sandboxworkspace.SafeApplyResult) sandboxworkspace.SafeApplyResult {
	if result.Status != sandboxworkspace.SafeApplyStatusHandoffRequired || result.Applied || len(result.HandoffInstructions) > 0 {
		return result
	}
	reason := sandboxSyncOutPrimaryHandoffReason(result.Reasons)
	if reason == "" {
		reason = sandboxSyncOutPrimaryHandoffReason(req.Handoff.Reasons)
	}
	if reason == "" {
		reason = sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact
	}
	result.HandoffInstructions = []sandboxworkspace.SyncOutHandoffInstruction{{
		Reason:    reason,
		Message:   sandboxSyncOutHandoffMessage(reason),
		Artifacts: sandboxSyncOutHandoffArtifactRefs(req.Summary, result),
	}}
	return result
}

func sandboxSyncOutNormalizeApplyResult(req sandboxSyncOutApplyRequest, result sandboxworkspace.SafeApplyResult) sandboxworkspace.SafeApplyResult {
	if result.Status != "" || result.Applied || result.DryRunPassed {
		return result
	}
	if req.Handoff.Status != "" {
		return req.Handoff
	}
	return sandboxSyncOutApplyHandoff(req.Summary, []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact})
}

func persistSandboxSyncOutApplyMetadata(store sandboxexecution.Store, executionID string, summary sandboxworkspace.SyncOutSummary, result sandboxworkspace.SafeApplyResult) error {
	return persistSandboxSyncOutApplyMetadataTransition(store, executionID, summary, result, false)
}

func persistSandboxSyncOutApplyMetadataTransition(
	store sandboxexecution.Store,
	executionID string,
	summary sandboxworkspace.SyncOutSummary,
	result sandboxworkspace.SafeApplyResult,
	resolveUnknown bool,
) error {
	summary = sandboxworkspace.SanitizeSyncOutSummary(summary)
	result = sandboxworkspace.SanitizeSafeApplyResult(result)
	if err := store.UpdateManifest(executionID, func(manifest *sandboxexecution.Manifest) error {
		if manifest.SyncOutApply != nil {
			current := sandboxworkspace.SanitizeSafeApplyResult(*manifest.SyncOutApply)
			if current.Applied || current.Status == sandboxworkspace.SafeApplyStatusApplied {
				return nil
			}
			if sandboxSyncOutApplyHasReason(current, sandboxworkspace.SyncOutApplyEligibilityReasonApplyOutcomeUnknown) &&
				!resolveUnknown &&
				!sandboxSyncOutApplyHasReason(result, sandboxworkspace.SyncOutApplyEligibilityReasonApplyOutcomeUnknown) {
				return nil
			}
		}
		manifest.SyncOut = cloneSandboxSyncOutSummary(&summary)
		manifest.SyncOutApply = cloneSandboxSafeApplyResult(&result)
		return nil
	}); err != nil {
		return fmt.Errorf("persist sandbox sync-out metadata: %w", err)
	}
	return nil
}

func persistFailedSandboxSyncOutHandoff(store sandboxexecution.Store, executionID string) error {
	manifest, err := store.LoadManifest(executionID)
	if err != nil {
		return fmt.Errorf("load failed sandbox execution manifest for sync-out metadata: %w", err)
	}
	summary := sandboxexecution.BuildSyncOutSummaryFromArtifacts(manifest)
	handoff := sandboxSyncOutApplyHandoff(summary, []sandboxworkspace.SyncOutApplyEligibilityReason{
		sandboxworkspace.SyncOutApplyEligibilityReasonManualReviewRequired,
	})
	handoff = sandboxSyncOutApplyResultWithHandoffInstructions(sandboxSyncOutApplyRequest{
		Summary: summary,
		Handoff: handoff,
	}, handoff)
	if err := persistSandboxSyncOutApplyMetadata(store, executionID, summary, handoff); err != nil {
		return fmt.Errorf("persist failed sandbox sync-out handoff: %w", err)
	}
	return nil
}

func outputSandboxSyncOutAugmentedJSON(out io.Writer, remoteJSON []byte, store sandboxexecution.Store, executionID string) error {
	return outputSandboxAugmentedJSON(out, remoteJSON, store, executionID)
}

func outputSandboxAugmentedJSON(out io.Writer, remoteJSON []byte, store sandboxexecution.Store, executionID string) error {
	if out == nil {
		out = io.Discard
	}
	manifest, err := store.LoadManifest(executionID)
	if err != nil || !sandboxManifestHasCommandJSONAugmentation(manifest) {
		return writeSandboxCapturedJSON(out, remoteJSON)
	}
	augmented, ok := sandboxAugmentJSON(remoteJSON, manifest)
	if !ok {
		return writeSandboxCapturedJSON(out, remoteJSON)
	}
	_, err = fmt.Fprintln(out, string(augmented))
	return err
}

func writeSandboxCapturedJSON(out io.Writer, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	_, err := out.Write(data)
	return err
}

func sandboxSyncOutAugmentJSON(remoteJSON []byte, manifest *sandboxexecution.Manifest) ([]byte, bool) {
	return sandboxAugmentJSON(remoteJSON, manifest)
}

func sandboxAugmentJSON(remoteJSON []byte, manifest *sandboxexecution.Manifest) ([]byte, bool) {
	if len(bytes.TrimSpace(remoteJSON)) == 0 || manifest == nil {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(remoteJSON))
	decoder.UseNumber()
	var raw map[string]any
	if err := decoder.Decode(&raw); err != nil {
		return nil, false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, false
	}
	if manifest.SyncOut != nil {
		raw["syncOut"] = manifest.SyncOut
	}
	if manifest.SyncOutApply != nil {
		raw["syncOutApply"] = manifest.SyncOutApply
	}
	if manifest.SyncOut != nil && strings.TrimSpace(manifest.ID) != "" {
		raw["sandboxExecutionId"] = strings.TrimSpace(manifest.ID)
	}
	if credentialDelivery := sandboxCommandJSONCredentialDeliveryStatus(manifest.CredentialDelivery); credentialDelivery != nil {
		raw["credentialDelivery"] = credentialDelivery
	}
	if readinessGate := sandboxCommandJSONSecurityReadinessGate(manifest.Security); readinessGate != nil {
		raw["securityReadinessGate"] = readinessGate
	}
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return nil, false
	}
	return data, true
}

func sandboxManifestHasCommandJSONAugmentation(manifest *sandboxexecution.Manifest) bool {
	if manifest == nil {
		return false
	}
	return manifest.SyncOut != nil ||
		manifest.SyncOutApply != nil ||
		sandboxCommandJSONCredentialDeliveryStatus(manifest.CredentialDelivery) != nil ||
		sandboxCommandJSONSecurityReadinessGate(manifest.Security) != nil
}

func sandboxCommandJSONSecurityReadinessGate(security *sandbox.SandboxSecurity) *sandbox.SandboxSecurityCapabilityReadinessGateDecision {
	if security == nil {
		return nil
	}
	return sandbox.CloneSandboxSecurityCapabilityReadinessGateDecisionPtr(security.SecurityReadinessGate)
}

func sandboxCommandJSONCredentialDeliveryStatus(status *sandbox.SandboxCredentialDeliveryStatusMetadata) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	if status == nil {
		return nil
	}
	sanitized := sandbox.SanitizeSandboxCredentialDeliverySurfaceStatusMetadata(*status)
	if sanitized.ID == "" || sanitized.PlanID == "" || sanitized.ActivationID == "" || sanitized.Status == "" {
		return nil
	}
	return &sanitized
}

func sandboxSyncOutPrimaryHandoffReason(reasons []sandboxworkspace.SyncOutApplyEligibilityReason) sandboxworkspace.SyncOutApplyEligibilityReason {
	for _, reason := range reasons {
		if reason != "" {
			return reason
		}
	}
	return ""
}

func sandboxSyncOutHandoffMessage(reason sandboxworkspace.SyncOutApplyEligibilityReason) string {
	switch reason {
	case sandboxworkspace.SyncOutApplyEligibilityReasonApplyOutcomeUnknown:
		return "Host apply may already have changed the worktree; inspect the host and stored sandbox sync-out artifacts before any retry."
	case sandboxworkspace.SyncOutApplyEligibilityReasonApplyDisabled:
		return "Automatic apply is disabled; inspect the listed sandbox sync-out artifacts before applying changes manually."
	case sandboxworkspace.SyncOutApplyEligibilityReasonDirtyWorktree:
		return "Host worktree has local changes; inspect the listed sandbox sync-out artifacts and clean or stash local work before applying manually."
	case sandboxworkspace.SyncOutApplyEligibilityReasonDryRunFailed:
		return "Automatic apply dry-run failed; inspect the listed sandbox sync-out artifacts and apply changes manually after resolving conflicts."
	case sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact:
		return "No eligible patch or bundle was available; inspect the listed sandbox sync-out artifacts manually."
	case sandboxworkspace.SyncOutApplyEligibilityReasonUnsafeArtifact:
		return "Automatic apply was skipped because the selected artifact is unsafe; inspect the listed sandbox sync-out artifacts manually."
	default:
		return "Automatic apply requires manual handoff; inspect the listed sandbox sync-out artifacts before mutating the host worktree."
	}
}

func sandboxSyncOutHandoffArtifactRefs(summary sandboxworkspace.SyncOutSummary, result sandboxworkspace.SafeApplyResult) []sandboxworkspace.SyncOutHandoffArtifactRef {
	refs := make([]sandboxworkspace.SyncOutHandoffArtifactRef, 0, 6)
	seen := map[string]bool{}
	add := func(ref sandboxworkspace.SyncOutHandoffArtifactRef) {
		if ref.ID == "" && ref.DisplayName == "" && ref.DisplayPath == "" {
			return
		}
		key := ref.ID
		if key == "" {
			key = ref.DisplayPath
		}
		if key == "" {
			key = ref.DisplayName
		}
		if seen[key] {
			return
		}
		seen[key] = true
		refs = append(refs, ref)
	}

	for _, artifact := range []*sandboxworkspace.SyncOutArtifact{
		summary.Committed.Patch,
		summary.Committed.Bundle,
		summary.Uncommitted.Diff,
		summary.Untracked.Archive,
		summary.Untracked.List,
	} {
		add(sandboxSyncOutHandoffArtifactRef(artifact))
	}
	for i := range summary.Recovery.Artifacts {
		add(sandboxSyncOutHandoffArtifactRef(&summary.Recovery.Artifacts[i]))
	}
	add(sandboxSyncOutHandoffResultArtifactRef(result))
	return refs
}

func sandboxSyncOutHandoffArtifactRef(artifact *sandboxworkspace.SyncOutArtifact) sandboxworkspace.SyncOutHandoffArtifactRef {
	if artifact == nil {
		return sandboxworkspace.SyncOutHandoffArtifactRef{}
	}
	return sandboxworkspace.SyncOutHandoffArtifactRef{
		ID:          sandboxSyncOutSafeHandoffID(artifact.ID),
		DisplayName: sandboxSyncOutSafeHandoffText(artifact.DisplayName),
		DisplayPath: sandboxSyncOutSafeHandoffDisplayPath(artifact.DisplayPath),
	}
}

func sandboxSyncOutHandoffResultArtifactRef(result sandboxworkspace.SafeApplyResult) sandboxworkspace.SyncOutHandoffArtifactRef {
	return sandboxworkspace.SyncOutHandoffArtifactRef{
		ID:          sandboxSyncOutSafeHandoffID(result.ArtifactID),
		DisplayName: sandboxSyncOutSafeHandoffText(result.DisplayName),
		DisplayPath: sandboxSyncOutSafeHandoffDisplayPath(result.DisplayPath),
	}
}

func sandboxSyncOutSafeHandoffID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || sandboxSyncOutUnsafeHandoffFragment(value) {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':':
		default:
			return ""
		}
	}
	return value
}

func sandboxSyncOutSafeHandoffText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || sandboxSyncOutUnsafeHandoffFragment(value) || filepath.IsAbs(value) || pathpkg.IsAbs(value) {
		return ""
	}
	return value
}

func sandboxSyncOutSafeHandoffDisplayPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || sandboxSyncOutUnsafeHandoffFragment(value) || filepath.IsAbs(value) || pathpkg.IsAbs(value) || strings.Contains(value, "\\") {
		return ""
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return ""
		}
	}
	clean := pathpkg.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	return clean
}

func sandboxSyncOutUnsafeHandoffFragment(value string) bool {
	if strings.ContainsAny(value, "\r\n") {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"token=",
		"secret",
		"credential",
		"api_key",
		"apikey",
		"access_token",
		"client_secret",
		"private_key",
		"ghp_",
		"/tmp/",
		"/workspace/",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
