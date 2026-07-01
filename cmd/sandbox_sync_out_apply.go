package cmd

import (
	"context"
	"fmt"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

type sandboxSyncOutApplier func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error)

type sandboxSyncOutApplyRequest struct {
	ExecutionID string
	Purpose     sandboxexecution.Purpose
	ProjectDir  string
	Options     sandboxSyncOutOptions
	Store       sandboxexecution.Store
	Manifest    *sandboxexecution.Manifest
	Summary     sandboxworkspace.SyncOutSummary
	Artifact    *sandboxworkspace.SyncOutArtifact
	PayloadPath string
	Handoff     sandboxworkspace.SafeApplyResult
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
	manifest, err := store.LoadManifest(req.ExecutionID)
	if err != nil {
		return sandboxworkspace.SafeApplyResult{}, fmt.Errorf("load sandbox execution manifest before sync-out apply: %w", err)
	}
	req.Store = store
	req.Manifest = manifest
	req.Summary = sandboxexecution.BuildSyncOutSummaryFromArtifacts(manifest)
	if err := populateSandboxSyncOutApplySelection(&req); err != nil {
		return sandboxworkspace.SafeApplyResult{}, err
	}
	result, err := apply(ctx, req)
	return sandboxSyncOutApplyResultWithHandoffInstructions(req, result), err
}

func defaultSandboxSyncOutApplier(ctx context.Context, req sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
	if req.Artifact == nil || strings.TrimSpace(req.PayloadPath) == "" {
		return req.Handoff, nil
	}
	return sandboxworkspace.SafeApply(ctx, sandboxworkspace.SafeApplyRequest{
		ProjectDir:  req.ProjectDir,
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
	payloadPath, err := req.Store.ResolveStoredPath(req.ExecutionID, artifact.StoredPath)
	if err != nil {
		return fmt.Errorf("resolve eligible sync-out artifact payload: %w", err)
	}
	artifactCopy := *artifact
	req.Artifact = &artifactCopy
	req.PayloadPath = payloadPath
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
