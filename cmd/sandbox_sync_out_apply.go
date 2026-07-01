package cmd

import (
	"context"
	"fmt"
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
	return apply(ctx, req)
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
