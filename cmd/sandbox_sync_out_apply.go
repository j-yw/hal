package cmd

import (
	"context"
	"fmt"

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
}

func applyRunSandboxSyncOut(ctx context.Context, store sandboxexecution.Store, req runSandboxRequest, deps runSandboxDeps) error {
	if deps.applySyncOut == nil || !req.SyncOut.Enabled {
		return nil
	}
	if _, err := applySandboxSyncOut(ctx, store, sandboxSyncOutApplyRequest{
		ExecutionID: req.ExecutionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  req.ProjectDir,
		Options:     req.SyncOut,
	}, deps.applySyncOut); err != nil {
		return fmt.Errorf("apply run sandbox sync-out: %w", err)
	}
	return nil
}

func applyAutoSandboxSyncOut(ctx context.Context, store sandboxexecution.Store, req autoSandboxRequest, deps autoSandboxDeps) error {
	if deps.applySyncOut == nil || !req.SyncOut.Enabled {
		return nil
	}
	if _, err := applySandboxSyncOut(ctx, store, sandboxSyncOutApplyRequest{
		ExecutionID: req.ExecutionID,
		Purpose:     sandboxexecution.PurposeAuto,
		ProjectDir:  req.ProjectDir,
		Options:     req.SyncOut,
	}, deps.applySyncOut); err != nil {
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
	return apply(ctx, req)
}
