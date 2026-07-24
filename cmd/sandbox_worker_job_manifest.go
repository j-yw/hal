package cmd

import (
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func runSandboxWorkerJobRouteSelected(req runSandboxRequest, target sandboxruntime.Target, selected *sandbox.SandboxState) bool {
	return runSandboxWorkerRuntimeRouteSelected(req, target, selected) &&
		selectedWorkerRootlessSandboxState(selected) &&
		strings.TrimSpace(target.Runtime.Driver) == sandboxruntime.DriverRootlessPodman
}

func autoSandboxWorkerJobRouteSelected(req autoSandboxRequest, target sandboxruntime.Target, selected *sandbox.SandboxState) bool {
	return autoSandboxWorkerRuntimeRouteSelected(req, target, selected) &&
		selectedWorkerRootlessSandboxState(selected) &&
		strings.TrimSpace(target.Runtime.Driver) == sandboxruntime.DriverRootlessPodman
}

func sandboxWorkerJobSelectedHostID(selected *sandbox.SandboxState) string {
	if selected == nil || selected.Host == nil {
		return ""
	}
	return strings.TrimSpace(selected.Host.ID)
}

func updateSandboxWorkerJobFinalization(
	current *sandboxexecution.FinalizationMetadata,
	job *sandboxexecution.WorkerJobReference,
	syncOutRequested bool,
	now time.Time,
) *sandboxexecution.FinalizationMetadata {
	updated := cloneSandboxWorkerJobFinalization(current)
	if updated == nil {
		updated = &sandboxexecution.FinalizationMetadata{
			ContractVersion: sandboxexecution.FinalizationContractVersion,
			State:           sandboxexecution.FinalizationStatePending,
		}
	}
	updated.SyncOutRequested = syncOutRequested
	updated.UpdatedAt = now.UTC()
	if job != nil && sandboxWorkerJobTerminal(job.State) {
		updated.TerminalJobState = strings.TrimSpace(job.State)
	}
	return updated
}

func preserveSandboxManifestWorkerJobState(store sandboxexecution.Store, manifest *sandboxexecution.Manifest) {
	if manifest == nil || strings.TrimSpace(manifest.ID) == "" {
		return
	}
	existing, err := store.LoadManifest(manifest.ID)
	if err != nil {
		return
	}
	if manifest.WorkerJob == nil {
		manifest.WorkerJob = sandboxexecution.SanitizeWorkerJobReference(existing.WorkerJob)
	}
	if manifest.Finalization == nil {
		manifest.Finalization = cloneSandboxWorkerJobFinalization(existing.Finalization)
	}
}

func cloneSandboxWorkerJobFinalization(metadata *sandboxexecution.FinalizationMetadata) *sandboxexecution.FinalizationMetadata {
	if metadata == nil {
		return nil
	}
	cloned := *metadata
	cloned.StartedAt = cloneSandboxWorkerJobTime(metadata.StartedAt)
	cloned.UpdatedAt = metadata.UpdatedAt
	cloned.CompletedAt = cloneSandboxWorkerJobTime(metadata.CompletedAt)
	cloned.Checkpoints.Artifacts.CompletedAt = cloneSandboxWorkerJobTime(metadata.Checkpoints.Artifacts.CompletedAt)
	cloned.Checkpoints.SyncOut.CompletedAt = cloneSandboxWorkerJobTime(metadata.Checkpoints.SyncOut.CompletedAt)
	cloned.Checkpoints.LeaseRelease.CompletedAt = cloneSandboxWorkerJobTime(metadata.Checkpoints.LeaseRelease.CompletedAt)
	cloned.Checkpoints.TerminalPublication.CompletedAt = cloneSandboxWorkerJobTime(metadata.Checkpoints.TerminalPublication.CompletedAt)
	return &cloned
}

func cloneSandboxWorkerJobTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
