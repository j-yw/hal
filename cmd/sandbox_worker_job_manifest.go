package cmd

import (
	"fmt"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
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
	if existing.Finalization != nil &&
		(existing.Finalization.State != sandboxexecution.FinalizationStatePending ||
			sandboxL3AnyFinalizationCheckpoint(existing.Finalization.Checkpoints)) {
		manifest.WorkerJob = sandboxexecution.SanitizeWorkerJobReference(existing.WorkerJob)
		manifest.Finalization = cloneSandboxWorkerJobFinalization(existing.Finalization)
		manifest.Status = existing.Status
		manifest.FinishedAt = cloneSandboxWorkerJobTime(existing.FinishedAt)
		return
	}
	if manifest.WorkerJob == nil {
		manifest.WorkerJob = sandboxexecution.SanitizeWorkerJobReference(existing.WorkerJob)
	}
	if manifest.Finalization == nil {
		manifest.Finalization = cloneSandboxWorkerJobFinalization(existing.Finalization)
	}
}

func persistSandboxWorkerJobUpdate(
	store sandboxexecution.Store,
	executionID string,
	incoming *sandboxexecution.WorkerJobReference,
	syncOutRequested bool,
	now time.Time,
) error {
	incoming = sandboxexecution.SanitizeWorkerJobReference(incoming)
	if incoming == nil {
		return fmt.Errorf("sandbox worker job update is invalid")
	}
	return store.UpdateManifest(executionID, func(manifest *sandboxexecution.Manifest) error {
		merged, err := mergeSandboxWorkerJobReference(
			manifest.WorkerJob,
			incoming,
			manifest.Finalization,
		)
		if err != nil {
			return err
		}
		manifest.WorkerJob = merged
		manifest.Finalization = mergeSandboxWorkerJobPendingFinalization(
			manifest.Finalization,
			merged,
			syncOutRequested,
			now,
		)
		return nil
	})
}

func mergeSandboxWorkerJobReference(
	current *sandboxexecution.WorkerJobReference,
	incoming *sandboxexecution.WorkerJobReference,
	finalization *sandboxexecution.FinalizationMetadata,
) (*sandboxexecution.WorkerJobReference, error) {
	current = sandboxexecution.SanitizeWorkerJobReference(current)
	incoming = sandboxexecution.SanitizeWorkerJobReference(incoming)
	if incoming == nil {
		return nil, fmt.Errorf("sandbox worker job update is invalid")
	}
	if current == nil {
		return incoming, nil
	}
	if !sandboxWorkerJobReferenceIdentityMatches(current, incoming) {
		return nil, fmt.Errorf("sandbox worker job update identity mismatch")
	}
	if finalization != nil &&
		(finalization.State != sandboxexecution.FinalizationStatePending ||
			sandboxL3AnyFinalizationCheckpoint(finalization.Checkpoints)) {
		return current, nil
	}
	if sandboxL3ProvenTerminalJobState(current.State) {
		if incoming.State != current.State || incoming.LogCursor < current.LogCursor {
			return current, nil
		}
		return incoming, nil
	}
	if sandboxL3UnprovenTerminalJobState(current.State) {
		if sandboxL3ActiveJobState(incoming.State) {
			return current, nil
		}
		if incoming.LogCursor < current.LogCursor {
			return current, nil
		}
		return incoming, nil
	}
	if current.State == sandboxworker.JobStateRunning && incoming.State == sandboxworker.JobStateQueued {
		return nil, fmt.Errorf("sandbox worker job state regressed")
	}
	if incoming.LogCursor < current.LogCursor {
		return nil, fmt.Errorf("sandbox worker job log cursor regressed")
	}
	return incoming, nil
}

func sandboxWorkerJobReferenceIdentityMatches(
	left *sandboxexecution.WorkerJobReference,
	right *sandboxexecution.WorkerJobReference,
) bool {
	if left == nil || right == nil {
		return false
	}
	return left.ContractVersion == right.ContractVersion &&
		left.JobID == right.JobID &&
		left.SubmissionKey == right.SubmissionKey &&
		left.WorkerID == right.WorkerID &&
		left.HostID == right.HostID &&
		left.RuntimeDriver == right.RuntimeDriver &&
		left.RuntimeID == right.RuntimeID &&
		left.SubmittedAt.Equal(right.SubmittedAt)
}

func mergeSandboxWorkerJobPendingFinalization(
	current *sandboxexecution.FinalizationMetadata,
	job *sandboxexecution.WorkerJobReference,
	syncOutRequested bool,
	now time.Time,
) *sandboxexecution.FinalizationMetadata {
	merged := cloneSandboxWorkerJobFinalization(current)
	if merged != nil &&
		(merged.State != sandboxexecution.FinalizationStatePending ||
			sandboxL3AnyFinalizationCheckpoint(merged.Checkpoints)) {
		return merged
	}
	merged = updateSandboxWorkerJobFinalization(merged, job, syncOutRequested, now)
	if current != nil {
		merged.SyncOutRequested = current.SyncOutRequested || syncOutRequested
		if current.UpdatedAt.After(merged.UpdatedAt) {
			merged.UpdatedAt = current.UpdatedAt
		}
	}
	return merged
}

func sandboxL3ProvenTerminalJobState(state string) bool {
	switch strings.TrimSpace(state) {
	case sandboxworker.JobStateSucceeded,
		sandboxworker.JobStateFailed,
		sandboxworker.JobStateCanceled:
		return true
	default:
		return false
	}
}

func sandboxL3UnprovenTerminalJobState(state string) bool {
	switch strings.TrimSpace(state) {
	case sandboxworker.JobStateInterrupted, sandboxworker.JobStateUnknown:
		return true
	default:
		return false
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
