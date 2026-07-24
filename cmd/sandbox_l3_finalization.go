package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

type sandboxL3FinalizationDeps struct {
	now              func() time.Time
	resolveJob       func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error)
	observeJob       func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error)
	drainLogs        func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error
	collectArtifacts func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error
	collectSyncOut   func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error
	releaseLease     func(context.Context, *sandboxexecution.Manifest) error
}

func finalizeSandboxL3Execution(
	ctx context.Context,
	store sandboxexecution.Store,
	executionID string,
	requestSyncOut bool,
	deps sandboxL3FinalizationDeps,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	executionID = strings.TrimSpace(executionID)
	if executionID == "" {
		return errors.New("execution_id_required: durable execution identity is required")
	}
	deps = normalizeSandboxL3FinalizationDeps(deps)
	return store.WithLockedExecution(executionID, func(locked sandboxexecution.Store) error {
		manifest, err := locked.LoadManifest(executionID)
		if err != nil {
			return errors.New("execution_manifest_unavailable: durable execution manifest is unavailable")
		}
		if manifest.Finalization != nil && manifest.Finalization.State == sandboxexecution.FinalizationStateCompleted {
			if err := validateSandboxL3CompletedPublication(manifest); err != nil {
				return err
			}
			if requestSyncOut && !manifest.Finalization.SyncOutRequested {
				return errors.New("sync_out_after_finalization: execution completed without sync-out intent")
			}
			return nil
		}
		if manifest.WorkerJob == nil {
			if !sandboxL3ExecutionAwaitingJobResolution(manifest) {
				return errors.New("worker_job_missing: durable worker job identity is required")
			}
			job, resolveErr := deps.resolveJob(ctx, manifest)
			if resolveErr != nil {
				return resolveErr
			}
			reference := sandboxL3WorkerJobReference(job)
			if reference == nil {
				return errors.New("worker_job_resolution_mismatch: resolved worker job identity is invalid")
			}
			now := deps.now().UTC()
			manifest.WorkerJob = reference
			finalization := ensureSandboxL3Finalization(manifest, requestSyncOut, now)
			finalization.State = sandboxexecution.FinalizationStatePending
			finalization.ReasonCode = ""
			if sandboxL3TerminalJobState(reference.State) {
				finalization.TerminalJobState = reference.State
			}
			finalization.UpdatedAt = now
			if err := locked.SaveManifest(manifest); err != nil {
				return errors.New("worker_job_resolution_write_failed: resolved worker job state is unavailable")
			}
		}

		job, observeErr := deps.observeJob(ctx, manifest)
		if observeErr != nil {
			return blockSandboxL3Finalization(locked, manifest, nil, requestSyncOut, "terminal_observation_failed", deps.now().UTC())
		}
		if err := validateSandboxL3LiveJob(manifest, job); err != nil {
			// Identity mismatches do not mutate the durable record. The operator
			// must inspect the selected worker/manifest binding explicitly.
			return err
		}
		if !sandboxL3TerminalJobState(job.State) {
			return fmt.Errorf("job_not_terminal: execution %s is still active", executionID)
		}
		if job.State == sandboxworker.JobStateUnknown || job.State == sandboxworker.JobStateInterrupted {
			if manifest.Finalization != nil && sandboxL3AnyFinalizationCheckpoint(manifest.Finalization.Checkpoints) {
				return errors.New("terminal_state_regression: live job state contradicted durable terminal proof")
			}
			return blockSandboxL3Finalization(locked, manifest, job, requestSyncOut, "terminal_proof_unavailable", deps.now().UTC())
		}

		now := deps.now().UTC()
		manifest.WorkerJob = sandboxL3WorkerJobReference(job)
		finalization := ensureSandboxL3Finalization(manifest, requestSyncOut, now)
		finalization.State = sandboxexecution.FinalizationStateFinalizing
		finalization.TerminalJobState = job.State
		finalization.ReasonCode = ""
		finalization.UpdatedAt = now
		if err := locked.SaveManifest(manifest); err != nil {
			return errors.New("finalization_state_write_failed: durable finalization state is unavailable")
		}

		// A completed artifact checkpoint proves terminal logs were drained
		// before artifact collection on an earlier attempt.
		if !finalization.Checkpoints.Artifacts.Completed {
			if err := deps.drainLogs(ctx, manifest, job); err != nil {
				return blockSandboxL3Finalization(locked, manifest, job, requestSyncOut, "terminal_log_drain_failed", deps.now().UTC())
			}
			if err := deps.collectArtifacts(ctx, locked, manifest, job); err != nil {
				return blockSandboxL3Finalization(locked, manifest, job, requestSyncOut, "artifact_collection_failed", deps.now().UTC())
			}
			manifest, err = reloadSandboxL3FinalizationManifest(locked, executionID)
			if err != nil {
				return err
			}
			checkpointSandboxL3Finalization(
				manifest,
				&manifest.Finalization.Checkpoints.Artifacts,
				deps.now().UTC(),
			)
			if err := locked.SaveManifest(manifest); err != nil {
				return errors.New("finalization_state_write_failed: durable artifact checkpoint is unavailable")
			}
		}

		finalization = manifest.Finalization
		if finalization.SyncOutRequested && !finalization.Checkpoints.SyncOut.Completed {
			if err := deps.collectSyncOut(ctx, locked, manifest, job); err != nil {
				return blockSandboxL3Finalization(locked, manifest, job, true, "sync_out_collection_failed", deps.now().UTC())
			}
			manifest, err = reloadSandboxL3FinalizationManifest(locked, executionID)
			if err != nil {
				return err
			}
			checkpointSandboxL3Finalization(
				manifest,
				&manifest.Finalization.Checkpoints.SyncOut,
				deps.now().UTC(),
			)
			if err := locked.SaveManifest(manifest); err != nil {
				return errors.New("finalization_state_write_failed: durable sync-out checkpoint is unavailable")
			}
		}

		finalization = manifest.Finalization
		if !finalization.Checkpoints.LeaseRelease.Completed {
			if err := deps.releaseLease(ctx, manifest); err != nil {
				return blockSandboxL3Finalization(locked, manifest, job, finalization.SyncOutRequested, "lease_release_failed", deps.now().UTC())
			}
			checkpointSandboxL3Finalization(
				manifest,
				&manifest.Finalization.Checkpoints.LeaseRelease,
				deps.now().UTC(),
			)
			if err := locked.SaveManifest(manifest); err != nil {
				return errors.New("finalization_state_write_failed: durable lease checkpoint is unavailable")
			}
		}

		return publishSandboxL3TerminalManifest(locked, manifest, job, deps.now().UTC())
	})
}

func normalizeSandboxL3FinalizationDeps(deps sandboxL3FinalizationDeps) sandboxL3FinalizationDeps {
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.resolveJob == nil {
		deps.resolveJob = func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
			return nil, errors.New("worker job resolution is unavailable")
		}
	}
	if deps.observeJob == nil {
		deps.observeJob = func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
			return nil, errors.New("worker observation is unavailable")
		}
	}
	if deps.drainLogs == nil {
		deps.drainLogs = func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			return errors.New("terminal log drain is unavailable")
		}
	}
	if deps.collectArtifacts == nil {
		deps.collectArtifacts = func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			return errors.New("terminal artifact collection is unavailable")
		}
	}
	if deps.collectSyncOut == nil {
		deps.collectSyncOut = func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			return errors.New("terminal sync-out collection is unavailable")
		}
	}
	if deps.releaseLease == nil {
		deps.releaseLease = func(context.Context, *sandboxexecution.Manifest) error {
			return errors.New("durable lease release is unavailable")
		}
	}
	return deps
}

func ensureSandboxL3Finalization(manifest *sandboxexecution.Manifest, requestSyncOut bool, now time.Time) *sandboxexecution.FinalizationMetadata {
	if manifest.Finalization == nil {
		startedAt := now
		manifest.Finalization = &sandboxexecution.FinalizationMetadata{
			ContractVersion: sandboxexecution.FinalizationContractVersion,
			State:           sandboxexecution.FinalizationStatePending,
			StartedAt:       &startedAt,
			UpdatedAt:       now,
		}
	}
	manifest.Finalization.ContractVersion = sandboxexecution.FinalizationContractVersion
	manifest.Finalization.SyncOutRequested = manifest.Finalization.SyncOutRequested || requestSyncOut
	if manifest.Finalization.StartedAt == nil {
		startedAt := now
		manifest.Finalization.StartedAt = &startedAt
	}
	return manifest.Finalization
}

func checkpointSandboxL3Finalization(
	manifest *sandboxexecution.Manifest,
	checkpoint *sandboxexecution.FinalizationCheckpoint,
	now time.Time,
) {
	if manifest == nil || manifest.Finalization == nil || checkpoint == nil || checkpoint.Completed {
		return
	}
	checkpoint.Completed = true
	completedAt := now
	checkpoint.CompletedAt = &completedAt
	manifest.Finalization.State = sandboxexecution.FinalizationStateFinalizing
	manifest.Finalization.ReasonCode = ""
	manifest.Finalization.UpdatedAt = now
}

func blockSandboxL3Finalization(
	store sandboxexecution.Store,
	manifest *sandboxexecution.Manifest,
	job *sandboxworker.Job,
	requestSyncOut bool,
	reasonCode string,
	now time.Time,
) error {
	if manifest == nil {
		return fmt.Errorf("%s: finalization is blocked", reasonCode)
	}
	current, err := store.LoadManifest(manifest.ID)
	if err != nil {
		return errors.New("finalization_state_reload_failed: finalization is blocked and durable state is unavailable")
	}
	manifest = current
	if job != nil {
		manifest.WorkerJob = sandboxL3WorkerJobReference(job)
	}
	finalization := ensureSandboxL3Finalization(manifest, requestSyncOut, now)
	finalization.State = sandboxexecution.FinalizationStateBlocked
	finalization.ReasonCode = reasonCode
	if job != nil {
		finalization.TerminalJobState = job.State
	}
	finalization.UpdatedAt = now
	if err := store.SaveManifest(manifest); err != nil {
		return fmt.Errorf("%s: finalization is blocked and durable state is unavailable", reasonCode)
	}
	return fmt.Errorf("%s: finalization is blocked", reasonCode)
}

func validateSandboxL3CompletedPublication(manifest *sandboxexecution.Manifest) error {
	if manifest == nil || manifest.Finalization == nil || manifest.WorkerJob == nil {
		return errors.New("terminal_publication_inconsistent: completed finalization identity is unavailable")
	}
	terminalState := strings.TrimSpace(manifest.Finalization.TerminalJobState)
	if !sandboxL3FinalizationProvenTerminalJobState(terminalState) ||
		strings.TrimSpace(manifest.WorkerJob.State) != terminalState ||
		manifest.Status != sandboxL3ExecutionStatusFromJob(terminalState) ||
		manifest.FinishedAt == nil ||
		manifest.WorkerJob.FinishedAt == nil ||
		!manifest.FinishedAt.Equal(*manifest.WorkerJob.FinishedAt) {
		return errors.New("terminal_publication_inconsistent: completed finalization state did not match durable execution")
	}
	return nil
}

func sandboxL3FinalizationProvenTerminalJobState(state string) bool {
	switch state {
	case sandboxworker.JobStateSucceeded,
		sandboxworker.JobStateFailed,
		sandboxworker.JobStateCanceled:
		return true
	default:
		return false
	}
}

func sandboxL3AnyFinalizationCheckpoint(checkpoints sandboxexecution.FinalizationCheckpoints) bool {
	return checkpoints.Artifacts.Completed ||
		checkpoints.SyncOut.Completed ||
		checkpoints.LeaseRelease.Completed ||
		checkpoints.TerminalPublication.Completed
}

func reloadSandboxL3FinalizationManifest(store sandboxexecution.Store, executionID string) (*sandboxexecution.Manifest, error) {
	manifest, err := store.LoadManifest(executionID)
	if err != nil || manifest.Finalization == nil {
		return nil, errors.New("finalization_state_unavailable: durable finalization state is unavailable")
	}
	return manifest, nil
}

func publishSandboxL3TerminalManifest(
	store sandboxexecution.Store,
	manifest *sandboxexecution.Manifest,
	job *sandboxworker.Job,
	now time.Time,
) error {
	if manifest == nil || manifest.Finalization == nil || job == nil {
		return errors.New("terminal_publication_failed: terminal state is unavailable")
	}
	finalization := manifest.Finalization
	checkpointSandboxL3Finalization(manifest, &finalization.Checkpoints.TerminalPublication, now)
	finalization.State = sandboxexecution.FinalizationStateCompleted
	finalization.ReasonCode = ""
	finalization.TerminalJobState = job.State
	completedAt := now
	finalization.CompletedAt = &completedAt
	finalization.UpdatedAt = now
	manifest.WorkerJob = sandboxL3WorkerJobReference(job)
	manifest.Status = sandboxL3ExecutionStatusFromJob(job.State)
	if job.FinishedAt != nil {
		manifest.FinishedAt = cloneL3Time(job.FinishedAt)
	} else {
		finishedAt := now
		manifest.FinishedAt = &finishedAt
	}
	if err := store.SaveManifest(manifest); err != nil {
		return errors.New("terminal_publication_failed: durable terminal publication is unavailable")
	}
	return nil
}

func sandboxL3ExecutionStatusFromJob(state string) sandboxexecution.Status {
	switch state {
	case sandboxworker.JobStateSucceeded:
		return sandboxexecution.StatusSucceeded
	case sandboxworker.JobStateCanceled:
		return sandboxexecution.StatusCanceled
	case sandboxworker.JobStateInterrupted:
		return sandboxexecution.StatusInterrupted
	case sandboxworker.JobStateUnknown:
		return sandboxexecution.StatusUnknown
	default:
		return sandboxexecution.StatusFailed
	}
}

func sandboxL3WorkerJobReference(job *sandboxworker.Job) *sandboxexecution.WorkerJobReference {
	if job == nil {
		return nil
	}
	reference := &sandboxexecution.WorkerJobReference{
		ContractVersion: sandboxexecution.WorkerJobContractVersion,
		JobID:           strings.TrimSpace(job.ID),
		SubmissionKey:   strings.TrimSpace(job.SubmissionKey),
		WorkerID:        strings.TrimSpace(job.WorkerID),
		HostID:          strings.TrimSpace(job.HostID),
		RuntimeDriver:   strings.TrimSpace(job.RuntimeDriver),
		RuntimeID:       strings.TrimSpace(job.RuntimeID),
		State:           strings.TrimSpace(job.State),
		SubmittedAt:     job.SubmittedAt,
		StartedAt:       cloneL3Time(job.StartedAt),
		HeartbeatAt:     cloneL3Time(job.HeartbeatAt),
		FinishedAt:      cloneL3Time(job.FinishedAt),
		LogCursor:       job.LogCursor,
	}
	return sandboxexecution.SanitizeWorkerJobReference(reference)
}
