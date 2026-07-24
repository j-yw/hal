package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

type foregroundSandboxL3JobClient struct {
	driver sandboxWorkerJobDriver
}

func (client foregroundSandboxL3JobClient) JobStatus(
	ctx context.Context,
	req sandboxworker.JobStatusRequest,
) (*sandboxworker.Job, error) {
	return client.driver.JobStatus(ctx, req.JobID)
}

func (client foregroundSandboxL3JobClient) JobLogs(
	ctx context.Context,
	req sandboxworker.JobLogsRequest,
) (*sandboxworker.JobLogsResponse, error) {
	return client.driver.JobLogs(ctx, req.JobID, req.Cursor, req.LimitBytes)
}

type foregroundSandboxL3FinalizationRequest struct {
	ExecutionID      string
	SyncOutRequested bool
	Store            sandboxexecution.Store
	RuntimeDriver    sandboxruntime.Driver
	Now              func() time.Time
	CollectArtifacts func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error
	CollectSyncOut   func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error
	ReleaseLease     func(string) (*sandbox.SandboxLease, error)
}

func finalizeForegroundSandboxL3Execution(ctx context.Context, req foregroundSandboxL3FinalizationRequest) error {
	jobDriver, ok := req.RuntimeDriver.(sandboxWorkerJobDriver)
	if !ok {
		return errors.New("worker_job_capability_missing: selected runtime cannot finalize its durable job")
	}
	client := foregroundSandboxL3JobClient{driver: jobDriver}
	return finalizeSandboxL3Execution(
		ctx,
		req.Store,
		req.ExecutionID,
		req.SyncOutRequested,
		sandboxL3FinalizationDeps{
			now: req.Now,
			observeJob: func(ctx context.Context, manifest *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
				if manifest == nil || manifest.WorkerJob == nil {
					return nil, errors.New("worker job identity is unavailable")
				}
				return client.JobStatus(ctx, sandboxworker.JobStatusRequest{
					ContractVersion: sandboxworker.JobContractVersion,
					JobID:           manifest.WorkerJob.JobID,
				})
			},
			drainLogs: func(ctx context.Context, manifest *sandboxexecution.Manifest, job *sandboxworker.Job) error {
				return streamSandboxL3Logs(ctx, client, manifest, job, true, io.Discard, io.Discard)
			},
			collectArtifacts: req.CollectArtifacts,
			collectSyncOut:   req.CollectSyncOut,
			releaseLease: func(_ context.Context, manifest *sandboxexecution.Manifest) error {
				return releaseForegroundSandboxL3Lease(manifest, req.ReleaseLease)
			},
		},
	)
}

func releaseForegroundSandboxL3Lease(
	manifest *sandboxexecution.Manifest,
	release func(string) (*sandbox.SandboxLease, error),
) error {
	if manifest == nil || manifest.Lease == nil {
		return nil
	}
	leaseID := strings.TrimSpace(manifest.Lease.ID)
	if leaseID == "" {
		return errors.New("lease_identity_missing: durable lease identity is required")
	}
	if runID := strings.TrimSpace(manifest.Lease.RunID); runID != "" && runID != strings.TrimSpace(manifest.ID) {
		return errors.New("lease_identity_mismatch: durable lease did not match execution")
	}
	if purpose := strings.TrimSpace(manifest.Lease.Purpose); purpose != "" && purpose != string(manifest.Purpose) {
		return errors.New("lease_identity_mismatch: durable lease did not match execution")
	}
	if release == nil {
		return errors.New("lease_release_unavailable: durable lease release is unavailable")
	}
	released, err := release(leaseID)
	if err != nil {
		return errors.New("lease_release_failed: exact durable lease was not released")
	}
	if released != nil && strings.TrimSpace(released.ID) != "" && strings.TrimSpace(released.ID) != leaseID {
		return fmt.Errorf("lease_identity_mismatch: released lease identity did not match execution")
	}
	return nil
}

func finalizeRunSandboxWorkerJob(
	ctx context.Context,
	store sandboxexecution.Store,
	req runSandboxRequest,
	result runSandboxExecutionResult,
	target *sandbox.SandboxState,
	deps runSandboxDeps,
) error {
	runtimeTarget, ok := runSandboxRuntimeTargetForCollection(result, target)
	if !ok || result.RuntimeDriver == nil {
		return errors.New("runtime_handle_unavailable: foreground worker runtime is unavailable")
	}
	resultForCollection := result
	if resultForCollection.Result == nil {
		resultForCollection.Result = &sandboxexec.Result{Target: runtimeTarget}
	}
	return finalizeForegroundSandboxL3Execution(ctx, foregroundSandboxL3FinalizationRequest{
		ExecutionID:      req.ExecutionID,
		SyncOutRequested: req.SyncOut.Enabled,
		Store:            store,
		RuntimeDriver:    result.RuntimeDriver,
		Now:              deps.now,
		CollectArtifacts: func(ctx context.Context, locked sandboxexecution.Store, _ *sandboxexecution.Manifest, _ *sandboxworker.Job) error {
			artifactReq := req
			artifactReq.SyncOut = sandboxSyncOutOptions{}
			if err := collectRunSandboxCoreStateArtifacts(ctx, locked, artifactReq, resultForCollection); err != nil {
				return err
			}
			if err := collectRunSandboxGeneratedArtifacts(ctx, locked, artifactReq, resultForCollection); err != nil {
				return err
			}
			return collectRunSandboxOutputSummaryArtifacts(locked, artifactReq, resultForCollection, target)
		},
		CollectSyncOut: func(ctx context.Context, locked sandboxexecution.Store, manifest *sandboxexecution.Manifest, _ *sandboxworker.Job) error {
			return collectSandboxL3SyncOutWithRuntime(ctx, locked, manifest, result.RuntimeDriver, runtimeTarget)
		},
		ReleaseLease: deps.releaseLease,
	})
}

func finalizeAutoSandboxWorkerJob(
	ctx context.Context,
	store sandboxexecution.Store,
	req autoSandboxRequest,
	result autoSandboxExecutionResult,
	target *sandbox.SandboxState,
	capturedJSON []byte,
	deps autoSandboxDeps,
) error {
	runtimeTarget, ok := autoSandboxRuntimeTargetForCollection(result, target)
	if !ok || result.RuntimeDriver == nil {
		return errors.New("runtime_handle_unavailable: foreground worker runtime is unavailable")
	}
	resultForCollection := result
	if resultForCollection.Result == nil {
		resultForCollection.Result = &sandboxexec.Result{Target: runtimeTarget}
	}
	return finalizeForegroundSandboxL3Execution(ctx, foregroundSandboxL3FinalizationRequest{
		ExecutionID:      req.ExecutionID,
		SyncOutRequested: req.SyncOut.Enabled,
		Store:            store,
		RuntimeDriver:    result.RuntimeDriver,
		Now:              deps.now,
		CollectArtifacts: func(ctx context.Context, locked sandboxexecution.Store, _ *sandboxexecution.Manifest, job *sandboxworker.Job) error {
			archivePath := ""
			if job != nil && job.State == sandboxworker.JobStateSucceeded {
				var err error
				archivePath, err = autoSandboxRemoteArchivePath(capturedJSON, resultForCollection.StdoutSummary)
				if err != nil {
					return fmt.Errorf("read remote auto archive path: %w", err)
				}
			}
			artifactReq := req
			artifactReq.SyncOut = sandboxSyncOutOptions{}
			if err := collectAutoSandboxCoreStateArtifacts(ctx, locked, artifactReq, resultForCollection, archivePath); err != nil {
				return err
			}
			if err := collectAutoSandboxGeneratedArtifacts(ctx, locked, artifactReq, resultForCollection); err != nil {
				return err
			}
			return collectAutoSandboxOutputSummaryArtifacts(locked, artifactReq, resultForCollection, target)
		},
		CollectSyncOut: func(ctx context.Context, locked sandboxexecution.Store, manifest *sandboxexecution.Manifest, _ *sandboxworker.Job) error {
			return collectSandboxL3SyncOutWithRuntime(ctx, locked, manifest, result.RuntimeDriver, runtimeTarget)
		},
		ReleaseLease: deps.releaseLease,
	})
}
