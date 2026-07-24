package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

const sandboxL3RecoveryOutputSummaryBytes = int(sandboxworker.DefaultJobLogReadBytes)

func defaultSandboxL3FinalizationDeps() sandboxL3FinalizationDeps {
	return sandboxL3FinalizationDeps{
		observeJob: observeSandboxL3DurableJob,
		drainLogsInStore: func(
			ctx context.Context,
			store sandboxexecution.Store,
			manifest *sandboxexecution.Manifest,
			job *sandboxworker.Job,
		) error {
			return drainSandboxL3TerminalLogs(ctx, store, manifest, job)
		},
		collectArtifacts: collectSandboxL3TerminalArtifacts,
		collectSyncOut:   collectSandboxL3SyncOut,
		releaseLease:     releaseSandboxL3DurableLease,
	}
}

func observeSandboxL3DurableJob(ctx context.Context, manifest *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
	client, err := sandboxL3ClientForManifest(manifest)
	if err != nil {
		return nil, err
	}
	job, err := client.JobStatus(ctx, sandboxworker.JobStatusRequest{
		ContractVersion: sandboxworker.JobContractVersion,
		JobID:           manifest.WorkerJob.JobID,
	})
	if err != nil {
		return nil, errors.Join(errors.New("worker_job_status_failed"), errors.New("selected worker job is unavailable"))
	}
	return job, nil
}

func drainSandboxL3TerminalLogs(
	ctx context.Context,
	store sandboxexecution.Store,
	manifest *sandboxexecution.Manifest,
	job *sandboxworker.Job,
) error {
	client, err := sandboxL3ClientForManifest(manifest)
	if err != nil {
		return err
	}
	stdout := &sandboxL3BoundedSummaryWriter{limit: sandboxL3RecoveryOutputSummaryBytes}
	stderr := &sandboxL3BoundedSummaryWriter{limit: sandboxL3RecoveryOutputSummaryBytes}
	if err := streamSandboxL3Logs(ctx, client, manifest, job, true, stdout, stderr); err != nil {
		return err
	}
	_, err = sandboxexecution.SaveCommandOutputSummaryArtifacts(sandboxexecution.CommandOutputSummaryArtifactsRequest{
		ExecutionID:   manifest.ID,
		Store:         store,
		StdoutSummary: boundedSandboxL3OutputSummary(sanitizeSandboxOutputSummary(stdout.String(), nil)),
		StderrSummary: boundedSandboxL3OutputSummary(sanitizeSandboxOutputSummary(stderr.String(), nil)),
	})
	if err != nil {
		return fmt.Errorf("persist terminal output summaries: %w", err)
	}
	return nil
}

func collectSandboxL3TerminalArtifacts(
	ctx context.Context,
	store sandboxexecution.Store,
	manifest *sandboxexecution.Manifest,
	_ *sandboxworker.Job,
) error {
	runtimeDriver, target, err := sandboxL3RuntimeHandleFromManifest(manifest)
	if err != nil {
		return err
	}
	core, err := sandboxexecution.CollectCoreStateArtifacts(ctx, sandboxexecution.CoreStateCollectionRequest{
		ExecutionID:        manifest.ID,
		Store:              store,
		Runtime:            runtimeDriver,
		Target:             target,
		Purpose:            manifest.Purpose,
		RemoteWorkspaceDir: manifest.WorkDir,
	})
	if err != nil {
		return fmt.Errorf("collect terminal core state: %w", err)
	}
	if err := requireSandboxL3CompleteCollection("terminal core state", core); err != nil {
		return err
	}
	recovery, err := sandboxexecution.CollectRecoveryArtifactsBestEffort(ctx, sandboxexecution.RecoveryArtifactCollectionRequest{
		ExecutionID:        manifest.ID,
		Store:              store,
		Runtime:            runtimeDriver,
		Target:             target,
		RemoteWorkspaceDir: manifest.WorkDir,
	})
	if err != nil {
		return fmt.Errorf("collect terminal recovery artifact: %w", err)
	}
	if err := requireSandboxL3CompleteCollection("terminal recovery artifact", recovery); err != nil {
		return err
	}
	reports, err := sandboxexecution.CollectReportsArchiveArtifacts(ctx, sandboxexecution.ReportsArchiveCollectionRequest{
		ExecutionID:        manifest.ID,
		Store:              store,
		Runtime:            runtimeDriver,
		Target:             target,
		RemoteWorkspaceDir: manifest.WorkDir,
	})
	if err != nil {
		return fmt.Errorf("collect terminal reports archive: %w", err)
	}
	return requireSandboxL3CompleteCollection("terminal reports archive", reports)
}

func collectSandboxL3SyncOut(
	ctx context.Context,
	store sandboxexecution.Store,
	manifest *sandboxexecution.Manifest,
	_ *sandboxworker.Job,
) error {
	runtimeDriver, target, err := sandboxL3RuntimeHandleFromManifest(manifest)
	if err != nil {
		return err
	}
	uncommitted, err := sandboxexecution.CollectUncommittedSyncOutArtifactBestEffort(ctx, sandboxexecution.UncommittedSyncOutCollectionRequest{
		ExecutionID:        manifest.ID,
		Store:              store,
		Runtime:            runtimeDriver,
		Target:             target,
		RemoteWorkspaceDir: manifest.WorkDir,
	})
	if err != nil {
		return fmt.Errorf("collect uncommitted sync-out artifact: %w", err)
	}
	if err := requireSandboxL3CompleteCollection("uncommitted sync-out artifact", uncommitted); err != nil {
		return err
	}
	untracked, err := sandboxexecution.CollectUntrackedSyncOutArtifactsBestEffort(ctx, sandboxexecution.UntrackedSyncOutCollectionRequest{
		ExecutionID:        manifest.ID,
		Store:              store,
		Runtime:            runtimeDriver,
		Target:             target,
		RemoteWorkspaceDir: manifest.WorkDir,
	})
	if err != nil {
		return fmt.Errorf("collect untracked sync-out artifacts: %w", err)
	}
	if err := requireSandboxL3CompleteCollection("untracked sync-out artifacts", untracked); err != nil {
		return err
	}
	if syncRef := sandboxL3ManifestSyncRef(manifest); syncRef != "" {
		committed, err := sandboxexecution.CollectCommittedSyncOutArtifactBestEffort(ctx, sandboxexecution.CommittedSyncOutCollectionRequest{
			ExecutionID:        manifest.ID,
			Store:              store,
			Runtime:            runtimeDriver,
			Target:             target,
			RemoteWorkspaceDir: manifest.WorkDir,
			SyncRef:            syncRef,
		})
		if err != nil {
			return fmt.Errorf("collect committed sync-out artifact: %w", err)
		}
		if err := requireSandboxL3CompleteCollection("committed sync-out artifact", committed); err != nil {
			return err
		}
	}
	return store.UpdateManifest(manifest.ID, func(current *sandboxexecution.Manifest) error {
		summary := sandboxexecution.BuildSyncOutSummaryFromArtifacts(current)
		current.SyncOut = &summary
		// L3 recovery and sync-out only produce a durable handoff. Host apply
		// remains the separate explicit `hal sandbox apply` command.
		current.SyncOutApply = nil
		return nil
	})
}

func requireSandboxL3CompleteCollection(stage string, result sandboxexecution.RuntimeCollectionResult) error {
	if len(result.ArtifactMetadata.Partial) == 0 && len(result.ArtifactMetadata.Warnings) == 0 {
		return nil
	}
	return fmt.Errorf("%s remained partial", stage)
}

func boundedSandboxL3OutputSummary(value string) string {
	writer := &sandboxL3BoundedSummaryWriter{limit: sandboxL3RecoveryOutputSummaryBytes}
	_, _ = writer.Write([]byte(value))
	return writer.String()
}

type sandboxL3BoundedSummaryWriter struct {
	builder strings.Builder
	limit   int
}

func (writer *sandboxL3BoundedSummaryWriter) Write(payload []byte) (int, error) {
	if writer == nil {
		return len(payload), nil
	}
	original := len(payload)
	remaining := writer.limit - writer.builder.Len()
	if remaining <= 0 {
		return original, nil
	}
	if len(payload) > remaining {
		payload = payload[:remaining]
	}
	_, _ = writer.builder.Write(payload)
	return original, nil
}

func (writer *sandboxL3BoundedSummaryWriter) String() string {
	if writer == nil {
		return ""
	}
	return strings.ToValidUTF8(writer.builder.String(), "")
}

func sandboxL3RuntimeHandleFromManifest(manifest *sandboxexecution.Manifest) (sandboxruntime.Driver, sandboxruntime.Target, error) {
	target, err := sandboxL3RuntimeTargetFromManifest(manifest)
	if err != nil {
		return nil, sandboxruntime.Target{}, err
	}
	host, err := sandboxL3LoadHost(strings.TrimSpace(manifest.WorkerJob.HostID))
	if err != nil || host == nil {
		return nil, sandboxruntime.Target{}, errors.New("runtime_handle_unavailable: durable worker host is unavailable")
	}
	if manifest.Host == nil || strings.TrimSpace(host.ID) != strings.TrimSpace(manifest.Host.ID) {
		return nil, sandboxruntime.Target{}, errors.New("runtime_handle_identity_mismatch: durable worker host identities did not match")
	}
	driver, err := sandboxWorkerRuntimeDriverFromTarget(
		sandboxWorkerRuntimeRequest{Target: target, Host: host},
		sandboxWorkerRuntimeDriverFactories{
			newWorkerClient: func(socketPath string) (sandboxworker.RuntimeDriverClient, error) {
				return sandboxL3NewWorkerClient(socketPath)
			},
		},
	)
	if err != nil {
		return nil, sandboxruntime.Target{}, errors.New("runtime_handle_unavailable: existing worker runtime handle is unavailable")
	}
	return driver, target, nil
}

func sandboxL3RuntimeTargetFromManifest(manifest *sandboxexecution.Manifest) (sandboxruntime.Target, error) {
	if manifest == nil || manifest.WorkerJob == nil {
		return sandboxruntime.Target{}, errors.New("runtime_handle_missing: durable worker runtime identity is required")
	}
	reference := manifest.WorkerJob
	driverID := strings.TrimSpace(reference.RuntimeDriver)
	runtimeID := strings.TrimSpace(reference.RuntimeID)
	workerID := strings.TrimSpace(reference.WorkerID)
	if driverID == "" || runtimeID == "" || workerID == "" {
		return sandboxruntime.Target{}, errors.New("runtime_handle_missing: durable worker runtime identity is incomplete")
	}
	if manifest.Runtime == nil {
		return sandboxruntime.Target{}, errors.New("runtime_handle_missing: durable runtime metadata is required")
	}
	if strings.TrimSpace(manifest.Runtime.Driver) != driverID ||
		strings.TrimSpace(manifest.Runtime.RuntimeID) != runtimeID ||
		strings.TrimSpace(manifest.Runtime.WorkerID) != workerID {
		return sandboxruntime.Target{}, errors.New("runtime_handle_identity_mismatch: durable runtime identities did not match")
	}
	if manifest.Host == nil ||
		strings.TrimSpace(manifest.Host.ID) != strings.TrimSpace(reference.HostID) ||
		strings.TrimSpace(manifest.Host.Kind) != sandbox.SandboxHostKindWorker {
		return sandboxruntime.Target{}, errors.New("runtime_handle_identity_mismatch: durable worker host identities did not match")
	}
	return sandboxruntime.Target{
		ID:     runtimeID,
		Name:   strings.TrimSpace(manifest.SandboxName),
		Status: sandbox.StatusRunning,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         driverID,
			RuntimeID:      runtimeID,
			Image:          strings.TrimSpace(manifest.Runtime.Image),
			WorkerID:       workerID,
			IsolationLevel: strings.TrimSpace(manifest.Runtime.IsolationLevel),
			Metadata:       sandboxRuntimeMetadataFromState(manifest.Runtime),
		},
	}, nil
}

func sandboxL3ManifestSyncRef(manifest *sandboxexecution.Manifest) string {
	if manifest == nil || manifest.Workspace == nil {
		return ""
	}
	return strings.TrimSpace(manifest.Workspace.SyncRef)
}

func releaseSandboxL3DurableLease(_ context.Context, manifest *sandboxexecution.Manifest) error {
	if manifest == nil || manifest.Lease == nil {
		return nil
	}
	reference := manifest.Lease
	leaseID := strings.TrimSpace(reference.ID)
	if leaseID == "" {
		return errors.New("lease_identity_missing: durable lease identity is required")
	}
	if strings.TrimSpace(reference.RunID) != strings.TrimSpace(manifest.ID) {
		return errors.New("lease_identity_mismatch: durable lease did not match execution")
	}
	store := sandbox.NewSandboxLeaseStore(nil)
	if _, err := store.ReleaseExact(sandbox.SandboxLeaseExactReleaseRequest{
		ID:          leaseID,
		SandboxName: strings.TrimSpace(manifest.SandboxName),
		ResourceKey: strings.TrimSpace(reference.ResourceKey),
		Purpose:     strings.TrimSpace(reference.Purpose),
		RunID:       strings.TrimSpace(reference.RunID),
		AcquiredAt:  reference.AcquiredAt,
	}); err != nil {
		return errors.New("lease_release_failed: exact durable lease was not released")
	}
	return nil
}
