package cmd

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestL8D6CredentialCleanupBlocksEveryLaterFinalizationEffect(t *testing.T) {
	store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
	manifest, err := store.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Finalization == nil {
		manifest.Finalization = &sandboxexecution.FinalizationMetadata{
			ContractVersion: sandboxexecution.FinalizationContractVersion,
			State:           sandboxexecution.FinalizationStatePending,
			UpdatedAt:       terminal.SubmittedAt,
		}
	}
	manifest.Finalization.Checkpoints.CredentialCleanup = &sandboxexecution.FinalizationCheckpoint{}
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	var forbidden atomic.Int32
	forbiddenEffect := func() { forbidden.Add(1) }
	deps := sandboxL3FinalizationDeps{
		now: func() time.Time { return terminal.FinishedAt.Add(time.Second) },
		observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
			return cloneL3WorkerJob(terminal), nil
		},
		drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			forbiddenEffect()
			return nil
		},
		collectArtifacts: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			forbiddenEffect()
			return nil
		},
		collectSyncOut: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			forbiddenEffect()
			return nil
		},
		releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
			forbiddenEffect()
			return nil
		},
	}
	err = finalizeSandboxL3Execution(context.Background(), store, executionID, true, deps)
	if err == nil || !strings.Contains(err.Error(), "credential_cleanup_incomplete") {
		t.Fatalf("finalization error = %v, want credential cleanup boundary", err)
	}
	if forbidden.Load() != 0 {
		t.Fatalf("incomplete credential cleanup crossed %d forbidden effects", forbidden.Load())
	}
	blocked, loadErr := store.LoadManifest(executionID)
	if loadErr != nil {
		t.Fatalf("LoadManifest(blocked) error: %v", loadErr)
	}
	if blocked.Finalization == nil || blocked.Finalization.State != sandboxexecution.FinalizationStateBlocked ||
		blocked.Finalization.ReasonCode != "credential_cleanup_incomplete" ||
		blocked.Finalization.Checkpoints.CredentialCleanup == nil ||
		blocked.Finalization.Checkpoints.CredentialCleanup.Completed {
		t.Fatalf("blocked credential finalization = %#v", blocked.Finalization)
	}
}

func TestL8D6CredentialCleanupCheckpointCloneIsDeep(t *testing.T) {
	completedAt := time.Date(2026, 8, 21, 2, 0, 0, 0, time.UTC)
	metadata := &sandboxexecution.FinalizationMetadata{
		ContractVersion: sandboxexecution.FinalizationContractVersion,
		State:           sandboxexecution.FinalizationStateFinalizing,
		Checkpoints: sandboxexecution.FinalizationCheckpoints{
			CredentialCleanup: &sandboxexecution.FinalizationCheckpoint{Completed: true, CompletedAt: &completedAt},
		},
		UpdatedAt: completedAt,
	}
	cloned := cloneSandboxWorkerJobFinalization(metadata)
	if cloned == nil || cloned.Checkpoints.CredentialCleanup == nil || cloned.Checkpoints.CredentialCleanup == metadata.Checkpoints.CredentialCleanup ||
		cloned.Checkpoints.CredentialCleanup.CompletedAt == metadata.Checkpoints.CredentialCleanup.CompletedAt {
		t.Fatalf("credential cleanup clone did not detach: original=%#v clone=%#v", metadata, cloned)
	}
	cloned.Checkpoints.CredentialCleanup.Completed = false
	*cloned.Checkpoints.CredentialCleanup.CompletedAt = completedAt.Add(time.Hour)
	if !metadata.Checkpoints.CredentialCleanup.Completed || !metadata.Checkpoints.CredentialCleanup.CompletedAt.Equal(completedAt) {
		t.Fatalf("credential cleanup clone mutated original: %#v", metadata.Checkpoints.CredentialCleanup)
	}
}
