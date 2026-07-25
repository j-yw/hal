package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestL3TerminalLogDrainRejectsStalledFinalCursor(t *testing.T) {
	store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
	manifest, err := store.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	terminal.LogCursor = 2
	driver := &fakeSandboxWorkerJobDriver{
		statusJobs: []sandboxworker.Job{*cloneL3WorkerJob(terminal)},
		logPages: []sandboxworker.JobLogsResponse{{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           terminal.ID,
			NextCursor:      0,
		}},
	}

	err = streamSandboxL3Logs(
		context.Background(),
		foregroundSandboxL3JobClient{driver: driver},
		manifest,
		terminal,
		true,
		io.Discard,
		io.Discard,
	)
	if err == nil || !strings.Contains(err.Error(), "worker_job_logs_incomplete") {
		t.Fatalf("stalled terminal log drain error = %v, want incomplete-log error", err)
	}
	if driver.logsCalls != 1 || driver.statusCalls != 1 {
		t.Fatalf("stalled terminal log calls = logs:%d status:%d, want one bounded attempt each", driver.logsCalls, driver.statusCalls)
	}
}

func TestL3RecoveryCommandsFinalizeConcreteDurableActionsWithoutForbiddenWork(t *testing.T) {
	for _, commandName := range []string{"recover", "sync-out"} {
		t.Run(commandName, func(t *testing.T) {
			script := &l3WorkerScript{
				jobState:         sandboxworker.JobStateSucceeded,
				logCursor:        1,
				panicOnForbidden: true,
				pages: map[uint64]sandboxworker.JobLogsResponse{
					0: {
						ContractVersion: sandboxworker.JobContractVersion,
						JobID:           "job-alpha",
						Records: []sandboxworker.JobLogRecord{{
							Cursor:    1,
							Stream:    sandboxworker.JobLogStreamStdout,
							Data:      "terminal output\n",
							Timestamp: time.Date(2026, 7, 25, 2, 0, 2, 0, time.UTC),
						}},
						NextCursor: 1,
					},
				},
			}
			harness := newL3WorkerHarness(t, script)
			harness.seed("alpha", "run-alpha", "job-alpha")
			leaseStore := seedL3RecoveryLease(t, "run-alpha", "alpha")

			originalFactories := defaultSandboxRuntimeDriverFactories
			defaultSandboxRuntimeDriverFactories = func() sandboxRuntimeDriverFactories {
				return sandboxRuntimeDriverFactories{
					sshMachine: func(sandbox.Provider) sandboxruntime.Driver {
						panic("L3 recovery resolved a provider")
					},
					rootlessPodman: func() sandboxruntime.Driver {
						panic("L3 recovery constructed a host runtime")
					},
					microVM: func() sandboxruntime.Driver {
						panic("L3 recovery constructed a microVM runtime")
					},
				}
			}
			t.Cleanup(func() {
				defaultSandboxRuntimeDriverFactories = originalFactories
			})

			stdout, stderr, err := runL3SandboxLeaf(
				context.Background(),
				commandName,
				[]string{"alpha", "--run", "run-alpha"},
			)
			if err != nil {
				t.Fatalf("%s: %v\nstdout:\n%s\nstderr:\n%s", commandName, err, stdout, stderr)
			}
			if commandName == "sync-out" {
				stdout, stderr, err = runL3SandboxLeaf(
					context.Background(),
					commandName,
					[]string{"alpha", "--run", "run-alpha"},
				)
				if err != nil {
					t.Fatalf("%s retry: %v\nstdout:\n%s\nstderr:\n%s", commandName, err, stdout, stderr)
				}
			}

			store, err := sandboxexecution.DefaultStore()
			if err != nil {
				t.Fatalf("open execution store: %v", err)
			}
			manifest, err := store.LoadManifest("run-alpha")
			if err != nil {
				t.Fatalf("load finalized manifest: %v", err)
			}
			if manifest.Status != sandboxexecution.StatusSucceeded ||
				manifest.Finalization == nil ||
				manifest.Finalization.State != sandboxexecution.FinalizationStateCompleted {
				t.Fatalf("finalized manifest = %#v", manifest)
			}
			checkpoints := manifest.Finalization.Checkpoints
			if !checkpoints.Artifacts.Completed || !checkpoints.LeaseRelease.Completed ||
				!checkpoints.TerminalPublication.Completed {
				t.Fatalf("finalization checkpoints = %#v", checkpoints)
			}
			if commandName == "sync-out" {
				if !manifest.Finalization.SyncOutRequested || !checkpoints.SyncOut.Completed {
					t.Fatalf("sync-out finalization = %#v", manifest.Finalization)
				}
				if manifest.SyncOut == nil {
					t.Fatal("sync-out summary was not persisted")
				}
				if manifest.SyncOutApply != nil {
					t.Fatalf("sync-out recovery implicitly applied to the host: %#v", manifest.SyncOutApply)
				}
				assertL3RecoverySyncOutSummarySafe(t, manifest.SyncOut)
			} else if manifest.SyncOut != nil || checkpoints.SyncOut.Completed {
				t.Fatalf("ordinary recovery persisted sync-out state: %#v / %#v", manifest.SyncOut, checkpoints.SyncOut)
			}
			assertL3RecoveryArtifactsUnique(t, manifest)

			released, err := leaseStore.Load("lease-run-alpha")
			if err != nil {
				t.Fatalf("load released lease: %v", err)
			}
			if released.Status != sandbox.SandboxLeaseStatusReleased {
				t.Fatalf("exact lease status = %q, want released", released.Status)
			}
			decoy, err := leaseStore.Load("lease-decoy")
			if err != nil {
				t.Fatalf("load decoy lease: %v", err)
			}
			if decoy.Status != sandbox.SandboxLeaseStatusActive {
				t.Fatalf("unrelated lease status = %q, want active", decoy.Status)
			}
			if _, err := os.Stat(harness.hostMutationMarker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s invoked provider/apply host mutation; marker stat error = %v", commandName, err)
			}
		})
	}
}

func TestL3RecoveryUnknownAndInterruptedNeverCrossConcreteActionBoundaries(t *testing.T) {
	for _, state := range []string{sandboxworker.JobStateUnknown, sandboxworker.JobStateInterrupted} {
		t.Run(state, func(t *testing.T) {
			harness := newL3WorkerHarness(t, &l3WorkerScript{
				jobState:               state,
				panicOnForbidden:       true,
				panicUnlessObservation: true,
				pages:                  map[uint64]sandboxworker.JobLogsResponse{},
			})
			harness.seed("alpha", "run-alpha", "job-alpha")
			leaseStore := seedL3RecoveryLease(t, "run-alpha", "alpha")

			_, _, err := runL3SandboxLeaf(
				context.Background(),
				"sync-out",
				[]string{"alpha", "--run", "run-alpha"},
			)
			if err == nil || !strings.Contains(err.Error(), "terminal_proof_unavailable") {
				t.Fatalf("%s recovery error = %v, want terminal proof boundary", state, err)
			}

			store, storeErr := sandboxexecution.DefaultStore()
			if storeErr != nil {
				t.Fatalf("open execution store: %v", storeErr)
			}
			manifest, loadErr := store.LoadManifest("run-alpha")
			if loadErr != nil {
				t.Fatalf("load blocked manifest: %v", loadErr)
			}
			if manifest.Finalization == nil ||
				manifest.Finalization.State != sandboxexecution.FinalizationStateBlocked ||
				manifest.Finalization.ReasonCode != "terminal_proof_unavailable" ||
				manifest.Finalization.Checkpoints.Artifacts.Completed ||
				manifest.Finalization.Checkpoints.SyncOut.Completed ||
				manifest.Finalization.Checkpoints.LeaseRelease.Completed {
				t.Fatalf("%s blocked finalization = %#v", state, manifest.Finalization)
			}
			wantStatus := sandboxexecution.Status(state)
			if manifest.Status != wantStatus || manifest.FinishedAt == nil {
				t.Fatalf("%s blocked manifest status/finishedAt = %q/%v, want %q/non-nil", state, manifest.Status, manifest.FinishedAt, wantStatus)
			}
			stdout, stderr, statusErr := runL3SandboxLeaf(
				context.Background(),
				"status",
				[]string{"alpha", "--json"},
			)
			if statusErr != nil {
				t.Fatalf("%s cached status: %v\nstdout:\n%s\nstderr:\n%s", state, statusErr, stdout, stderr)
			}
			var projection sandboxL3StatusResponse
			if err := json.Unmarshal([]byte(stdout), &projection); err != nil {
				t.Fatalf("%s decode cached status: %v\n%s", state, err, stdout)
			}
			if projection.Execution == nil || projection.Execution.Status != state || projection.Execution.Active {
				t.Fatalf("%s cached execution projection = %#v", state, projection.Execution)
			}
			lease, leaseErr := leaseStore.Load("lease-run-alpha")
			if leaseErr != nil {
				t.Fatalf("load exact lease: %v", leaseErr)
			}
			if lease.Status != sandbox.SandboxLeaseStatusActive {
				t.Fatalf("%s exact lease status = %q, want active", state, lease.Status)
			}
			if manifest.SyncOut != nil || manifest.SyncOutApply != nil {
				t.Fatalf("%s persisted mutable sync-out state: %#v / %#v", state, manifest.SyncOut, manifest.SyncOutApply)
			}
			if _, statErr := os.Stat(harness.hostMutationMarker); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s invoked provider/apply host mutation; marker stat error = %v", state, statErr)
			}
		})
	}
}

func TestL3RecoveryBestEffortPartialResultsBlockAndRetryCleanly(t *testing.T) {
	tests := []struct {
		name            string
		command         string
		failureMarker   string
		reasonCode      string
		checkpoint      func(*sandboxexecution.FinalizationMetadata) bool
		partialArtifact string
		preCheckpointOK func(*sandboxexecution.FinalizationMetadata) bool
	}{
		{
			name:          "recovery-artifact",
			command:       "recover",
			failureMarker: ".hal/recovery/workspace.patch",
			reasonCode:    "artifact_collection_failed",
			checkpoint: func(finalization *sandboxexecution.FinalizationMetadata) bool {
				return finalization.Checkpoints.Artifacts.Completed
			},
			partialArtifact: "recovery-patch",
			preCheckpointOK: func(*sandboxexecution.FinalizationMetadata) bool { return true },
		},
		{
			name:          "sync-out-artifact",
			command:       "sync-out",
			failureMarker: ".hal/sync/uncommitted.diff",
			reasonCode:    "sync_out_collection_failed",
			checkpoint: func(finalization *sandboxexecution.FinalizationMetadata) bool {
				return finalization.Checkpoints.SyncOut.Completed
			},
			partialArtifact: "uncommitted-diff",
			preCheckpointOK: func(finalization *sandboxexecution.FinalizationMetadata) bool {
				return finalization.Checkpoints.Artifacts.Completed
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := &l3WorkerScript{
				jobState:         sandboxworker.JobStateSucceeded,
				panicOnForbidden: true,
				pages:            map[uint64]sandboxworker.JobLogsResponse{},
				failExecContains: map[string]int{tt.failureMarker: 1},
			}
			harness := newL3WorkerHarness(t, script)
			harness.seed("alpha", "run-alpha", "job-alpha")
			leaseStore := seedL3RecoveryLease(t, "run-alpha", "alpha")

			_, _, err := runL3SandboxLeaf(
				context.Background(),
				tt.command,
				[]string{"alpha", "--run", "run-alpha"},
			)
			if err == nil || !strings.Contains(err.Error(), tt.reasonCode) {
				t.Fatalf("first %s error = %v, want %s", tt.command, err, tt.reasonCode)
			}
			store, err := sandboxexecution.DefaultStore()
			if err != nil {
				t.Fatalf("open execution store: %v", err)
			}
			blocked, err := store.LoadManifest("run-alpha")
			if err != nil {
				t.Fatalf("load blocked manifest: %v", err)
			}
			if blocked.Finalization == nil ||
				blocked.Finalization.State != sandboxexecution.FinalizationStateBlocked ||
				blocked.Finalization.ReasonCode != tt.reasonCode ||
				tt.checkpoint(blocked.Finalization) ||
				!tt.preCheckpointOK(blocked.Finalization) ||
				blocked.Finalization.Checkpoints.LeaseRelease.Completed ||
				blocked.Finalization.Checkpoints.TerminalPublication.Completed {
				t.Fatalf("blocked finalization = %#v", blocked.Finalization)
			}
			requireL3ArtifactAttemptState(t, blocked, tt.partialArtifact, true)
			lease, err := leaseStore.Load("lease-run-alpha")
			if err != nil {
				t.Fatalf("load blocked lease: %v", err)
			}
			if lease.Status != sandbox.SandboxLeaseStatusActive {
				t.Fatalf("blocked lease status = %q, want active", lease.Status)
			}

			_, _, err = runL3SandboxLeaf(
				context.Background(),
				tt.command,
				[]string{"alpha", "--run", "run-alpha"},
			)
			if err != nil {
				t.Fatalf("retry %s: %v", tt.command, err)
			}
			completed, err := store.LoadManifest("run-alpha")
			if err != nil {
				t.Fatalf("load completed manifest: %v", err)
			}
			if completed.Finalization == nil ||
				completed.Finalization.State != sandboxexecution.FinalizationStateCompleted ||
				!tt.checkpoint(completed.Finalization) ||
				!completed.Finalization.Checkpoints.LeaseRelease.Completed ||
				!completed.Finalization.Checkpoints.TerminalPublication.Completed {
				t.Fatalf("completed finalization = %#v", completed.Finalization)
			}
			requireL3ArtifactAttemptState(t, completed, tt.partialArtifact, false)
		})
	}
}

func TestL3RecoveryDrainPersistsBoundedRedactedOutputSummaries(t *testing.T) {
	chunk := strings.Repeat("x", 20<<10)
	recordedAt := time.Date(2026, 7, 25, 2, 0, 2, 0, time.UTC)
	script := &l3WorkerScript{
		jobState:         sandboxworker.JobStateSucceeded,
		logCursor:        5,
		panicOnForbidden: true,
		pages: map[uint64]sandboxworker.JobLogsResponse{
			0: {
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           "job-alpha",
				Records: []sandboxworker.JobLogRecord{
					{Cursor: 1, Stream: sandboxworker.JobLogStreamStdout, Data: "safe stdout\n" + chunk, Timestamp: recordedAt},
					{Cursor: 2, Stream: sandboxworker.JobLogStreamStdout, Data: chunk, Timestamp: recordedAt},
				},
				NextCursor: 2,
			},
			2: {
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           "job-alpha",
				Records: []sandboxworker.JobLogRecord{
					{Cursor: 3, Stream: sandboxworker.JobLogStreamStdout, Data: chunk, Timestamp: recordedAt},
					{Cursor: 4, Stream: sandboxworker.JobLogStreamStdout, Data: chunk, Timestamp: recordedAt},
				},
				NextCursor: 4,
			},
			4: {
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           "job-alpha",
				Records: []sandboxworker.JobLogRecord{
					{Cursor: 5, Stream: sandboxworker.JobLogStreamStderr, Data: "TOKEN=detached-secret\nsafe stderr\n", Timestamp: recordedAt},
				},
				NextCursor: 5,
			},
		},
	}
	harness := newL3WorkerHarness(t, script)
	harness.seed("alpha", "run-alpha", "job-alpha")
	seedL3RecoveryLease(t, "run-alpha", "alpha")

	if _, _, err := runL3SandboxLeaf(context.Background(), "recover", []string{"alpha", "--run", "run-alpha"}); err != nil {
		t.Fatalf("recover: %v", err)
	}
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	manifest, err := store.LoadManifest("run-alpha")
	if err != nil {
		t.Fatalf("load recovered manifest: %v", err)
	}
	stdout := readL3RecoveryOutputSummary(t, store, manifest, "stdout-summary")
	stderr := readL3RecoveryOutputSummary(t, store, manifest, "stderr-summary")
	if len(stdout) > int(sandboxworker.DefaultJobLogReadBytes) {
		t.Fatalf("stdout summary bytes = %d, want <= %d", len(stdout), sandboxworker.DefaultJobLogReadBytes)
	}
	if !strings.Contains(stdout, "safe stdout") {
		t.Fatalf("stdout summary omitted retained output: %q", stdout)
	}
	if !strings.Contains(stderr, "safe stderr") || strings.Contains(stderr, "detached-secret") || strings.Contains(stderr, "TOKEN=") {
		t.Fatalf("stderr summary was not safely redacted: %q", stderr)
	}
}

func TestL3FollowLogsRetriesOnlyTransientDaemonTransportFailures(t *testing.T) {
	tests := []struct {
		name      string
		failures  map[string]int
		operation string
	}{
		{
			name:      "initial-status",
			failures:  map[string]int{sandboxworker.OperationJobStatus: 1},
			operation: sandboxworker.OperationJobStatus,
		},
		{
			name:      "log-page",
			failures:  map[string]int{sandboxworker.OperationJobLogs: 1},
			operation: sandboxworker.OperationJobLogs,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recordedAt := time.Date(2026, 7, 25, 2, 0, 2, 0, time.UTC)
			script := &l3WorkerScript{
				jobState:          sandboxworker.JobStateSucceeded,
				logCursor:         1,
				transportFailures: tt.failures,
				pages: map[uint64]sandboxworker.JobLogsResponse{
					0: {
						ContractVersion: sandboxworker.JobContractVersion,
						JobID:           "job-alpha",
						Records: []sandboxworker.JobLogRecord{{
							Cursor:    1,
							Stream:    sandboxworker.JobLogStreamStdout,
							Data:      "reattached output\n",
							Timestamp: recordedAt,
						}},
						NextCursor: 1,
					},
				},
			}
			harness := newL3WorkerHarness(t, script)
			harness.seed("alpha", "run-alpha", "job-alpha")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			stdout, stderr, err := runL3SandboxLeaf(ctx, "logs", []string{"alpha", "--run", "run-alpha", "--follow"})
			if err != nil {
				t.Fatalf("follow after transient %s failure: %v\nstdout:\n%s\nstderr:\n%s", tt.operation, err, stdout, stderr)
			}
			if !strings.Contains(stdout, "reattached output") {
				t.Fatalf("follow output after transient %s failure = %q", tt.operation, stdout)
			}
			if attempts := script.transportAttemptCount(tt.operation); attempts < 2 {
				t.Fatalf("%s transport attempts = %d, want retry", tt.operation, attempts)
			}
		})
	}
}

func TestL3LogReconnectBoundariesRemainFailClosed(t *testing.T) {
	t.Run("non-follow-transport-fails-fast", func(t *testing.T) {
		script := &l3WorkerScript{
			jobState:          sandboxworker.JobStateSucceeded,
			transportFailures: map[string]int{sandboxworker.OperationJobStatus: 2},
			pages:             map[uint64]sandboxworker.JobLogsResponse{},
		}
		harness := newL3WorkerHarness(t, script)
		harness.seed("alpha", "run-alpha", "job-alpha")
		_, _, err := runL3SandboxLeaf(context.Background(), "logs", []string{"alpha", "--run", "run-alpha"})
		if err == nil || !strings.Contains(err.Error(), "worker_job_status_failed") {
			t.Fatalf("non-follow transport error = %v", err)
		}
		if attempts := script.transportAttemptCount(sandboxworker.OperationJobStatus); attempts != 1 {
			t.Fatalf("non-follow status attempts = %d, want 1", attempts)
		}
	})

	t.Run("follow-protocol-error-is-not-retried", func(t *testing.T) {
		script := &l3WorkerScript{
			jobState:         sandboxworker.JobStateSucceeded,
			protocolFailures: map[string]int{sandboxworker.OperationJobLogs: 2},
			pages:            map[uint64]sandboxworker.JobLogsResponse{},
		}
		harness := newL3WorkerHarness(t, script)
		harness.seed("alpha", "run-alpha", "job-alpha")
		_, _, err := runL3SandboxLeaf(context.Background(), "logs", []string{"alpha", "--run", "run-alpha", "--follow"})
		if err == nil || !strings.Contains(err.Error(), "worker_job_logs_failed") {
			t.Fatalf("follow protocol error = %v", err)
		}
		if attempts := script.transportAttemptCount(sandboxworker.OperationJobLogs); attempts != 1 {
			t.Fatalf("follow protocol attempts = %d, want 1", attempts)
		}
	})

	t.Run("follow-transport-stops-at-context", func(t *testing.T) {
		script := &l3WorkerScript{
			jobState:          sandboxworker.JobStateSucceeded,
			transportFailures: map[string]int{sandboxworker.OperationJobStatus: 100},
			pages:             map[uint64]sandboxworker.JobLogsResponse{},
		}
		harness := newL3WorkerHarness(t, script)
		harness.seed("alpha", "run-alpha", "job-alpha")
		ctx, cancel := context.WithTimeout(context.Background(), 140*time.Millisecond)
		defer cancel()
		_, _, err := runL3SandboxLeaf(ctx, "logs", []string{"alpha", "--run", "run-alpha", "--follow"})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("follow persistent transport error = %v, want context deadline", err)
		}
		if attempts := script.transportAttemptCount(sandboxworker.OperationJobStatus); attempts < 2 || attempts > 8 {
			t.Fatalf("bounded follow status attempts = %d, want 2..8", attempts)
		}
	})
}

func TestL3StandaloneSyncOutAfterCompletedRecoveryDoesNotReplayFinalization(t *testing.T) {
	script := &l3WorkerScript{
		jobState:         sandboxworker.JobStateSucceeded,
		panicOnForbidden: true,
		pages:            map[uint64]sandboxworker.JobLogsResponse{},
	}
	harness := newL3WorkerHarness(t, script)
	harness.seed("alpha", "run-alpha", "job-alpha")
	leaseStore := seedL3RecoveryLease(t, "run-alpha", "alpha")

	if _, _, err := runL3SandboxLeaf(context.Background(), "recover", []string{"alpha", "--run", "run-alpha"}); err != nil {
		t.Fatalf("initial recover: %v", err)
	}
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	before, err := store.LoadManifest("run-alpha")
	if err != nil {
		t.Fatalf("load completed recovery: %v", err)
	}
	artifactCompletedAt := cloneL3Time(before.Finalization.Checkpoints.Artifacts.CompletedAt)
	leaseCompletedAt := cloneL3Time(before.Finalization.Checkpoints.LeaseRelease.CompletedAt)
	publicationCompletedAt := cloneL3Time(before.Finalization.Checkpoints.TerminalPublication.CompletedAt)

	script.mu.Lock()
	script.failExecContains = map[string]int{".hal/sync/uncommitted.diff": 1}
	script.mu.Unlock()
	if _, _, err := runL3SandboxLeaf(context.Background(), "sync-out", []string{"alpha"}); err == nil ||
		!strings.Contains(err.Error(), "sync_out_collection_failed") {
		t.Fatalf("first standalone post-completion sync-out error = %v", err)
	}
	blocked, err := store.LoadManifest("run-alpha")
	if err != nil {
		t.Fatalf("load blocked post-completion sync-out: %v", err)
	}
	if blocked.Finalization == nil ||
		blocked.Finalization.State != sandboxexecution.FinalizationStateBlocked ||
		blocked.Finalization.Checkpoints.SyncOut.Completed ||
		!sameL3Time(artifactCompletedAt, blocked.Finalization.Checkpoints.Artifacts.CompletedAt) ||
		!sameL3Time(leaseCompletedAt, blocked.Finalization.Checkpoints.LeaseRelease.CompletedAt) ||
		!sameL3Time(publicationCompletedAt, blocked.Finalization.Checkpoints.TerminalPublication.CompletedAt) {
		t.Fatalf("blocked post-completion sync-out replayed prior checkpoints: before=%#v blocked=%#v", before.Finalization.Checkpoints, blocked.Finalization)
	}

	if _, _, err := runL3SandboxLeaf(context.Background(), "sync-out", []string{"alpha"}); err != nil {
		t.Fatalf("standalone post-completion sync-out: %v", err)
	}
	after, err := store.LoadManifest("run-alpha")
	if err != nil {
		t.Fatalf("load post-completion sync-out: %v", err)
	}
	if after.Finalization == nil ||
		after.Finalization.State != sandboxexecution.FinalizationStateCompleted ||
		!after.Finalization.SyncOutRequested ||
		!after.Finalization.Checkpoints.SyncOut.Completed ||
		after.SyncOut == nil ||
		after.SyncOutApply != nil {
		t.Fatalf("post-completion sync-out state = finalization %#v summary %#v apply %#v", after.Finalization, after.SyncOut, after.SyncOutApply)
	}
	if !sameL3Time(artifactCompletedAt, after.Finalization.Checkpoints.Artifacts.CompletedAt) ||
		!sameL3Time(leaseCompletedAt, after.Finalization.Checkpoints.LeaseRelease.CompletedAt) ||
		!sameL3Time(publicationCompletedAt, after.Finalization.Checkpoints.TerminalPublication.CompletedAt) {
		t.Fatalf("post-completion sync-out replayed prior checkpoints: before=%#v after=%#v", before.Finalization.Checkpoints, after.Finalization.Checkpoints)
	}
	lease, err := leaseStore.Load("lease-run-alpha")
	if err != nil {
		t.Fatalf("load released lease: %v", err)
	}
	if lease.Status != sandbox.SandboxLeaseStatusReleased {
		t.Fatalf("post-completion lease status = %q, want released", lease.Status)
	}
	if _, err := os.Stat(harness.hostMutationMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("post-completion sync-out implicitly applied to host; marker stat error = %v", err)
	}
}

func TestL3ExplicitRecoveryRejectsCompletedExecution(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	now := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	saveL3Sandbox(t, "alpha", now)
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	manifest := l3Manifest("run-completed", "alpha", now, "job-completed", sandboxworker.JobStateSucceeded, 0)
	manifest.Status = sandboxexecution.StatusSucceeded
	completedAt := now.Add(3 * time.Second)
	completed := sandboxexecution.FinalizationCheckpoint{Completed: true, CompletedAt: &completedAt}
	manifest.Finalization = &sandboxexecution.FinalizationMetadata{
		ContractVersion:  sandboxexecution.FinalizationContractVersion,
		State:            sandboxexecution.FinalizationStateCompleted,
		TerminalJobState: sandboxworker.JobStateSucceeded,
		Checkpoints: sandboxexecution.FinalizationCheckpoints{
			Artifacts:           completed,
			LeaseRelease:        completed,
			TerminalPublication: completed,
		},
		StartedAt:   &completedAt,
		UpdatedAt:   completedAt,
		CompletedAt: &completedAt,
	}
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("save completed execution: %v", err)
	}

	_, _, err = selectSandboxL3Execution("alpha", "run-completed", sandboxL3SelectionRecover)
	if err == nil || !strings.Contains(err.Error(), "execution_not_recoverable") {
		t.Fatalf("explicit completed recovery selection error = %v, want execution_not_recoverable", err)
	}
	manifest.Finalization.SyncOutRequested = true
	manifest.Finalization.Checkpoints.SyncOut = completed
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("save completed sync-out execution: %v", err)
	}
	_, selected, err := selectSandboxL3Execution("alpha", "run-completed", sandboxL3SelectionSyncOut)
	if err != nil {
		t.Fatalf("explicit repeated sync-out selection error = %v", err)
	}
	if selected.ID != manifest.ID {
		t.Fatalf("explicit repeated sync-out selected %q, want %q", selected.ID, manifest.ID)
	}
}

func seedL3RecoveryLease(t *testing.T, executionID, sandboxName string) *sandbox.SandboxLeaseStore {
	t.Helper()
	now := time.Date(2026, 7, 25, 2, 0, 0, 0, time.UTC)
	store := sandbox.NewSandboxLeaseStore(func() time.Time { return now })
	exact, err := store.Acquire(sandbox.SandboxLeaseAcquireRequest{
		ID:          "lease-" + executionID,
		SandboxID:   "sandbox-" + sandboxName,
		SandboxName: sandboxName,
		ResourceKey: "host:worker-l3",
		Holder:      "holder-" + executionID,
		Purpose:     sandbox.SandboxLeasePurposeRun,
		RunID:       executionID,
	}, time.Hour)
	if err != nil {
		t.Fatalf("acquire exact recovery lease: %v", err)
	}
	if _, err := store.Acquire(sandbox.SandboxLeaseAcquireRequest{
		ID:          "lease-decoy",
		SandboxID:   "sandbox-decoy",
		SandboxName: "decoy",
		ResourceKey: "runtime:decoy",
		Holder:      "holder-decoy",
		Purpose:     sandbox.SandboxLeasePurposeRun,
		RunID:       "run-decoy",
	}, time.Hour); err != nil {
		t.Fatalf("acquire decoy recovery lease: %v", err)
	}

	executionStore, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	manifest, err := executionStore.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("load recovery manifest: %v", err)
	}
	manifest.Workspace = &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		Branch:      "feature/l3-recovery",
		SyncRef:     "base-l3-recovery",
	}
	manifest.Lease = &sandbox.SandboxLeaseRef{
		ID:            exact.ID,
		HostID:        "worker-l3",
		HostName:      "worker-l3",
		RuntimeDriver: sandbox.SandboxRuntimeDriverRootlessPodman,
		ResourceKey:   exact.ResourceKey,
		Purpose:       exact.Purpose,
		RunID:         exact.RunID,
		AcquiredAt:    exact.AcquiredAt,
		ExpiresAt:     exact.ExpiresAt,
	}
	if err := executionStore.SaveManifest(manifest); err != nil {
		t.Fatalf("save recovery lease reference: %v", err)
	}
	return store
}

func assertL3RecoveryArtifactsUnique(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	if manifest.ArtifactMetadata == nil {
		t.Fatal("artifact metadata was not persisted")
	}
	seen := map[string]bool{}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		key := artifact.ID + "\x00" + artifact.Path
		if seen[key] {
			t.Errorf("artifact metadata duplicated stable identity %q", key)
		}
		seen[key] = true
	}
	for _, requiredID := range []string{"prd", "progress", "recovery-patch", "reports-archive", "stdout-summary"} {
		found := false
		for _, artifact := range manifest.ArtifactMetadata.Collected {
			if artifact.ID == requiredID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("artifact metadata missing %q: %#v", requiredID, manifest.ArtifactMetadata.Collected)
		}
	}
}

func requireL3ArtifactAttemptState(t *testing.T, manifest *sandboxexecution.Manifest, artifactID string, wantPartial bool) {
	t.Helper()
	if manifest == nil || manifest.ArtifactMetadata == nil {
		t.Fatalf("artifact metadata unavailable for %q", artifactID)
	}
	partial := false
	for _, artifact := range manifest.ArtifactMetadata.Partial {
		if artifact.ID == artifactID {
			partial = true
		}
	}
	warning := false
	for _, artifactWarning := range manifest.ArtifactMetadata.Warnings {
		if artifactWarning.Artifact.ID == artifactID {
			warning = true
		}
	}
	if partial != wantPartial || warning != wantPartial {
		t.Fatalf("artifact %q partial/warning = %v/%v, want %v/%v: %#v", artifactID, partial, warning, wantPartial, wantPartial, manifest.ArtifactMetadata)
	}
}

func readL3RecoveryOutputSummary(
	t *testing.T,
	store sandboxexecution.Store,
	manifest *sandboxexecution.Manifest,
	artifactID string,
) string {
	t.Helper()
	if manifest == nil || manifest.ArtifactMetadata == nil {
		t.Fatalf("output summary metadata unavailable for %q", artifactID)
	}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		if artifact.ID != artifactID {
			continue
		}
		file, err := store.OpenStoredFile(manifest.ID, artifact.StoredPath)
		if err != nil {
			t.Fatalf("open output summary %q: %v", artifactID, err)
		}
		defer file.Close()
		payload, err := io.ReadAll(file)
		if err != nil {
			t.Fatalf("read output summary %q: %v", artifactID, err)
		}
		return string(payload)
	}
	t.Fatalf("output summary artifact %q missing: %#v", artifactID, manifest.ArtifactMetadata.Collected)
	return ""
}

func sameL3Time(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func assertL3RecoverySyncOutSummarySafe(t *testing.T, summary *sandboxworkspace.SyncOutSummary) {
	t.Helper()
	payload := strings.ToLower(strings.TrimSpace(summary.Workspace.InputSource + " " + summary.Workspace.Branch + " " + summary.Workspace.SyncRef))
	for _, forbidden := range []string{"/home/", "/tmp/", "token=", "https://"} {
		if strings.Contains(payload, forbidden) {
			t.Errorf("sync-out summary leaked %q: %#v", forbidden, summary)
		}
	}
}
