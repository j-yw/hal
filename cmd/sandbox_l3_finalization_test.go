package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestL3FinalizationRunsOrderedSideEffectsOnceAcrossRetries(t *testing.T) {
	store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
	var mu sync.Mutex
	var calls []string
	appendCall := func(name string) {
		mu.Lock()
		calls = append(calls, name)
		mu.Unlock()
	}
	deps := sandboxL3FinalizationDeps{
		now: func() time.Time { return terminal.FinishedAt.Add(time.Second) },
		observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
			appendCall("observe")
			return cloneL3WorkerJob(terminal), nil
		},
		drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			appendCall("logs")
			return nil
		},
		collectArtifacts: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			appendCall("artifacts")
			return nil
		},
		collectSyncOut: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			appendCall("sync-out")
			return nil
		},
		releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
			appendCall("lease")
			return nil
		},
	}

	if err := finalizeSandboxL3Execution(context.Background(), store, executionID, true, deps); err != nil {
		t.Fatalf("first finalization: %v", err)
	}
	if err := finalizeSandboxL3Execution(context.Background(), store, executionID, true, deps); err != nil {
		t.Fatalf("repeated finalization: %v", err)
	}
	if got, want := strings.Join(calls, ","), "observe,logs,artifacts,sync-out,lease"; got != want {
		t.Fatalf("finalization calls = %q, want %q", got, want)
	}

	manifest, err := store.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded || manifest.FinishedAt == nil {
		t.Fatalf("terminal manifest = status %q finishedAt %v", manifest.Status, manifest.FinishedAt)
	}
	if manifest.Finalization == nil || manifest.Finalization.State != sandboxexecution.FinalizationStateCompleted {
		t.Fatalf("finalization = %#v, want completed", manifest.Finalization)
	}
	checkpoints := manifest.Finalization.Checkpoints
	if !checkpoints.Artifacts.Completed || !checkpoints.SyncOut.Completed ||
		!checkpoints.LeaseRelease.Completed || !checkpoints.TerminalPublication.Completed {
		t.Fatalf("finalization checkpoints = %#v, want all completed", checkpoints)
	}
}

func TestL3FinalizationConcurrentRecoverySerializesExternalEffects(t *testing.T) {
	store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
	var observeCalls, logCalls, artifactCalls, releaseCalls atomic.Int32
	deps := sandboxL3FinalizationDeps{
		now: func() time.Time { return terminal.FinishedAt.Add(time.Second) },
		observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
			observeCalls.Add(1)
			return cloneL3WorkerJob(terminal), nil
		},
		drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			logCalls.Add(1)
			return nil
		},
		collectArtifacts: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			artifactCalls.Add(1)
			return nil
		},
		releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
			releaseCalls.Add(1)
			return nil
		},
	}

	const attempts = 8
	start := make(chan struct{})
	errs := make(chan error, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- finalizeSandboxL3Execution(context.Background(), store, executionID, false, deps)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent finalization error: %v", err)
		}
	}
	if observeCalls.Load() != 1 || logCalls.Load() != 1 || artifactCalls.Load() != 1 || releaseCalls.Load() != 1 {
		t.Fatalf("concurrent calls observe/log/artifact/release = %d/%d/%d/%d, want 1/1/1/1",
			observeCalls.Load(), logCalls.Load(), artifactCalls.Load(), releaseCalls.Load())
	}
}

func TestL3FinalizationResumesAfterEachCheckpointFailureWithoutRepeatingCompletedWork(t *testing.T) {
	tests := []struct {
		name       string
		failing    string
		reasonCode string
	}{
		{name: "artifact", failing: "artifact", reasonCode: "artifact_collection_failed"},
		{name: "sync-out", failing: "sync-out", reasonCode: "sync_out_collection_failed"},
		{name: "lease", failing: "lease", reasonCode: "lease_release_failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
			var mu sync.Mutex
			counts := map[string]int{}
			call := func(name string) error {
				mu.Lock()
				defer mu.Unlock()
				counts[name]++
				if name == tt.failing && counts[name] == 1 {
					return errors.New("TOKEN=finalization-secret /home/private/path")
				}
				return nil
			}
			deps := sandboxL3FinalizationDeps{
				now: func() time.Time { return terminal.FinishedAt.Add(time.Second) },
				observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
					_ = call("observe")
					return cloneL3WorkerJob(terminal), nil
				},
				drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
					return call("logs")
				},
				collectArtifacts: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
					return call("artifact")
				},
				collectSyncOut: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
					return call("sync-out")
				},
				releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
					return call("lease")
				},
			}

			err := finalizeSandboxL3Execution(context.Background(), store, executionID, true, deps)
			if err == nil || !strings.Contains(err.Error(), tt.reasonCode) {
				t.Fatalf("first finalization error = %v, want %s", err, tt.reasonCode)
			}
			for _, secret := range []string{"finalization-secret", "/home/private/path", "TOKEN="} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("finalization error leaked %q: %v", secret, err)
				}
			}
			blocked, loadErr := store.LoadManifest(executionID)
			if loadErr != nil {
				t.Fatalf("LoadManifest(blocked) error: %v", loadErr)
			}
			if blocked.Finalization == nil || blocked.Finalization.State != sandboxexecution.FinalizationStateBlocked ||
				blocked.Finalization.ReasonCode != tt.reasonCode {
				t.Fatalf("blocked finalization = %#v", blocked.Finalization)
			}

			if err := finalizeSandboxL3Execution(context.Background(), store, executionID, true, deps); err != nil {
				t.Fatalf("retry finalization: %v", err)
			}
			if counts[tt.failing] != 2 {
				t.Fatalf("%s calls = %d, want retry once", tt.failing, counts[tt.failing])
			}
			switch tt.failing {
			case "sync-out":
				if counts["artifact"] != 1 {
					t.Fatalf("completed artifact step repeated %d times", counts["artifact"])
				}
			case "lease":
				if counts["artifact"] != 1 || counts["sync-out"] != 1 {
					t.Fatalf("completed pre-lease steps repeated: %#v", counts)
				}
			}
		})
	}
}

func TestL3FinalizationUnknownOrInterruptedFailsClosedBeforeSideEffects(t *testing.T) {
	for _, state := range []string{sandboxworker.JobStateUnknown, sandboxworker.JobStateInterrupted} {
		t.Run(state, func(t *testing.T) {
			store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
			terminal.State = state
			terminal.FailureCode = "unproven"
			var forbidden atomic.Int32
			deps := sandboxL3FinalizationDeps{
				now: func() time.Time { return terminal.FinishedAt.Add(time.Second) },
				observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
					return cloneL3WorkerJob(terminal), nil
				},
				drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
					forbidden.Add(1)
					return nil
				},
				collectArtifacts: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
					forbidden.Add(1)
					return nil
				},
				collectSyncOut: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
					forbidden.Add(1)
					return nil
				},
				releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
					forbidden.Add(1)
					return nil
				},
			}
			err := finalizeSandboxL3Execution(context.Background(), store, executionID, true, deps)
			if err == nil || !strings.Contains(err.Error(), "terminal_proof_unavailable") {
				t.Fatalf("finalization error = %v, want terminal proof boundary", err)
			}
			if forbidden.Load() != 0 {
				t.Fatalf("unproven state crossed %d forbidden boundaries", forbidden.Load())
			}
			manifest, loadErr := store.LoadManifest(executionID)
			if loadErr != nil {
				t.Fatalf("LoadManifest() error: %v", loadErr)
			}
			if manifest.Finalization == nil ||
				manifest.Finalization.State != sandboxexecution.FinalizationStateBlocked ||
				manifest.Finalization.ReasonCode != "terminal_proof_unavailable" ||
				manifest.Finalization.Checkpoints.Artifacts.Completed ||
				manifest.Finalization.Checkpoints.LeaseRelease.Completed {
				t.Fatalf("unproven finalization = %#v", manifest.Finalization)
			}
		})
	}
}

func TestL3FinalizationIdentityMismatchDoesNotMutateOrFinalize(t *testing.T) {
	store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
	terminal.RuntimeID = "other-runtime"
	before, err := store.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("LoadManifest(before) error: %v", err)
	}
	var forbidden atomic.Int32
	deps := sandboxL3FinalizationDeps{
		observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
			return cloneL3WorkerJob(terminal), nil
		},
		drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			forbidden.Add(1)
			return nil
		},
		collectArtifacts: func(context.Context, sandboxexecution.Store, *sandboxexecution.Manifest, *sandboxworker.Job) error {
			forbidden.Add(1)
			return nil
		},
		releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
			forbidden.Add(1)
			return nil
		},
	}
	err = finalizeSandboxL3Execution(context.Background(), store, executionID, false, deps)
	if err == nil || !strings.Contains(err.Error(), "worker_job_identity_mismatch") {
		t.Fatalf("identity mismatch error = %v", err)
	}
	if forbidden.Load() != 0 {
		t.Fatalf("identity mismatch crossed %d forbidden boundaries", forbidden.Load())
	}
	after, loadErr := store.LoadManifest(executionID)
	if loadErr != nil {
		t.Fatalf("LoadManifest(after) error: %v", loadErr)
	}
	if after.Finalization != before.Finalization || after.WorkerJob.RuntimeID != before.WorkerJob.RuntimeID {
		t.Fatalf("identity mismatch mutated manifest: before=%#v after=%#v", before, after)
	}
}

func seedL3FinalizationExecution(t *testing.T, initialState string) (sandboxexecution.Store, string, *sandboxworker.Job) {
	t.Helper()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
	executionID := "run-finalize"
	startedAt := time.Date(2026, 7, 25, 4, 0, 0, 0, time.UTC)
	manifest := l3Manifest(executionID, "alpha", startedAt, "job-finalize", initialState, 0)
	manifest.Status = sandboxexecution.StatusRunning
	manifest.FinishedAt = nil
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	jobStarted := startedAt.Add(time.Second)
	jobFinished := startedAt.Add(2 * time.Second)
	exitCode := 0
	terminal := &sandboxworker.Job{
		ContractVersion: sandboxworker.JobContractVersion,
		ID:              "job-finalize",
		WorkerID:        "worker-l3",
		HostID:          "worker-l3",
		RuntimeDriver:   "rootless_podman",
		RuntimeID:       "runtime-l3",
		State:           sandboxworker.JobStateSucceeded,
		SubmittedAt:     startedAt,
		StartedAt:       &jobStarted,
		HeartbeatAt:     &jobStarted,
		FinishedAt:      &jobFinished,
		ExitCode:        &exitCode,
	}
	return store, executionID, terminal
}

func cloneL3WorkerJob(job *sandboxworker.Job) *sandboxworker.Job {
	if job == nil {
		return nil
	}
	cloned := *job
	cloned.StartedAt = cloneL3Time(job.StartedAt)
	cloned.HeartbeatAt = cloneL3Time(job.HeartbeatAt)
	cloned.FinishedAt = cloneL3Time(job.FinishedAt)
	if job.ExitCode != nil {
		exitCode := *job.ExitCode
		cloned.ExitCode = &exitCode
	}
	return &cloned
}
