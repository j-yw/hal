package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestL3DetachedSuccessfulAutoRecoveryUsesStoredBoundedSummaryArchive(t *testing.T) {
	const archivePath = ".hal/archive/2026-07-25-detached-auto"
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
	startedAt := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	manifest := l3Manifest(
		"run-auto-detached",
		"alpha",
		startedAt,
		"job-auto-detached",
		sandboxworker.JobStateSucceeded,
		1,
	)
	manifest.Purpose = sandboxexecution.PurposeAuto
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("save detached auto manifest: %v", err)
	}
	summary := `{"contractVersion":2,"ok":true,"steps":{"archive":{"status":"completed","path":"` + archivePath + `"}}}` + "\n"
	if _, err := sandboxexecution.SaveCommandOutputSummaryArtifacts(
		sandboxexecution.CommandOutputSummaryArtifactsRequest{
			ExecutionID:   manifest.ID,
			Store:         store,
			StdoutSummary: summary,
		},
	); err != nil {
		t.Fatalf("persist drained stdout summary: %v", err)
	}

	var copied []string
	driver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			copied = append(copied, req.SourcePath)
			if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(req.DestinationPath, []byte("detached auto payload\n"), 0o600)
		},
	}
	err := collectSandboxL3RecoveryTerminalArtifactsWithRuntime(
		context.Background(),
		store,
		manifest,
		l3RecoveryTerminalJobFromManifest(manifest),
		driver,
		sandboxruntime.Target{},
	)
	if err != nil {
		t.Fatalf("collect detached successful auto artifacts: %v", err)
	}

	for _, name := range []string{"prd.json", "progress.txt", "auto-state.json"} {
		want := manifest.WorkDir + "/" + archivePath + "/" + name
		if !containsL3RecoveryPath(copied, want) {
			t.Errorf("detached auto core copy paths = %q, want %q", copied, want)
		}
		live := manifest.WorkDir + "/.hal/" + name
		if containsL3RecoveryPath(copied, live) {
			t.Errorf("detached successful auto recovery silently fell back to live state %q", live)
		}
	}
}

func TestL3SuccessfulAutoRecoveryRequiresUsableStoredArchiveSummary(t *testing.T) {
	tests := []struct {
		name    string
		summary string
		code    string
	}{
		{
			name: "missing",
			code: "auto_archive_path_unavailable",
		},
		{
			name:    "bounded read rejects oversized payload",
			summary: strings.Repeat("x", int(sandboxworker.DefaultJobLogReadBytes)+1),
			code:    "auto_archive_summary_too_large",
		},
		{
			name:    "truncated or pathless",
			summary: `{"contractVersion":2,"ok":true,"steps":{"archive":`,
			code:    "auto_archive_path_unavailable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "executions"))
			manifest := l3Manifest(
				"run-auto-boundary",
				"alpha",
				time.Date(2026, 7, 25, 8, 30, 0, 0, time.UTC),
				"job-auto-boundary",
				sandboxworker.JobStateSucceeded,
				0,
			)
			manifest.Purpose = sandboxexecution.PurposeAuto
			if err := store.SaveManifest(manifest); err != nil {
				t.Fatalf("save successful auto manifest: %v", err)
			}
			if tt.summary != "" {
				if _, err := sandboxexecution.SaveCommandOutputSummaryArtifacts(
					sandboxexecution.CommandOutputSummaryArtifactsRequest{
						ExecutionID:   manifest.ID,
						Store:         store,
						StdoutSummary: tt.summary,
					},
				); err != nil {
					t.Fatalf("persist test stdout summary: %v", err)
				}
			}
			var runtimeCalls atomic.Int32
			driver := fakeRunSandboxRuntimeDriver{
				id: sandboxruntime.DriverRootlessPodman,
				exec: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					runtimeCalls.Add(1)
					return &sandboxruntime.ExecResult{}, nil
				},
				copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
					runtimeCalls.Add(1)
					if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
						return err
					}
					return os.WriteFile(req.DestinationPath, []byte("unexpected live payload\n"), 0o600)
				},
			}
			err := collectSandboxL3RecoveryTerminalArtifactsWithRuntime(
				context.Background(),
				store,
				manifest,
				l3RecoveryTerminalJobFromManifest(manifest),
				driver,
				sandboxruntime.Target{},
			)
			if err == nil || !strings.Contains(err.Error(), tt.code) {
				t.Fatalf("successful auto recovery error = %v, want %s", err, tt.code)
			}
			if runtimeCalls.Load() != 0 {
				t.Fatalf("successful auto recovery crossed %d runtime boundaries without a proven archive path", runtimeCalls.Load())
			}
		})
	}
}

func TestL3RecoveryJobContractsRemainFreeOfCommandAndPathFields(t *testing.T) {
	for _, value := range []any{
		sandboxworker.Job{},
		sandboxexecution.WorkerJobReference{},
	} {
		typ := reflect.TypeOf(value)
		for index := 0; index < typ.NumField(); index++ {
			field := typ.Field(index)
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			for _, forbidden := range []string{"command", "path", "workDir"} {
				if strings.EqualFold(field.Name, forbidden) || strings.EqualFold(tag, forbidden) {
					t.Errorf("%s contains forbidden recovery field %q/%q", typ.Name(), field.Name, tag)
				}
			}
		}
	}
}

func TestL3NamedLiveStatusFallsBackOnlyForClientOrTransportUnavailability(t *testing.T) {
	t.Run("client construction", func(t *testing.T) {
		harness := newL3WorkerHarness(t, &l3WorkerScript{
			jobState: sandboxworker.JobStateRunning,
			pages:    map[uint64]sandboxworker.JobLogsResponse{},
		})
		harness.seed("alpha", "run-alpha", "job-alpha")
		originalFactory := sandboxL3NewWorkerClient
		sandboxL3NewWorkerClient = func(string) (*sandboxworker.Client, error) {
			return nil, errors.New("TOKEN=client-secret /tmp/private.sock")
		}
		t.Cleanup(func() { sandboxL3NewWorkerClient = originalFactory })

		response := readL3NamedLiveStatusResponse(t, "alpha")
		assertL3CachedStatusFallback(t, response, "worker_client_unavailable")
	})

	t.Run("job status transport", func(t *testing.T) {
		harness := newL3WorkerHarness(t, &l3WorkerScript{
			jobState:          sandboxworker.JobStateRunning,
			transportFailures: map[string]int{sandboxworker.OperationJobStatus: 1},
			pages:             map[uint64]sandboxworker.JobLogsResponse{},
		})
		harness.seed("alpha", "run-alpha", "job-alpha")

		response := readL3NamedLiveStatusResponse(t, "alpha")
		assertL3CachedStatusFallback(t, response, "worker_job_status_failed")
	})

	t.Run("protocol mismatch still fails closed", func(t *testing.T) {
		harness := newL3WorkerHarness(t, &l3WorkerScript{
			jobState:         sandboxworker.JobStateRunning,
			protocolFailures: map[string]int{sandboxworker.OperationJobStatus: 1},
			pages:            map[uint64]sandboxworker.JobLogsResponse{},
		})
		harness.seed("alpha", "run-alpha", "job-alpha")

		var output strings.Builder
		err := runSandboxL3StatusJSON(context.Background(), "alpha", true, &output)
		if err == nil {
			t.Fatal("protocol failure returned cached status, want fail-closed error")
		}
		if output.Len() != 0 {
			t.Fatalf("protocol failure emitted fallback JSON: %q", output.String())
		}
	})

	t.Run("identity mismatch still fails closed", func(t *testing.T) {
		harness := newL3WorkerHarness(t, &l3WorkerScript{
			jobState: sandboxworker.JobStateRunning,
			pages:    map[uint64]sandboxworker.JobLogsResponse{},
		})
		harness.seed("alpha", "run-alpha", "job-alpha")
		store, err := sandboxexecution.DefaultStore()
		if err != nil {
			t.Fatalf("open execution store: %v", err)
		}
		manifest, err := store.LoadManifest("run-alpha")
		if err != nil {
			t.Fatalf("load execution manifest: %v", err)
		}
		manifest.WorkerJob.RuntimeID = "runtime-other"
		if err := store.SaveManifest(manifest); err != nil {
			t.Fatalf("save mismatched execution manifest: %v", err)
		}

		var output strings.Builder
		err = runSandboxL3StatusJSON(context.Background(), "alpha", true, &output)
		if err == nil || !strings.Contains(err.Error(), "worker_job_identity_mismatch") {
			t.Fatalf("identity mismatch error = %v, want fail-closed identity code", err)
		}
		if output.Len() != 0 {
			t.Fatalf("identity mismatch emitted fallback JSON: %q", output.String())
		}
	})
}

func TestL3MissingOptionalReportsDoesNotBlockMandatoryFinalization(t *testing.T) {
	store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
	var releases atomic.Int32
	driver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
			if strings.HasSuffix(req.SourcePath, "/.hal/reports.tar") {
				return fs.ErrNotExist
			}
			if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(req.DestinationPath, []byte("mandatory L3 payload\n"), 0o600)
		},
	}
	deps := sandboxL3FinalizationDeps{
		now: func() time.Time { return terminal.FinishedAt.Add(time.Second) },
		observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
			return cloneL3WorkerJob(terminal), nil
		},
		drainLogsInStore: func(
			_ context.Context,
			locked sandboxexecution.Store,
			manifest *sandboxexecution.Manifest,
			_ *sandboxworker.Job,
		) error {
			_, err := sandboxexecution.SaveCommandOutputSummaryArtifacts(
				sandboxexecution.CommandOutputSummaryArtifactsRequest{
					ExecutionID:   manifest.ID,
					Store:         locked,
					StdoutSummary: "terminal output\n",
				},
			)
			return err
		},
		collectArtifacts: func(
			ctx context.Context,
			locked sandboxexecution.Store,
			manifest *sandboxexecution.Manifest,
			_ *sandboxworker.Job,
		) error {
			return collectSandboxL3TerminalArtifactsWithRuntime(
				ctx,
				locked,
				manifest,
				driver,
				sandboxruntime.Target{},
				"",
			)
		},
		releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
			releases.Add(1)
			return nil
		},
	}

	if err := finalizeSandboxL3Execution(context.Background(), store, executionID, false, deps); err != nil {
		t.Fatalf("finalize with missing optional reports archive: %v", err)
	}
	manifest, err := store.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("load finalized manifest: %v", err)
	}
	if manifest.Finalization == nil ||
		!manifest.Finalization.Checkpoints.Artifacts.Completed ||
		!manifest.Finalization.Checkpoints.LeaseRelease.Completed ||
		!manifest.Finalization.Checkpoints.TerminalPublication.Completed ||
		manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf(
			"optional reports finalization status/checkpoints = %q/%t/%t/%t",
			manifest.Status,
			manifest.Finalization != nil && manifest.Finalization.Checkpoints.Artifacts.Completed,
			manifest.Finalization != nil && manifest.Finalization.Checkpoints.LeaseRelease.Completed,
			manifest.Finalization != nil && manifest.Finalization.Checkpoints.TerminalPublication.Completed,
		)
	}
	if releases.Load() != 1 {
		t.Fatalf("lease release calls = %d, want 1", releases.Load())
	}
	requireL3ArtifactAttemptState(t, manifest, "reports-archive", true)
	for _, required := range []string{"prd", "progress", "recovery-patch", "stdout-summary"} {
		if !l3RecoveryArtifactCollected(manifest, required) {
			t.Errorf("mandatory L3 artifact %q was not collected", required)
		}
	}
}

func TestL3ReportsCollectionErrorsAndMandatoryPartialsStillBlock(t *testing.T) {
	t.Run("reports generation error", func(t *testing.T) {
		store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
		var releases atomic.Int32
		driver := fakeRunSandboxRuntimeDriver{
			id: sandboxruntime.DriverRootlessPodman,
			exec: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				if strings.Contains(strings.Join(req.Args, "\n"), "reports.tar") {
					return nil, errors.New("reports generation failed")
				}
				return &sandboxruntime.ExecResult{}, nil
			},
		}
		err := finalizeSandboxL3Execution(context.Background(), store, executionID, false, sandboxL3FinalizationDeps{
			now: func() time.Time { return terminal.FinishedAt.Add(time.Second) },
			observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
				return cloneL3WorkerJob(terminal), nil
			},
			drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
				return nil
			},
			collectArtifacts: func(
				ctx context.Context,
				locked sandboxexecution.Store,
				manifest *sandboxexecution.Manifest,
				_ *sandboxworker.Job,
			) error {
				return collectSandboxL3TerminalArtifactsWithRuntime(
					ctx,
					locked,
					manifest,
					driver,
					sandboxruntime.Target{},
					"",
				)
			},
			releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
				releases.Add(1)
				return nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "artifact_collection_failed") {
			t.Fatalf("reports generation finalization error = %v, want blocking artifact error", err)
		}
		if releases.Load() != 0 {
			t.Fatalf("reports generation error released lease %d times", releases.Load())
		}
	})

	t.Run("reports transport copy error", func(t *testing.T) {
		store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
		var releases atomic.Int32
		driver := fakeRunSandboxRuntimeDriver{
			id: sandboxruntime.DriverRootlessPodman,
			copyOut: func(_ context.Context, req sandboxruntime.CopyRequest) error {
				if strings.HasSuffix(req.SourcePath, "/.hal/reports.tar") {
					return errors.New("worker transport unavailable")
				}
				if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
					return err
				}
				return os.WriteFile(req.DestinationPath, []byte("mandatory payload\n"), 0o600)
			},
		}
		err := finalizeSandboxL3Execution(context.Background(), store, executionID, false, sandboxL3FinalizationDeps{
			now: func() time.Time { return terminal.FinishedAt.Add(time.Second) },
			observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
				return cloneL3WorkerJob(terminal), nil
			},
			drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
				return nil
			},
			collectArtifacts: func(
				ctx context.Context,
				locked sandboxexecution.Store,
				manifest *sandboxexecution.Manifest,
				_ *sandboxworker.Job,
			) error {
				return collectSandboxL3TerminalArtifactsWithRuntime(
					ctx,
					locked,
					manifest,
					driver,
					sandboxruntime.Target{},
					"",
				)
			},
			releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
				releases.Add(1)
				return nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "artifact_collection_failed") {
			t.Fatalf("reports transport finalization error = %v, want blocking artifact error", err)
		}
		if releases.Load() != 0 {
			t.Fatalf("reports transport error released lease %d times", releases.Load())
		}
	})

	t.Run("mandatory core copy error", func(t *testing.T) {
		store, executionID, terminal := seedL3FinalizationExecution(t, sandboxworker.JobStateRunning)
		var releases atomic.Int32
		driver := fakeRunSandboxRuntimeDriver{
			id: sandboxruntime.DriverRootlessPodman,
			copyOut: func(context.Context, sandboxruntime.CopyRequest) error {
				return fs.ErrNotExist
			},
		}
		err := finalizeSandboxL3Execution(context.Background(), store, executionID, false, sandboxL3FinalizationDeps{
			now: func() time.Time { return terminal.FinishedAt.Add(time.Second) },
			observeJob: func(context.Context, *sandboxexecution.Manifest) (*sandboxworker.Job, error) {
				return cloneL3WorkerJob(terminal), nil
			},
			drainLogs: func(context.Context, *sandboxexecution.Manifest, *sandboxworker.Job) error {
				return nil
			},
			collectArtifacts: func(
				ctx context.Context,
				locked sandboxexecution.Store,
				manifest *sandboxexecution.Manifest,
				_ *sandboxworker.Job,
			) error {
				return collectSandboxL3TerminalArtifactsWithRuntime(
					ctx,
					locked,
					manifest,
					driver,
					sandboxruntime.Target{},
					"",
				)
			},
			releaseLease: func(context.Context, *sandboxexecution.Manifest) error {
				releases.Add(1)
				return nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "artifact_collection_failed") {
			t.Fatalf("mandatory core finalization error = %v, want blocking artifact error", err)
		}
		if releases.Load() != 0 {
			t.Fatalf("mandatory core error released lease %d times", releases.Load())
		}
	})
}

func readL3NamedLiveStatusResponse(t *testing.T, sandboxName string) sandboxL3StatusResponse {
	t.Helper()
	var output strings.Builder
	if err := runSandboxL3StatusJSON(context.Background(), sandboxName, true, &output); err != nil {
		t.Fatalf("read named live status: %v", err)
	}
	var response sandboxL3StatusResponse
	if err := json.Unmarshal([]byte(output.String()), &response); err != nil {
		t.Fatalf("decode named live status: %v", err)
	}
	return response
}

func assertL3CachedStatusFallback(t *testing.T, response sandboxL3StatusResponse, code string) {
	t.Helper()
	if response.Source != "cached" ||
		response.Execution == nil ||
		response.Execution.RunID != "run-alpha" ||
		response.Execution.Job == nil ||
		response.Execution.Job.ID != "job-alpha" {
		t.Fatalf(
			"cached fallback source/run/job = %q/%q/%q",
			response.Source,
			l3RecoveryExecutionID(response.Execution),
			l3RecoveryJobID(response.Execution),
		)
	}
	if len(response.Diagnostics) != 1 ||
		response.Diagnostics[0].Code != code ||
		strings.Contains(response.Diagnostics[0].Message, "TOKEN=") ||
		strings.Contains(response.Diagnostics[0].Message, "/tmp/") {
		t.Fatalf("cached fallback diagnostic = %q/%q, want sanitized %q", l3RecoveryDiagnosticCode(response.Diagnostics), l3RecoveryDiagnosticMessage(response.Diagnostics), code)
	}
}

func l3RecoveryExecutionID(execution *sandboxL3ExecutionStatus) string {
	if execution == nil {
		return ""
	}
	return execution.RunID
}

func l3RecoveryJobID(execution *sandboxL3ExecutionStatus) string {
	if execution == nil || execution.Job == nil {
		return ""
	}
	return execution.Job.ID
}

func l3RecoveryDiagnosticCode(diagnostics []sandboxL3Diagnostic) string {
	if len(diagnostics) == 0 {
		return ""
	}
	return diagnostics[0].Code
}

func l3RecoveryDiagnosticMessage(diagnostics []sandboxL3Diagnostic) string {
	if len(diagnostics) == 0 {
		return ""
	}
	return diagnostics[0].Message
}

func containsL3RecoveryPath(paths []string, want string) bool {
	for _, got := range paths {
		if got == want {
			return true
		}
	}
	return false
}

func l3RecoveryArtifactCollected(manifest *sandboxexecution.Manifest, artifactID string) bool {
	if manifest == nil || manifest.ArtifactMetadata == nil {
		return false
	}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		if artifact.ID == artifactID {
			return true
		}
	}
	return false
}

func l3RecoveryTerminalJobFromManifest(manifest *sandboxexecution.Manifest) *sandboxworker.Job {
	if manifest == nil || manifest.WorkerJob == nil {
		return nil
	}
	reference := manifest.WorkerJob
	return &sandboxworker.Job{
		ContractVersion: reference.ContractVersion,
		ID:              reference.JobID,
		SubmissionKey:   reference.SubmissionKey,
		WorkerID:        reference.WorkerID,
		HostID:          reference.HostID,
		RuntimeDriver:   reference.RuntimeDriver,
		RuntimeID:       reference.RuntimeID,
		State:           reference.State,
		SubmittedAt:     reference.SubmittedAt,
		StartedAt:       reference.StartedAt,
		HeartbeatAt:     reference.HeartbeatAt,
		FinishedAt:      reference.FinishedAt,
		LogCursor:       reference.LogCursor,
	}
}
