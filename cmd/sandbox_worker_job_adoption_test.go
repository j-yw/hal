package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestSandboxWorkerJobRunnerClosesLostAcknowledgementAndDrainsTerminalLogs(t *testing.T) {
	executionID := "exec-stable-1"
	submissionID := sandboxWorkerJobSubmissionID(executionID)
	if submissionID != executionID {
		t.Fatalf("submission identity = %q, want exact execution ID %q", submissionID, executionID)
	}
	for _, forbidden := range []string{"raw-secret", "/private/work", "worker.sock"} {
		if strings.Contains(submissionID, forbidden) {
			t.Fatalf("submission identity exposed %q: %s", forbidden, submissionID)
		}
	}

	now := time.Date(2026, 7, 25, 4, 0, 0, 0, time.UTC)
	startedAt := now.Add(time.Second)
	finishedAt := startedAt.Add(time.Second)
	exitCode := 0
	driver := &fakeSandboxWorkerJobDriver{
		startErr: context.DeadlineExceeded,
		resolveJob: sandboxworker.Job{
			ContractVersion: sandboxworker.JobContractVersion,
			ID:              "job-1",
			SubmissionKey:   sandboxWorkerJobSubmissionKey(submissionID),
			WorkerID:        "worker-1",
			HostID:          "host-1",
			RuntimeDriver:   sandboxruntime.DriverRootlessPodman,
			RuntimeID:       "runtime-1",
			State:           sandboxworker.JobStateQueued,
			SubmittedAt:     now,
		},
		statusJobs: []sandboxworker.Job{
			{
				ContractVersion: sandboxworker.JobContractVersion,
				ID:              "job-1",
				SubmissionKey:   sandboxWorkerJobSubmissionKey(submissionID),
				WorkerID:        "worker-1",
				HostID:          "host-1",
				RuntimeDriver:   sandboxruntime.DriverRootlessPodman,
				RuntimeID:       "runtime-1",
				State:           sandboxworker.JobStateRunning,
				SubmittedAt:     now,
				StartedAt:       &startedAt,
				HeartbeatAt:     &startedAt,
				LogCursor:       1,
			},
			{
				ContractVersion: sandboxworker.JobContractVersion,
				ID:              "job-1",
				SubmissionKey:   sandboxWorkerJobSubmissionKey(submissionID),
				WorkerID:        "worker-1",
				HostID:          "host-1",
				RuntimeDriver:   sandboxruntime.DriverRootlessPodman,
				RuntimeID:       "runtime-1",
				State:           sandboxworker.JobStateSucceeded,
				SubmittedAt:     now,
				StartedAt:       &startedAt,
				HeartbeatAt:     &startedAt,
				FinishedAt:      &finishedAt,
				LogCursor:       3,
				ExitCode:        &exitCode,
			},
		},
		logPages: []sandboxworker.JobLogsResponse{
			{
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           "job-1",
				Records: []sandboxworker.JobLogRecord{{
					Cursor:    1,
					Stream:    sandboxworker.JobLogStreamStdout,
					Data:      "first TOKEN=raw-secret\n",
					Timestamp: startedAt,
				}},
				NextCursor: 1,
			},
			{
				ContractVersion: sandboxworker.JobContractVersion,
				JobID:           "job-1",
				Records: []sandboxworker.JobLogRecord{
					{Cursor: 2, Stream: sandboxworker.JobLogStreamStderr, Data: "warning /private/work/file\n", Timestamp: finishedAt},
					{Cursor: 3, Stream: sandboxworker.JobLogStreamStdout, Data: "done\n", Timestamp: finishedAt},
				},
				NextCursor: 3,
			},
		},
	}

	var stdout, stderr bytes.Buffer
	var persisted []*sandboxexecution.WorkerJobReference
	driver.persistCount = func() int { return len(persisted) }
	err := runSandboxWorkerJob(context.Background(), sandboxWorkerJobRunRequest{
		ExecutionID: executionID,
		Driver:      driver,
		HostID:      "host-1",
		Target:      sandboxWorkerJobRuntimeTarget(),
		Command: sandboxexec.CommandRequest{
			Command: []string{"hal", "run"},
			WorkDir: "/private/work",
			Env:     map[string]string{"TOKEN": "raw-secret"},
			Stdout:  &stdout,
			Stderr:  &stderr,
		},
		Persist: func(reference *sandboxexecution.WorkerJobReference) error {
			persisted = append(persisted, sandboxexecution.SanitizeWorkerJobReference(reference))
			return nil
		},
		Wait: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatalf("runSandboxWorkerJob() error: %v", err)
	}
	if driver.startCalls != 1 || driver.resolveCalls != 1 {
		t.Fatalf("start/resolve calls = %d/%d, want lost-ack recovery 1/1", driver.startCalls, driver.resolveCalls)
	}
	if driver.startSubmissionID != submissionID || driver.resolveSubmissionID != submissionID {
		t.Fatalf("submission identities = %q/%q, want deterministic %q", driver.startSubmissionID, driver.resolveSubmissionID, submissionID)
	}
	if driver.cancelCalls != 0 || driver.execCalls != 0 {
		t.Fatalf("cancel/synchronous exec calls = %d/%d, want zero", driver.cancelCalls, driver.execCalls)
	}
	if len(persisted) < 3 {
		t.Fatalf("persisted worker job snapshots = %d, want acceptance and poll progress", len(persisted))
	}
	if driver.firstPollPersistCount == 0 {
		t.Fatal("first status/log poll happened before durable acceptance hook")
	}
	first := persisted[0]
	if first == nil || first.JobID != "job-1" || first.SubmissionKey != sandboxWorkerJobSubmissionKey(submissionID) || first.LogCursor != 0 {
		t.Fatalf("first persisted reference = %#v, want safe accepted identity", first)
	}
	encodedReference, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("json.Marshal(worker job reference) error: %v", err)
	}
	for _, forbidden := range []string{submissionID, "raw-secret", "/private/work", "hal run"} {
		if strings.Contains(string(encodedReference), forbidden) {
			t.Fatalf("durable worker job reference exposed %q: %s", forbidden, encodedReference)
		}
	}
	last := persisted[len(persisted)-1]
	if last.State != sandboxworker.JobStateSucceeded || last.LogCursor != 3 {
		t.Fatalf("last persisted reference = %#v, want succeeded terminal cursor 3", last)
	}
	var running *sandboxexecution.WorkerJobReference
	for _, reference := range persisted {
		if reference != nil && reference.State == sandboxworker.JobStateRunning {
			running = reference
			break
		}
	}
	if running == nil || running.LogCursor != 1 {
		t.Fatalf("running producer snapshot = %#v, want producer cursor 1 before reader drain", running)
	}
	if !reflect.DeepEqual(driver.logCursors, []uint64{0, 1}) {
		t.Fatalf("log cursors = %#v, want bounded monotonic drain", driver.logCursors)
	}
	if strings.Contains(stdout.String(), "raw-secret") || strings.Contains(stderr.String(), "/private/work") {
		t.Fatalf("streamed logs were not redacted: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "[redacted]") || !strings.Contains(stdout.String(), "done") || !strings.Contains(stderr.String(), "[redacted]") {
		t.Fatalf("streamed logs missing records: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestSandboxWorkerJobRunnerRejectsSubmissionConflictWithoutResolution(t *testing.T) {
	driver := &fakeSandboxWorkerJobDriver{
		startErr: &sandboxworker.ProtocolError{
			Operation: sandboxworker.OperationJobStart,
			Code:      sandboxworker.ErrorCodeSubmissionConflict,
			Message:   "accepted request differs",
		},
		resolveJob: queuedSandboxWorkerJob("submission-conflict"),
	}
	persistCalls := 0
	err := runSandboxWorkerJob(context.Background(), sandboxWorkerJobRunRequest{
		ExecutionID: "submission-conflict",
		Driver:      driver,
		HostID:      "host-1",
		Target:      sandboxWorkerJobRuntimeTarget(),
		Command:     sandboxexec.CommandRequest{Command: []string{"different-command"}},
		Persist: func(*sandboxexecution.WorkerJobReference) error {
			persistCalls++
			return nil
		},
	})
	if err == nil {
		t.Fatal("submission conflict error = nil")
	}
	if driver.resolveCalls != 0 || driver.statusCalls != 0 || persistCalls != 0 {
		t.Fatalf("conflict resolve/status/persist calls = %d/%d/%d, want zero", driver.resolveCalls, driver.statusCalls, persistCalls)
	}
	var detached *sandboxWorkerJobDetachedError
	if errors.As(err, &detached) {
		t.Fatalf("authoritative submission conflict was mislabeled detached: %v", err)
	}
}

func TestSandboxWorkerJobRunnerWarnsOnceForProvenRetentionGap(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 4, 4, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	exitCode := 0
	terminal := queuedSandboxWorkerJob("retention-gap")
	terminal.State = sandboxworker.JobStateSucceeded
	terminal.StartedAt = &startedAt
	terminal.HeartbeatAt = &startedAt
	terminal.FinishedAt = &finishedAt
	terminal.LogCursor = 4
	terminal.ExitCode = &exitCode
	driver := &fakeSandboxWorkerJobDriver{
		startJob:   queuedSandboxWorkerJob("retention-gap"),
		statusJobs: []sandboxworker.Job{terminal},
		logPages: []sandboxworker.JobLogsResponse{{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           terminal.ID,
			Records: []sandboxworker.JobLogRecord{{
				Cursor:    4,
				Stream:    sandboxworker.JobLogStreamStdout,
				Data:      "available\n",
				Timestamp: finishedAt,
			}},
			NextCursor:   4,
			OldestCursor: 4,
			Truncated:    true,
		}},
	}
	var stderr bytes.Buffer
	err := runSandboxWorkerJob(context.Background(), sandboxWorkerJobRunRequest{
		ExecutionID: "retention-gap",
		Driver:      driver,
		HostID:      "host-1",
		Target:      sandboxWorkerJobRuntimeTarget(),
		Command:     sandboxexec.CommandRequest{Command: []string{"true"}, Stderr: &stderr},
		Persist:     func(*sandboxexecution.WorkerJobReference) error { return nil },
		Wait:        func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatalf("runSandboxWorkerJob() error: %v", err)
	}
	if got := strings.Count(stderr.String(), "warning: sandbox worker job log retention gap"); got != 1 {
		t.Fatalf("retention warnings = %d, want one; stderr=%q", got, stderr.String())
	}
}

func TestSandboxWorkerJobRunnerRejectsEverySelectedIdentityMismatch(t *testing.T) {
	fields := []struct {
		name   string
		mutate func(*sandboxworker.Job)
	}{
		{name: "job", mutate: func(job *sandboxworker.Job) { job.ID = "job-other" }},
		{name: "host", mutate: func(job *sandboxworker.Job) { job.HostID = "host-other" }},
		{name: "worker", mutate: func(job *sandboxworker.Job) { job.WorkerID = "worker-other" }},
		{name: "driver", mutate: func(job *sandboxworker.Job) { job.RuntimeDriver = sandboxruntime.DriverSSHMachine }},
		{name: "runtime", mutate: func(job *sandboxworker.Job) { job.RuntimeID = "runtime-other" }},
	}
	for _, field := range fields {
		for _, phase := range []string{"acceptance", "status"} {
			if phase == "acceptance" && field.name == "job" {
				continue
			}
			t.Run(phase+"/"+field.name, func(t *testing.T) {
				startJob := queuedSandboxWorkerJob("identity")
				statusJob := queuedSandboxWorkerJob("identity")
				if phase == "acceptance" {
					field.mutate(&startJob)
				} else {
					field.mutate(&statusJob)
				}
				driver := &fakeSandboxWorkerJobDriver{
					startJob:   startJob,
					statusJobs: []sandboxworker.Job{statusJob},
				}
				err := runSandboxWorkerJob(context.Background(), sandboxWorkerJobRunRequest{
					ExecutionID: "identity",
					Driver:      driver,
					HostID:      "host-1",
					Target:      sandboxWorkerJobRuntimeTarget(),
					Command:     sandboxexec.CommandRequest{Command: []string{"true"}},
					Persist:     func(*sandboxexecution.WorkerJobReference) error { return nil },
					Wait:        func(context.Context) error { return nil },
				})
				if err == nil {
					t.Fatalf("%s identity mismatch %s error = nil", phase, field.name)
				}
				for _, unsafe := range []string{"host-other", "worker-other", "runtime-other"} {
					if strings.Contains(err.Error(), unsafe) {
						t.Fatalf("identity mismatch error exposed %q: %v", unsafe, err)
					}
				}
			})
		}
	}
}

func TestSandboxWorkerJobRunnerReturnsRecoverableDetachedErrorAfterAcceptance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	driver := &fakeSandboxWorkerJobDriver{
		startJob:         queuedSandboxWorkerJob("detached"),
		cancelAfterStart: cancel,
	}
	persistCalls := 0
	err := runSandboxWorkerJob(ctx, sandboxWorkerJobRunRequest{
		ExecutionID: "detached",
		Driver:      driver,
		HostID:      "host-1",
		Target:      sandboxWorkerJobRuntimeTarget(),
		Command:     sandboxexec.CommandRequest{Command: []string{"true"}},
		Persist: func(*sandboxexecution.WorkerJobReference) error {
			persistCalls++
			return nil
		},
	})
	var detached *sandboxWorkerJobDetachedError
	if !errors.As(err, &detached) || !detached.Recoverable() || !detached.Detached() {
		t.Fatalf("runSandboxWorkerJob() error = %#v, want typed recoverable detached error", err)
	}
	if persistCalls != 1 {
		t.Fatalf("persist calls = %d, want accepted reference before detach", persistCalls)
	}
	if driver.statusCalls != 0 || driver.logsCalls != 0 || driver.cancelCalls != 0 || driver.execCalls != 0 {
		t.Fatalf("post-detach calls status/logs/cancel/exec = %d/%d/%d/%d, want zero", driver.statusCalls, driver.logsCalls, driver.cancelCalls, driver.execCalls)
	}
}

func TestSandboxWorkerJobRunnerRejectsMismatchedLogIdentity(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 4, 3, 0, 0, time.UTC)
	status := queuedSandboxWorkerJob("log-identity")
	status.State = sandboxworker.JobStateRunning
	status.StartedAt = &startedAt
	status.HeartbeatAt = &startedAt
	status.LogCursor = 1
	driver := &fakeSandboxWorkerJobDriver{
		startJob:   queuedSandboxWorkerJob("log-identity"),
		statusJobs: []sandboxworker.Job{status},
		logPages: []sandboxworker.JobLogsResponse{{
			ContractVersion: sandboxworker.JobContractVersion,
			JobID:           "job-other",
			Records: []sandboxworker.JobLogRecord{{
				Cursor:    1,
				Stream:    sandboxworker.JobLogStreamStdout,
				Data:      "unsafe",
				Timestamp: startedAt,
			}},
			NextCursor: 1,
		}},
	}
	var stdout bytes.Buffer
	err := runSandboxWorkerJob(context.Background(), sandboxWorkerJobRunRequest{
		ExecutionID: "log-identity",
		Driver:      driver,
		HostID:      "host-1",
		Target:      sandboxWorkerJobRuntimeTarget(),
		Command:     sandboxexec.CommandRequest{Command: []string{"true"}, Stdout: &stdout},
		Persist:     func(*sandboxexecution.WorkerJobReference) error { return nil },
		Wait:        func(context.Context) error { return nil },
	})
	var detached *sandboxWorkerJobDetachedError
	if !errors.As(err, &detached) {
		t.Fatalf("log identity error = %#v, want recoverable detached error", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("mismatched logs reached stdout: %q", stdout.String())
	}
}

func TestSandboxWorkerJobRunnerReturnsTerminalExitFailure(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 4, 5, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	exitCode := 23
	job := queuedSandboxWorkerJob("terminal-failure")
	job.State = sandboxworker.JobStateFailed
	job.StartedAt = &startedAt
	job.HeartbeatAt = &startedAt
	job.FinishedAt = &finishedAt
	job.ExitCode = &exitCode
	driver := &fakeSandboxWorkerJobDriver{
		startJob:   queuedSandboxWorkerJob("terminal-failure"),
		statusJobs: []sandboxworker.Job{job},
	}
	err := runSandboxWorkerJob(context.Background(), sandboxWorkerJobRunRequest{
		ExecutionID: "terminal-failure",
		Driver:      driver,
		HostID:      "host-1",
		Target:      sandboxWorkerJobRuntimeTarget(),
		Command:     sandboxexec.CommandRequest{Command: []string{"false"}},
		Persist:     func(*sandboxexecution.WorkerJobReference) error { return nil },
		Wait:        func(context.Context) error { return nil },
	})
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != exitCode {
		t.Fatalf("terminal failure error = %#v, want exit code %d", err, exitCode)
	}
}

func TestRunAndAutoSandboxManifestSavesPreserveWorkerJobAndFinalization(t *testing.T) {
	now := time.Date(2026, 7, 25, 5, 0, 0, 0, time.UTC)
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		t.Run(string(purpose), func(t *testing.T) {
			store := newPrivateSandboxExecutionTestStore(t)
			executionID := "preserve-" + string(purpose)
			workerJob := sandboxWorkerJobReference(queuedSandboxWorkerJob("submission-preserve"), 2)
			finalization := &sandboxexecution.FinalizationMetadata{
				ContractVersion:  sandboxexecution.FinalizationContractVersion,
				State:            sandboxexecution.FinalizationStatePending,
				SyncOutRequested: true,
				UpdatedAt:        now,
			}
			if err := store.SaveManifest(&sandboxexecution.Manifest{
				ID:           executionID,
				Purpose:      purpose,
				Status:       sandboxexecution.StatusRunning,
				StartedAt:    now,
				WorkerJob:    workerJob,
				Finalization: finalization,
			}); err != nil {
				t.Fatalf("SaveManifest(seed) error: %v", err)
			}
			switch purpose {
			case sandboxexecution.PurposeRun:
				if err := saveRunSandboxManifest(store, runSandboxRequest{ExecutionID: executionID}, sandboxexecution.StatusRunning, now, nil, nil); err != nil {
					t.Fatalf("saveRunSandboxManifest() error: %v", err)
				}
			case sandboxexecution.PurposeAuto:
				if err := saveAutoSandboxManifest(store, autoSandboxRequest{ExecutionID: executionID}, sandboxexecution.StatusRunning, now, nil, nil); err != nil {
					t.Fatalf("saveAutoSandboxManifest() error: %v", err)
				}
			}
			loaded, err := store.LoadManifest(executionID)
			if err != nil {
				t.Fatalf("LoadManifest() error: %v", err)
			}
			if !reflect.DeepEqual(loaded.WorkerJob, workerJob) || !reflect.DeepEqual(loaded.Finalization, finalization) {
				t.Fatalf("saved L3 state = workerJob %#v finalization %#v, want preserved", loaded.WorkerJob, loaded.Finalization)
			}
		})
	}
}

func TestSandboxWorkerJobUpdateCannotRegressCompletedFinalization(t *testing.T) {
	store := newPrivateSandboxExecutionTestStore(t)
	executionID := "concurrent-completed"
	startedAt := time.Date(2026, 7, 25, 5, 10, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	finalizedAt := finishedAt.Add(time.Second)
	exitCode := 0
	terminal := queuedSandboxWorkerJob(executionID)
	terminal.State = sandboxworker.JobStateSucceeded
	terminal.StartedAt = &startedAt
	terminal.HeartbeatAt = &startedAt
	terminal.FinishedAt = &finishedAt
	terminal.ExitCode = &exitCode
	terminal.LogCursor = 9
	terminalReference := sandboxWorkerJobReference(terminal, terminal.LogCursor)
	checkpoint := sandboxexecution.FinalizationCheckpoint{Completed: true, CompletedAt: &finalizedAt}
	completed := &sandboxexecution.FinalizationMetadata{
		ContractVersion:  sandboxexecution.FinalizationContractVersion,
		State:            sandboxexecution.FinalizationStateCompleted,
		TerminalJobState: sandboxworker.JobStateSucceeded,
		Checkpoints: sandboxexecution.FinalizationCheckpoints{
			Artifacts:           checkpoint,
			LeaseRelease:        checkpoint,
			TerminalPublication: checkpoint,
		},
		StartedAt:   &finishedAt,
		UpdatedAt:   finalizedAt,
		CompletedAt: &finalizedAt,
	}
	if err := store.SaveManifest(&sandboxexecution.Manifest{
		ID:           executionID,
		Purpose:      sandboxexecution.PurposeRun,
		Status:       sandboxexecution.StatusSucceeded,
		StartedAt:    startedAt,
		FinishedAt:   &finishedAt,
		WorkerJob:    terminalReference,
		Finalization: completed,
	}); err != nil {
		t.Fatalf("SaveManifest(seed) error: %v", err)
	}

	stale := queuedSandboxWorkerJob(executionID)
	stale.State = sandboxworker.JobStateRunning
	stale.StartedAt = &startedAt
	stale.HeartbeatAt = &startedAt
	stale.LogCursor = 3
	if err := persistSandboxWorkerJobUpdate(
		store,
		executionID,
		sandboxWorkerJobReference(stale, stale.LogCursor),
		false,
		finalizedAt.Add(time.Second),
	); err != nil {
		t.Fatalf("persistSandboxWorkerJobUpdate(stale) error: %v", err)
	}

	loaded, err := store.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if loaded.Status != sandboxexecution.StatusSucceeded ||
		!reflect.DeepEqual(loaded.WorkerJob, terminalReference) ||
		!reflect.DeepEqual(loaded.Finalization, completed) {
		t.Fatalf("stale update regressed completed manifest: %#v", loaded)
	}
}

func TestRunAndAutoSandboxDetachedJobsStayRunningWithoutFinalizationSideEffects(t *testing.T) {
	now := time.Date(2026, 7, 25, 5, 30, 0, 0, time.UTC)
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		t.Run(string(purpose), func(t *testing.T) {
			projectDir := t.TempDir()
			store := newPrivateSandboxExecutionTestStore(t)
			executionID := "detached-" + string(purpose)
			target := workerRootlessCachedSandbox("worker-rootless")
			target.Host.ID = "host-1"
			target.Runtime.RuntimeID = "runtime-1"
			target.Lease = &sandbox.SandboxLeaseRef{ID: "lease-1"}
			driver := &fakeSandboxWorkerJobDriver{}
			workerJob := sandboxWorkerJobReference(queuedSandboxWorkerJob(executionID), 0)
			detached := &sandboxWorkerJobDetachedError{Cause: context.Canceled}
			releaseCalls := 0
			applyCalls := 0

			switch purpose {
			case sandboxexecution.PurposeRun:
				err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
					Base:                  "main",
					BaseChanged:           true,
					SandboxSyncOut:        true,
					SandboxSyncOutChanged: true,
				}, io.Discard, io.Discard, runSandboxDeps{
					defaultStore:   func() (sandboxexecution.Store, error) { return store, nil },
					newExecutionID: func(time.Time) string { return executionID },
					now:            func() time.Time { return now },
					workingDir:     func() (string, error) { return projectDir, nil },
					planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
						return sandboxworkspace.Plan{
							Mode:       sandbox.SandboxWorkspaceModeClone,
							ProjectDir: projectDir,
							Repository: "git@example.com:org/repo.git",
							Branch:     "feature/detached",
						}, nil
					},
					execute: func(_ context.Context, _ runSandboxRequest, _, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
						if err := hooks.OnTargetReady(target); err != nil {
							return runSandboxExecutionResult{}, err
						}
						if err := hooks.OnWorkerJobUpdate(workerJob); err != nil {
							return runSandboxExecutionResult{}, err
						}
						return runSandboxExecutionResult{
							Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
							RuntimeDriver: driver,
						}, detached
					},
					applySyncOut: func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
						applyCalls++
						return sandboxworkspace.SafeApplyResult{}, nil
					},
					releaseLease: func(string) (*sandbox.SandboxLease, error) {
						releaseCalls++
						return nil, nil
					},
				})
				assertDetachedSandboxTopLevelResult(t, err, store, executionID, driver, releaseCalls, applyCalls)
			case sandboxexecution.PurposeAuto:
				err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
					Base:                  "main",
					BaseChanged:           true,
					SandboxSyncOut:        true,
					SandboxSyncOutChanged: true,
				}, io.Discard, io.Discard, autoSandboxDeps{
					defaultStore:   func() (sandboxexecution.Store, error) { return store, nil },
					newExecutionID: func(time.Time) string { return executionID },
					now:            func() time.Time { return now },
					planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
						return sandboxworkspace.Plan{
							Mode:       sandbox.SandboxWorkspaceModeClone,
							ProjectDir: projectDir,
							Repository: "git@example.com:org/repo.git",
							Branch:     "feature/detached",
						}, nil
					},
					execute: func(_ context.Context, _ autoSandboxRequest, _, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
						if err := hooks.OnTargetReady(target); err != nil {
							return autoSandboxExecutionResult{}, err
						}
						if err := hooks.OnWorkerJobUpdate(workerJob); err != nil {
							return autoSandboxExecutionResult{}, err
						}
						return autoSandboxExecutionResult{
							Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
							RuntimeDriver: driver,
						}, detached
					},
					applySyncOut: func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
						applyCalls++
						return sandboxworkspace.SafeApplyResult{}, nil
					},
					releaseLease: func(string) (*sandbox.SandboxLease, error) {
						releaseCalls++
						return nil, nil
					},
				})
				assertDetachedSandboxTopLevelResult(t, err, store, executionID, driver, releaseCalls, applyCalls)
			}
		})
	}
}

func TestRunAndAutoTerminalWorkerJobsUseSharedFinalizationWithoutImplicitApply(t *testing.T) {
	now := time.Date(2026, 7, 25, 5, 45, 0, 0, time.UTC)
	states := []string{
		sandboxworker.JobStateSucceeded,
		sandboxworker.JobStateFailed,
		sandboxworker.JobStateCanceled,
		sandboxworker.JobStateInterrupted,
		sandboxworker.JobStateUnknown,
	}
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		for _, state := range states {
			t.Run(string(purpose)+"/"+state, func(t *testing.T) {
				projectDir := t.TempDir()
				store := newPrivateSandboxExecutionTestStore(t)
				executionID := "terminal-" + string(purpose) + "-" + state
				target := workerRootlessCachedSandbox("worker-rootless")
				target.Host.ID = "host-1"
				target.Runtime.RuntimeID = "runtime-1"
				target.Runtime.WorkerID = "worker-1"
				target.Lease = &sandbox.SandboxLeaseRef{
					ID:      "lease-" + string(purpose) + "-" + state,
					RunID:   executionID,
					Purpose: string(purpose),
				}
				terminal := queuedSandboxWorkerJob(executionID)
				terminal.State = state
				startedAt := now.Add(time.Second)
				finishedAt := now.Add(2 * time.Second)
				terminal.StartedAt = &startedAt
				terminal.HeartbeatAt = &startedAt
				terminal.FinishedAt = &finishedAt
				exitCode := 0
				if state == sandboxworker.JobStateFailed {
					exitCode = ExitCodeExpectedNonZero
				}
				if state == sandboxworker.JobStateSucceeded || state == sandboxworker.JobStateFailed {
					terminal.ExitCode = &exitCode
				}
				driver := &fakeSandboxWorkerJobDriver{
					statusJobs: []sandboxworker.Job{terminal},
					logPages: []sandboxworker.JobLogsResponse{{
						ContractVersion: sandboxworker.JobContractVersion,
						JobID:           terminal.ID,
					}},
					exec: func(sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
						return &sandboxruntime.ExecResult{}, nil
					},
					copyOut: func(req sandboxruntime.CopyRequest) error {
						return os.WriteFile(req.DestinationPath, []byte("fake terminal artifact"), 0o600)
					},
				}
				workerJob := sandboxWorkerJobReference(terminal, terminal.LogCursor)
				execErr := sandboxWorkerJobTerminalResult(terminal)
				releaseCalls := 0
				applyCalls := 0

				switch purpose {
				case sandboxexecution.PurposeRun:
					err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
						Base:                  "main",
						BaseChanged:           true,
						SandboxSyncOut:        true,
						SandboxSyncOutChanged: true,
						SandboxApply:          true,
						SandboxApplyChanged:   true,
					}, io.Discard, io.Discard, runSandboxDeps{
						defaultStore:   func() (sandboxexecution.Store, error) { return store, nil },
						newExecutionID: func(time.Time) string { return executionID },
						now:            func() time.Time { return now },
						workingDir:     func() (string, error) { return projectDir, nil },
						planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
							return terminalWorkerJobWorkspacePlan(projectDir), nil
						},
						execute: func(_ context.Context, _ runSandboxRequest, _, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
							if err := hooks.OnTargetReady(target); err != nil {
								return runSandboxExecutionResult{}, err
							}
							if err := hooks.OnWorkerJobUpdate(workerJob); err != nil {
								return runSandboxExecutionResult{}, err
							}
							return runSandboxExecutionResult{
								Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
								RuntimeDriver: driver,
							}, execErr
						},
						applySyncOut: func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
							applyCalls++
							return sandboxworkspace.SafeApplyResult{}, nil
						},
						releaseLease: func(string) (*sandbox.SandboxLease, error) {
							releaseCalls++
							return &sandbox.SandboxLease{Status: sandbox.SandboxLeaseStatusReleased}, nil
						},
					})
					assertTerminalSandboxTopLevelResult(t, err, store, executionID, state, driver, releaseCalls, applyCalls)
				case sandboxexecution.PurposeAuto:
					err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
						Base:                  "main",
						BaseChanged:           true,
						SandboxSyncOut:        true,
						SandboxSyncOutChanged: true,
						SandboxApply:          true,
						SandboxApplyChanged:   true,
					}, io.Discard, io.Discard, autoSandboxDeps{
						defaultStore:   func() (sandboxexecution.Store, error) { return store, nil },
						newExecutionID: func(time.Time) string { return executionID },
						now:            func() time.Time { return now },
						planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
							return terminalWorkerJobWorkspacePlan(projectDir), nil
						},
						execute: func(_ context.Context, _ autoSandboxRequest, _, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
							if err := hooks.OnTargetReady(target); err != nil {
								return autoSandboxExecutionResult{}, err
							}
							if err := hooks.OnWorkerJobUpdate(workerJob); err != nil {
								return autoSandboxExecutionResult{}, err
							}
							return autoSandboxExecutionResult{
								Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
								RuntimeDriver: driver,
							}, execErr
						},
						applySyncOut: func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
							applyCalls++
							return sandboxworkspace.SafeApplyResult{}, nil
						},
						releaseLease: func(string) (*sandbox.SandboxLease, error) {
							releaseCalls++
							return &sandbox.SandboxLease{Status: sandbox.SandboxLeaseStatusReleased}, nil
						},
					})
					assertTerminalSandboxTopLevelResult(t, err, store, executionID, state, driver, releaseCalls, applyCalls)
				}
			})
		}
	}
}

func TestRunAndAutoFinalCommandDispatchKeepsLegacySynchronousPath(t *testing.T) {
	for _, purpose := range []string{sandbox.SandboxLeasePurposeRun, sandbox.SandboxLeasePurposeAuto} {
		t.Run(purpose, func(t *testing.T) {
			driver := &fakeSandboxWorkerJobDriver{
				exec: func(sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					return &sandboxruntime.ExecResult{}, nil
				},
			}
			err := runSandboxWorkerJobOrSync(context.Background(), sandboxWorkerJobCommandRequest{
				ExecutionID:  "legacy-" + purpose,
				UseWorkerJob: false,
				Run:          sandboxexec.RunContext{Driver: driver},
				Command:      sandboxexec.CommandRequest{Command: []string{"true"}},
			})
			if err != nil {
				t.Fatalf("runSandboxWorkerJobOrSync() error: %v", err)
			}
			if driver.execCalls != 1 || driver.startCalls != 0 {
				t.Fatalf("legacy synchronous Exec/job start calls = %d/%d, want 1/0", driver.execCalls, driver.startCalls)
			}
		})
	}
}

func TestExplicitWorkerJobRouteFailsClosedWithoutJobCapability(t *testing.T) {
	execCalls := 0
	driver := fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			execCalls++
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	err := runSandboxWorkerJobOrSync(context.Background(), sandboxWorkerJobCommandRequest{
		ExecutionID:  "missing-job-capability",
		UseWorkerJob: true,
		Run: sandboxexec.RunContext{
			Target: sandboxWorkerJobRuntimeTarget(),
			Driver: driver,
		},
		Command: sandboxexec.CommandRequest{Command: []string{"true"}},
	})
	if err == nil || !strings.Contains(err.Error(), "job capability") {
		t.Fatalf("explicit worker route error = %v, want job capability failure", err)
	}
	if execCalls != 0 {
		t.Fatalf("explicit worker route used synchronous Exec %d times", execCalls)
	}
}

func TestRunAndAutoFinalCommandDispatchUsesJobsWhilePreparationExecRemainsAllowed(t *testing.T) {
	for _, purpose := range []string{sandbox.SandboxLeasePurposeRun, sandbox.SandboxLeasePurposeAuto} {
		t.Run(purpose, func(t *testing.T) {
			executionID := "worker-job-" + purpose
			startedAt := time.Date(2026, 7, 25, 6, 0, 0, 0, time.UTC)
			finishedAt := startedAt.Add(time.Second)
			exitCode := 0
			terminal := queuedSandboxWorkerJob(executionID)
			terminal.State = sandboxworker.JobStateSucceeded
			terminal.StartedAt = &startedAt
			terminal.HeartbeatAt = &startedAt
			terminal.FinishedAt = &finishedAt
			terminal.ExitCode = &exitCode
			driver := &fakeSandboxWorkerJobDriver{
				startJob:   queuedSandboxWorkerJob(executionID),
				statusJobs: []sandboxworker.Job{terminal},
			}
			driver.exec = func(req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				if !reflect.DeepEqual(req.Args, []string{"prepare"}) {
					t.Fatalf("synchronous Exec received final command: %#v", req.Args)
				}
				return &sandboxruntime.ExecResult{}, nil
			}
			if _, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{Args: []string{"prepare"}}); err != nil {
				t.Fatalf("preparation Exec error: %v", err)
			}
			persistCalls := 0
			err := runSandboxWorkerJobOrSync(context.Background(), sandboxWorkerJobCommandRequest{
				ExecutionID:  executionID,
				UseWorkerJob: true,
				HostID:       "host-1",
				Run: sandboxexec.RunContext{
					Target: sandboxWorkerJobRuntimeTarget(),
					Driver: driver,
				},
				Command: sandboxexec.CommandRequest{
					Command: []string{"hal", purpose},
				},
				Persist: func(*sandboxexecution.WorkerJobReference) error {
					persistCalls++
					return nil
				},
				Wait: func(context.Context) error { return nil },
			})
			if err != nil {
				t.Fatalf("runSandboxWorkerJobOrSync() error: %v", err)
			}
			if driver.execCalls != 1 || driver.startCalls != 1 || persistCalls < 2 {
				t.Fatalf("prep Exec/job start/persist calls = %d/%d/%d, want 1/1/at least 2", driver.execCalls, driver.startCalls, persistCalls)
			}
			if !strings.Contains(strings.Join(driver.startExecReq.Args, " "), "hal") {
				t.Fatalf("JobStart exec args = %#v, want final hal command", driver.startExecReq.Args)
			}
		})
	}
}

func TestRunAndAutoProductionCallSitesUseWorkerJobDispatcherWithoutDirectImports(t *testing.T) {
	for _, test := range []struct {
		path          string
		routeSelector string
	}{
		{path: "run_sandbox.go", routeSelector: "runSandboxWorkerJobRouteSelected"},
		{path: "auto_sandbox.go", routeSelector: "autoSandboxWorkerJobRouteSelected"},
	} {
		source, err := os.ReadFile(test.path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", test.path, err)
		}
		text := string(source)
		if !strings.Contains(text, "runSandboxWorkerJobOrSync") || !strings.Contains(text, test.routeSelector) {
			t.Fatalf("%s does not route its final command through worker job selection", test.path)
		}
		if importsPackage(t, test.path, "github.com/jywlabs/hal/internal/sandboxworker") {
			t.Fatalf("%s imports sandboxworker directly", test.path)
		}
	}
}

func TestRunAndAutoWorkerJobRouteSelectionIsExplicitRootlessOnly(t *testing.T) {
	selected := workerRootlessCachedSandbox("worker-rootless")
	selected.Host.ID = "host-1"
	selected.Runtime.RuntimeID = "runtime-1"
	target := sandboxRuntimeTargetFromState(selected)

	runReq := runSandboxRequest{
		SandboxHostID:  "host-1",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
	}
	autoReq := autoSandboxRequest{
		SandboxHostID:  "host-1",
		SandboxRuntime: sandboxruntime.DriverRootlessPodman,
	}
	if !runSandboxWorkerJobRouteSelected(runReq, target, selected) {
		t.Fatal("explicit run worker-rootless route was not selected")
	}
	if !autoSandboxWorkerJobRouteSelected(autoReq, target, selected) {
		t.Fatal("explicit auto worker-rootless route was not selected")
	}
	if runSandboxWorkerJobRouteSelected(runSandboxRequest{}, target, selected) {
		t.Fatal("implicit run route selected daemon-owned jobs")
	}
	if autoSandboxWorkerJobRouteSelected(autoSandboxRequest{}, target, selected) {
		t.Fatal("implicit auto route selected daemon-owned jobs")
	}

	sshTarget := target
	sshTarget.Runtime.Driver = sandboxruntime.DriverSSHMachine
	if runSandboxWorkerJobRouteSelected(runReq, sshTarget, selected) ||
		autoSandboxWorkerJobRouteSelected(autoReq, sshTarget, selected) {
		t.Fatal("provider/SSH route selected daemon-owned jobs")
	}
}

func assertDetachedSandboxTopLevelResult(
	t *testing.T,
	err error,
	store sandboxexecution.Store,
	executionID string,
	driver *fakeSandboxWorkerJobDriver,
	releaseCalls, applyCalls int,
) {
	t.Helper()
	var detached *sandboxWorkerJobDetachedError
	if !errors.As(err, &detached) {
		t.Fatalf("top-level error = %#v, want detached job error", err)
	}
	manifest, loadErr := store.LoadManifest(executionID)
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if manifest.Status != sandboxexecution.StatusRunning || manifest.FinishedAt != nil {
		t.Fatalf("detached manifest status/finishedAt = %q/%v, want running/nil", manifest.Status, manifest.FinishedAt)
	}
	if manifest.WorkerJob == nil || manifest.WorkerJob.JobID != "job-1" {
		t.Fatalf("detached manifest WorkerJob = %#v, want durable accepted reference", manifest.WorkerJob)
	}
	if manifest.Finalization == nil || manifest.Finalization.State != sandboxexecution.FinalizationStatePending {
		t.Fatalf("detached manifest Finalization = %#v, want pending", manifest.Finalization)
	}
	if len(manifest.Artifacts) != 0 || manifest.ArtifactMetadata != nil || manifest.SyncOut != nil || manifest.SyncOutApply != nil {
		t.Fatalf("detached manifest collected/applied artifacts: %#v", manifest)
	}
	if releaseCalls != 0 || applyCalls != 0 || driver.copyOutCalls != 0 || driver.cancelCalls != 0 {
		t.Fatalf("detached side effects release/apply/copyOut/cancel = %d/%d/%d/%d, want zero", releaseCalls, applyCalls, driver.copyOutCalls, driver.cancelCalls)
	}
}

func assertTerminalSandboxTopLevelResult(
	t *testing.T,
	err error,
	store sandboxexecution.Store,
	executionID, state string,
	driver *fakeSandboxWorkerJobDriver,
	releaseCalls, applyCalls int,
) {
	t.Helper()
	proven := sandboxL3FinalizationProvenTerminalJobState(state)
	if state == sandboxworker.JobStateSucceeded {
		if err != nil {
			t.Fatalf("top-level succeeded job error = %v", err)
		}
	} else if err == nil {
		t.Fatalf("top-level %s job error = nil, want terminal result", state)
	}
	manifest, loadErr := store.LoadManifest(executionID)
	if loadErr != nil {
		t.Fatalf("LoadManifest() error: %v", loadErr)
	}
	if proven {
		if manifest.Finalization == nil || manifest.Finalization.State != sandboxexecution.FinalizationStateCompleted {
			t.Fatalf("terminal manifest Finalization = %#v, want completed", manifest.Finalization)
		}
		if manifest.Status != sandboxL3ExecutionStatusFromJob(state) || manifest.FinishedAt == nil {
			t.Fatalf("terminal manifest status/finishedAt = %q/%v, want published %q", manifest.Status, manifest.FinishedAt, sandboxL3ExecutionStatusFromJob(state))
		}
		if releaseCalls != 1 {
			t.Fatalf("terminal release calls = %d, want one finalization release", releaseCalls)
		}
		if driver.copyOutCalls == 0 {
			t.Fatal("terminal finalization did not collect artifacts")
		}
	} else {
		if manifest.Finalization == nil ||
			manifest.Finalization.State != sandboxexecution.FinalizationStateBlocked ||
			manifest.Finalization.ReasonCode != "terminal_proof_unavailable" {
			t.Fatalf("unproven terminal Finalization = %#v, want blocked terminal proof", manifest.Finalization)
		}
		wantStatus := sandboxL3ExecutionStatusFromJob(state)
		if manifest.Status != wantStatus || manifest.FinishedAt == nil {
			t.Fatalf("unproven terminal status/finishedAt = %q/%v, want %q/non-nil", manifest.Status, manifest.FinishedAt, wantStatus)
		}
		if releaseCalls != 0 || driver.copyOutCalls != 0 || driver.execCalls != 0 {
			t.Fatalf("unproven terminal side effects release/copyOut/exec = %d/%d/%d, want zero", releaseCalls, driver.copyOutCalls, driver.execCalls)
		}
	}
	if applyCalls != 0 || driver.cancelCalls != 0 {
		t.Fatalf("terminal implicit apply/cancel calls = %d/%d, want zero", applyCalls, driver.cancelCalls)
	}
}

func terminalWorkerJobWorkspacePlan(projectDir string) sandboxworkspace.Plan {
	return sandboxworkspace.Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		ProjectDir:  projectDir,
		Repository:  "git@example.com:org/repo.git",
		Branch:      "feature/terminal",
		SyncRef:     "main",
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
	}
}

type fakeSandboxWorkerJobDriver struct {
	startJob              sandboxworker.Job
	startErr              error
	resolveJob            sandboxworker.Job
	statusJobs            []sandboxworker.Job
	logPages              []sandboxworker.JobLogsResponse
	cancelAfterStart      context.CancelFunc
	startCalls            int
	resolveCalls          int
	statusCalls           int
	logsCalls             int
	cancelCalls           int
	execCalls             int
	copyOutCalls          int
	exec                  func(sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error)
	copyOut               func(sandboxruntime.CopyRequest) error
	startSubmissionID     string
	startExecReq          sandboxruntime.ExecRequest
	resolveSubmissionID   string
	logCursors            []uint64
	persistCount          func() int
	firstPollPersistCount int
}

func (driver *fakeSandboxWorkerJobDriver) ID() string {
	return sandboxruntime.DriverRootlessPodman
}

func (*fakeSandboxWorkerJobDriver) Create(context.Context, sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	return nil, errors.New("unexpected Create")
}

func (*fakeSandboxWorkerJobDriver) Start(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, errors.New("unexpected Start")
}

func (*fakeSandboxWorkerJobDriver) Stop(context.Context, sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	return nil, errors.New("unexpected Stop")
}

func (*fakeSandboxWorkerJobDriver) Delete(context.Context, sandboxruntime.LifecycleRequest) error {
	return errors.New("unexpected Delete")
}

func (*fakeSandboxWorkerJobDriver) Inspect(context.Context, sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	return nil, errors.New("unexpected Inspect")
}

func (driver *fakeSandboxWorkerJobDriver) Exec(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	driver.execCalls++
	if driver.exec != nil {
		return driver.exec(req)
	}
	panic("synchronous Driver.Exec used for final worker command")
}

func (*fakeSandboxWorkerJobDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (driver *fakeSandboxWorkerJobDriver) CopyOut(_ context.Context, req sandboxruntime.CopyRequest) error {
	driver.copyOutCalls++
	if driver.copyOut != nil {
		return driver.copyOut(req)
	}
	return nil
}

func (driver *fakeSandboxWorkerJobDriver) JobStart(_ context.Context, submissionID string, req sandboxruntime.ExecRequest) (*sandboxworker.Job, error) {
	driver.startCalls++
	driver.startSubmissionID = submissionID
	driver.startExecReq = req
	if driver.cancelAfterStart != nil {
		driver.cancelAfterStart()
	}
	if driver.startErr != nil {
		return nil, driver.startErr
	}
	job := driver.startJob
	return &job, nil
}

func (driver *fakeSandboxWorkerJobDriver) JobResolve(_ context.Context, submissionID string) (*sandboxworker.Job, error) {
	driver.resolveCalls++
	driver.resolveSubmissionID = submissionID
	job := driver.resolveJob
	return &job, nil
}

func (driver *fakeSandboxWorkerJobDriver) JobStatus(context.Context, string) (*sandboxworker.Job, error) {
	driver.recordFirstPoll()
	driver.statusCalls++
	if len(driver.statusJobs) == 0 {
		return nil, errors.New("unexpected JobStatus")
	}
	job := driver.statusJobs[0]
	driver.statusJobs = driver.statusJobs[1:]
	return &job, nil
}

func (driver *fakeSandboxWorkerJobDriver) JobLogs(_ context.Context, _ string, cursor uint64, limitBytes int64) (*sandboxworker.JobLogsResponse, error) {
	driver.recordFirstPoll()
	driver.logsCalls++
	driver.logCursors = append(driver.logCursors, cursor)
	if limitBytes != sandboxworker.DefaultJobLogReadBytes {
		return nil, errors.New("job log read was not bounded")
	}
	if len(driver.logPages) == 0 {
		return nil, errors.New("unexpected JobLogs")
	}
	page := driver.logPages[0]
	driver.logPages = driver.logPages[1:]
	return &page, nil
}

// JobCancel is intentionally outside the production seam.
func (driver *fakeSandboxWorkerJobDriver) JobCancel(context.Context, sandboxworker.JobCancelRequest) (*sandboxworker.Job, error) {
	driver.cancelCalls++
	return nil, errors.New("unexpected JobCancel")
}

func (driver *fakeSandboxWorkerJobDriver) recordFirstPoll() {
	if driver.statusCalls+driver.logsCalls != 0 {
		return
	}
	if driver.persistCount != nil {
		driver.firstPollPersistCount = driver.persistCount()
	}
}

func sandboxWorkerJobRuntimeTarget() sandboxruntime.Target {
	return sandboxruntime.Target{
		ID:     "target-1",
		Name:   "worker-rootless",
		Status: sandbox.StatusRunning,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverRootlessPodman,
			RuntimeID:      "runtime-1",
			WorkerID:       "worker-1",
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
}

func queuedSandboxWorkerJob(executionID string) sandboxworker.Job {
	submissionID := sandboxWorkerJobSubmissionID(executionID)
	return sandboxworker.Job{
		ContractVersion: sandboxworker.JobContractVersion,
		ID:              "job-1",
		SubmissionKey:   sandboxWorkerJobSubmissionKey(submissionID),
		WorkerID:        "worker-1",
		HostID:          "host-1",
		RuntimeDriver:   sandboxruntime.DriverRootlessPodman,
		RuntimeID:       "runtime-1",
		State:           sandboxworker.JobStateQueued,
		SubmittedAt:     time.Date(2026, 7, 25, 4, 0, 0, 0, time.UTC),
	}
}

var _ sandboxWorkerJobDriver = (*fakeSandboxWorkerJobDriver)(nil)
var _ io.Writer = (*bytes.Buffer)(nil)
