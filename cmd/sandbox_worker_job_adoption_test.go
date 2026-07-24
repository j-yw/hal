package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
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
	if submissionID == "" || submissionID != sandboxWorkerJobSubmissionID(executionID) {
		t.Fatalf("submission identity = %q, want stable non-empty identity", submissionID)
	}
	if submissionID == sandboxWorkerJobSubmissionID("exec-stable-2") {
		t.Fatal("different execution IDs produced the same submission identity")
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
	last := persisted[len(persisted)-1]
	if last.State != sandboxworker.JobStateSucceeded || last.LogCursor != 3 {
		t.Fatalf("last persisted reference = %#v, want succeeded terminal cursor 3", last)
	}
	if !reflect.DeepEqual(driver.logCursors, []uint64{0, 1}) {
		t.Fatalf("log cursors = %#v, want bounded monotonic drain", driver.logCursors)
	}
	if strings.Contains(stdout.String(), "raw-secret") || strings.Contains(stderr.String(), "/private/work") {
		t.Fatalf("streamed logs were not redacted: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "first") || !strings.Contains(stdout.String(), "done") || !strings.Contains(stderr.String(), "warning") {
		t.Fatalf("streamed logs missing records: stdout=%q stderr=%q", stdout.String(), stderr.String())
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
		t.Run(field.name, func(t *testing.T) {
			job := queuedSandboxWorkerJob("identity")
			field.mutate(&job)
			driver := &fakeSandboxWorkerJobDriver{
				startJob:   queuedSandboxWorkerJob("identity"),
				statusJobs: []sandboxworker.Job{job},
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
				t.Fatalf("identity mismatch %s error = nil", field.name)
			}
			for _, unsafe := range []string{"host-other", "worker-other", "runtime-other"} {
				if strings.Contains(err.Error(), unsafe) {
					t.Fatalf("identity mismatch error exposed %q: %v", unsafe, err)
				}
			}
		})
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

func TestRunAndAutoSandboxManifestSavesPreserveWorkerJobAndFinalization(t *testing.T) {
	now := time.Date(2026, 7, 25, 5, 0, 0, 0, time.UTC)
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		t.Run(string(purpose), func(t *testing.T) {
			store := sandboxexecution.NewStore(t.TempDir())
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

func TestRunAndAutoSandboxDetachedJobsStayRunningWithoutFinalizationSideEffects(t *testing.T) {
	now := time.Date(2026, 7, 25, 5, 30, 0, 0, time.UTC)
	for _, purpose := range []sandboxexecution.Purpose{sandboxexecution.PurposeRun, sandboxexecution.PurposeAuto} {
		t.Run(string(purpose), func(t *testing.T) {
			projectDir := t.TempDir()
			store := sandboxexecution.NewStore(t.TempDir())
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

func TestRunAndAutoFinalCommandDispatchKeepsLegacySynchronousPath(t *testing.T) {
	for _, purpose := range []string{sandbox.SandboxLeasePurposeRun, sandbox.SandboxLeasePurposeAuto} {
		t.Run(purpose, func(t *testing.T) {
			execCalls := 0
			driver := fakeRunSandboxRuntimeDriver{
				exec: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					execCalls++
					return &sandboxruntime.ExecResult{}, nil
				},
			}
			err := runSandboxWorkerJobOrSync(context.Background(), sandboxWorkerJobCommandRequest{
				Purpose:      purpose,
				ExecutionID:  "legacy-" + purpose,
				UseWorkerJob: false,
				Run:          sandboxexec.RunContext{Driver: driver},
				Command:      sandboxexec.CommandRequest{Command: []string{"true"}},
			})
			if err != nil {
				t.Fatalf("runSandboxWorkerJobOrSync() error: %v", err)
			}
			if execCalls != 1 {
				t.Fatalf("legacy synchronous Exec calls = %d, want 1", execCalls)
			}
		})
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
	startSubmissionID     string
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

func (driver *fakeSandboxWorkerJobDriver) Exec(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	driver.execCalls++
	panic("synchronous Driver.Exec used for final worker command")
}

func (*fakeSandboxWorkerJobDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (driver *fakeSandboxWorkerJobDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	driver.copyOutCalls++
	return nil
}

func (driver *fakeSandboxWorkerJobDriver) JobStart(_ context.Context, submissionID string, _ sandboxruntime.ExecRequest) (*sandboxworker.Job, error) {
	driver.startCalls++
	driver.startSubmissionID = submissionID
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

func sandboxWorkerJobSubmissionKey(submissionID string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(submissionID)))
	return "submission-" + hex.EncodeToString(sum[:])
}

var _ sandboxWorkerJobDriver = (*fakeSandboxWorkerJobDriver)(nil)
var _ io.Writer = (*bytes.Buffer)(nil)
