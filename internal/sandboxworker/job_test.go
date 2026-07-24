package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestWorkerJobSurvivesClientDisconnectAndPersistsRedactedPrivateState(t *testing.T) {
	secret := "l2-canary-super-secret"
	argumentSecret := "l2-argument-only-canary"
	started := make(chan struct{})
	release := make(chan struct{})
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "job_driver"},
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			close(started)
			_, _ = io.WriteString(req.Stdout, "before "+secret[:9])
			_, _ = io.WriteString(req.Stdout, secret[9:]+" after\n")
			_, _ = io.WriteString(req.Stdout, argumentSecret[:11])
			_, _ = io.WriteString(req.Stdout, argumentSecret[11:]+"\n")
			<-release
			_, _ = io.WriteString(req.Stderr, "finished\n")
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	service, stateDir, daemonCancel := newL2JobTestService(t, driver)
	defer daemonCancel()

	server, err := NewServer(ServerOptions{SocketPath: "worker.sock", Handler: service})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	serverConn, clientConn := net.Pipe()
	go server.handleConnection(context.Background(), serverConn)

	request := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-disconnect",
		Operation:       OperationJobStart,
		DriverID:        driver.ID(),
		JobStart: &JobStartRequest{
			ContractVersion: JobContractVersion,
			Exec: func() ExecRequest {
				req := l2JobExecRequest(secret)
				req.Args = append(req.Args, "--argument-only", argumentSecret)
				return req
			}(),
		},
	}
	if err := json.NewEncoder(clientConn).Encode(request); err != nil {
		t.Fatalf("encode job start: %v", err)
	}
	var startResponse Response
	if err := json.NewDecoder(clientConn).Decode(&startResponse); err != nil {
		t.Fatalf("decode job start: %v", err)
	}
	if !startResponse.OK || startResponse.Job == nil {
		t.Fatalf("job start response = %#v error=%#v, want accepted job", startResponse, startResponse.Error)
	}
	jobID := startResponse.Job.ID
	_ = clientConn.Close()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon-owned job did not start")
	}
	close(release)
	job := waitForL2JobState(t, service, jobID, JobStateSucceeded)
	if job.ExitCode == nil || *job.ExitCode != 0 {
		t.Fatalf("completed job exitCode = %#v, want 0", job.ExitCode)
	}

	logsResponse := service.JobLogsResponse("logs", JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           jobID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	if !logsResponse.OK || logsResponse.JobLogs == nil {
		t.Fatalf("job logs response = %#v, want logs", logsResponse)
	}
	var rendered strings.Builder
	var previous uint64
	for _, record := range logsResponse.JobLogs.Records {
		if record.Cursor <= previous {
			t.Fatalf("log cursors are not strictly increasing: %#v", logsResponse.JobLogs.Records)
		}
		previous = record.Cursor
		rendered.WriteString(record.Data)
	}
	if strings.Contains(rendered.String(), secret) || strings.Contains(rendered.String(), argumentSecret) {
		t.Fatalf("job logs exposed secret canary: %q", rendered.String())
	}
	if !strings.Contains(rendered.String(), "[redacted]") || !strings.Contains(rendered.String(), "finished") {
		t.Fatalf("job logs = %q, want redacted and completed output", rendered.String())
	}

	assertL2JobStatePrivateAndSanitized(t, stateDir, secret)
	assertL2JobStatePrivateAndSanitized(t, stateDir, argumentSecret)
}

func TestWorkerJobCapabilitiesRequireConfiguredStateAndExecDriver(t *testing.T) {
	rootlessDriver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: RuntimeDriverRootlessPodman},
		execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			return &sandboxruntime.ExecResult{}, nil
		},
	}
	registry, err := NewDriverRegistry(rootlessDriver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	withoutJobs, err := NewService(ServiceOptions{
		WorkerID: "worker-no-jobs",
		HostKind: HostKindLocal,
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService(without jobs) error: %v", err)
	}
	if stringSliceContains(withoutJobs.Capabilities().SupportedOperations, OperationJobStart) {
		t.Fatal("worker without durable state advertised job_start")
	}

	withJobs, err := NewService(ServiceOptions{
		WorkerID:    "worker-with-jobs",
		HostKind:    HostKindLocal,
		Registry:    registry,
		JobStateDir: filepath.Join(t.TempDir(), "jobs"),
	})
	if err != nil {
		t.Fatalf("NewService(with jobs) error: %v", err)
	}
	defer withJobs.Close()
	capabilities := withJobs.Capabilities()
	for _, operation := range []string{OperationJobStart, OperationJobStatus, OperationJobLogs, OperationJobCancel} {
		if !stringSliceContains(capabilities.SupportedOperations, operation) {
			t.Fatalf("configured worker does not advertise %s: %#v", operation, capabilities.SupportedOperations)
		}
	}
	if len(capabilities.RuntimeDrivers) != 1 || !stringSliceContains(capabilities.RuntimeDrivers[0].Operations, OperationJobStart) {
		t.Fatalf("exec-capable runtime does not advertise job_start: %#v", capabilities.RuntimeDrivers)
	}

	microVMRegistry, err := NewDriverRegistry(&fakeWorkerRuntimeDriver{id: RuntimeDriverMicroVM})
	if err != nil {
		t.Fatalf("NewDriverRegistry(microVM) error: %v", err)
	}
	withoutExec, err := NewService(ServiceOptions{
		WorkerID:    "worker-without-job-exec",
		HostKind:    HostKindLocal,
		Registry:    microVMRegistry,
		JobStateDir: filepath.Join(t.TempDir(), "jobs"),
	})
	if err != nil {
		t.Fatalf("NewService(without job exec) error: %v", err)
	}
	defer withoutExec.Close()
	withoutExecCapabilities := withoutExec.Capabilities()
	if stringSliceContains(withoutExecCapabilities.SupportedOperations, OperationJobStart) {
		t.Fatalf("worker without exec advertised job_start: %#v", withoutExecCapabilities.SupportedOperations)
	}
	for _, operation := range []string{OperationJobStatus, OperationJobLogs, OperationJobCancel} {
		if !stringSliceContains(withoutExecCapabilities.SupportedOperations, operation) {
			t.Fatalf("durable worker omitted %s: %#v", operation, withoutExecCapabilities.SupportedOperations)
		}
	}
}

func TestWorkerJobStartRejectsWorkBeyondConfiguredCapacity(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var execCalls atomic.Int32
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "capacity_driver"},
		execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if execCalls.Add(1) == 1 {
				close(started)
				<-release
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:    "worker-capacity",
		HostKind:    HostKindLocal,
		Registry:    registry,
		JobStateDir: filepath.Join(t.TempDir(), "jobs"),
		Capacity: WorkerCapacity{
			MaxConcurrentSandboxes: 1,
		},
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	defer service.jobs.close()

	first := service.JobStartResponse(context.Background(), "first", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		Exec:            l2JobExecRequest("first-secret"),
	})
	if !first.OK || first.Job == nil {
		t.Fatalf("first start = %#v error=%#v, want accepted", first, first.Error)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first job did not start")
	}

	second := service.JobStartResponse(context.Background(), "second", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		Exec:            l2JobExecRequest("second-secret"),
	})
	if second.OK || second.Error == nil || second.Error.Code != ErrorCodeCapacityExceeded {
		t.Fatalf("second start = %#v, want stable capacity error", second)
	}

	close(release)
	waitForL2JobState(t, service, first.Job.ID, JobStateSucceeded)
	third := service.JobStartResponse(context.Background(), "third", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		Exec:            l2JobExecRequest("third-secret"),
	})
	if !third.OK || third.Job == nil {
		t.Fatalf("third start after release = %#v error=%#v, want accepted", third, third.Error)
	}
	waitForL2JobState(t, service, third.Job.ID, JobStateSucceeded)
	if got := execCalls.Load(); got != 2 {
		t.Fatalf("driver exec calls = %d, want exactly two admitted jobs", got)
	}
}

func TestWorkerJobCancellationAndTerminalRaceRules(t *testing.T) {
	t.Run("accepted cancel wins while running", func(t *testing.T) {
		started := make(chan struct{})
		driver := &l2JobRuntimeDriver{
			fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "cancel_driver"},
			execFn: func(ctx context.Context, _ sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				close(started)
				<-ctx.Done()
				return &sandboxruntime.ExecResult{ExitCode: -1}, ctx.Err()
			},
		}
		service, _, daemonCancel := newL2JobTestService(t, driver)
		defer daemonCancel()
		start := service.JobStartResponse(context.Background(), "start", driver.ID(), JobStartRequest{
			ContractVersion: JobContractVersion,
			Exec:            l2JobExecRequest("cancel-secret"),
		})
		if !start.OK || start.Job == nil {
			t.Fatalf("start response = %#v error=%#v", start, start.Error)
		}
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("job did not start")
		}
		cancel := service.JobCancelResponse("cancel", JobCancelRequest{
			ContractVersion: JobContractVersion,
			JobID:           start.Job.ID,
		})
		if !cancel.OK {
			t.Fatalf("cancel response = %#v", cancel)
		}
		waitForL2JobState(t, service, start.Job.ID, JobStateCanceled)
	})

	t.Run("persisted terminal state wins", func(t *testing.T) {
		driver := &l2JobRuntimeDriver{
			fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "terminal_driver"},
			execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
				return &sandboxruntime.ExecResult{ExitCode: 0}, nil
			},
		}
		service, _, daemonCancel := newL2JobTestService(t, driver)
		defer daemonCancel()
		start := service.JobStartResponse(context.Background(), "start", driver.ID(), JobStartRequest{
			ContractVersion: JobContractVersion,
			Exec:            l2JobExecRequest("terminal-secret"),
		})
		if !start.OK || start.Job == nil {
			t.Fatalf("start response = %#v error=%#v", start, start.Error)
		}
		terminal := waitForL2JobState(t, service, start.Job.ID, JobStateSucceeded)
		cancel := service.JobCancelResponse("cancel", JobCancelRequest{
			ContractVersion: JobContractVersion,
			JobID:           terminal.ID,
		})
		if !cancel.OK || cancel.Job == nil || cancel.Job.State != JobStateSucceeded {
			t.Fatalf("cancel after terminal = %#v, want succeeded preserved", cancel)
		}
	})
}

func TestWorkerServiceCloseWaitsForActiveJobShutdown(t *testing.T) {
	started := make(chan struct{})
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "shutdown_driver"},
		execFn: func(ctx context.Context, _ sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	service, _, daemonCancel := newL2JobTestService(t, driver)
	defer daemonCancel()
	start := service.JobStartResponse(context.Background(), "start", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		Exec:            l2JobExecRequest("shutdown-secret"),
	})
	if !start.OK || start.Job == nil {
		t.Fatalf("start response = %#v error=%#v", start, start.Error)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("job did not start")
	}

	service.Close()
	status := service.JobStatusResponse("status", JobStatusRequest{
		ContractVersion: JobContractVersion,
		JobID:           start.Job.ID,
	})
	if !status.OK || status.Job == nil || status.Job.State != JobStateInterrupted ||
		status.Job.FailureCode != "daemon_stopped" || status.Job.FinishedAt == nil {
		t.Fatalf("job after service close = %#v error=%#v, want durable interruption", status.Job, status.Error)
	}
}

func TestWorkerJobRestartReconcilesWithoutRerun(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "jobs")
	store, err := newJobStore(stateDir)
	if err != nil {
		t.Fatalf("newJobStore() error: %v", err)
	}
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	for _, item := range []struct {
		id    string
		state string
	}{
		{id: "job-queued", state: JobStateQueued},
		{id: "job-running", state: JobStateRunning},
		{id: "job-succeeded", state: JobStateSucceeded},
	} {
		job := Job{
			ContractVersion: JobContractVersion,
			ID:              item.id,
			WorkerID:        "worker-old",
			HostID:          "worker-old",
			RuntimeDriver:   "job_driver",
			RuntimeID:       "runtime-safe",
			State:           item.state,
			SubmittedAt:     now,
		}
		if err := store.save(job, nil); err != nil {
			t.Fatalf("seed %s: %v", item.id, err)
		}
	}

	manager, err := newJobManager(jobManagerOptions{
		Context:  context.Background(),
		WorkerID: "worker-new",
		StateDir: stateDir,
		Now:      func() time.Time { return now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	for jobID, want := range map[string]string{
		"job-queued":    JobStateInterrupted,
		"job-running":   JobStateUnknown,
		"job-succeeded": JobStateSucceeded,
	} {
		got, err := manager.status(jobID)
		if err != nil {
			t.Fatalf("status(%s): %v", jobID, err)
		}
		if got.State != want {
			t.Fatalf("status(%s) state = %q, want %q", jobID, got.State, want)
		}
	}
}

func TestWorkerJobRestartReconcilesCursorAndTruncationFromLogSnapshot(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "jobs")
	store, err := newJobStore(stateDir)
	if err != nil {
		t.Fatalf("newJobStore() error: %v", err)
	}
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	job := Job{
		ContractVersion: JobContractVersion,
		ID:              "job-log-snapshot",
		WorkerID:        "worker-log-snapshot",
		RuntimeDriver:   "job_driver",
		State:           JobStateSucceeded,
		SubmittedAt:     now,
		LogCursor:       1,
	}
	records := []JobLogRecord{{
		Cursor:    1,
		Stream:    JobLogStreamStdout,
		Data:      "retained",
		Timestamp: now,
	}}
	if err := store.save(job, records); err != nil {
		t.Fatalf("save() initial snapshot: %v", err)
	}

	advanced := job
	advanced.LogCursor = 2
	advanced.LogTruncated = true
	advanced.StdoutTruncated = true
	logData, err := encodeStoredJobLogs(advanced, records)
	if err != nil {
		t.Fatalf("encodeStoredJobLogs() advanced snapshot: %v", err)
	}
	jobDir, err := store.jobDir(job.ID)
	if err != nil {
		t.Fatalf("jobDir() error: %v", err)
	}
	if err := writePrivateFileAtomic(jobDir, jobLogsFileName, logData); err != nil {
		t.Fatalf("write advanced log snapshot: %v", err)
	}

	manager, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-log-snapshot",
		StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("newJobManager() restart error: %v", err)
	}
	defer manager.close()
	got, err := manager.status(job.ID)
	if err != nil {
		t.Fatalf("status() error: %v", err)
	}
	if got.LogCursor != 2 || !got.LogTruncated || !got.StdoutTruncated {
		t.Fatalf("recovered log metadata = %#v, want cursor 2 with stdout truncation", got)
	}
}

func TestWorkerJobStateDirectoryHasExclusiveManagerOwnership(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "jobs")
	first, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-first",
		StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("newJobManager() first owner error: %v", err)
	}
	t.Cleanup(first.close)

	if _, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-second",
		StateDir: stateDir,
	}); err == nil {
		t.Fatal("newJobManager() accepted a second live owner")
	}

	first.close()
	restarted, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-restarted",
		StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("newJobManager() after owner shutdown error: %v", err)
	}
	restarted.close()
}

func TestWorkerJobRestartLoadsEscapeHeavyRetainedLogs(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "jobs")
	store, err := newJobStore(stateDir)
	if err != nil {
		t.Fatalf("newJobStore() error: %v", err)
	}
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	recordCount := int(DefaultJobLogRetentionBytes / DefaultJobLogRecordBytes)
	records := make([]JobLogRecord, 0, recordCount)
	for index := 0; index < recordCount; index++ {
		records = append(records, JobLogRecord{
			Cursor:    uint64(index + 1),
			Stream:    JobLogStreamStdout,
			Data:      strings.Repeat(`"`, int(DefaultJobLogRecordBytes)),
			Timestamp: now,
		})
	}
	job := Job{
		ContractVersion: JobContractVersion,
		ID:              "job-escaped",
		WorkerID:        "worker-old",
		RuntimeDriver:   "job_driver",
		State:           JobStateSucceeded,
		SubmittedAt:     now,
		LogCursor:       uint64(recordCount),
	}
	if err := store.save(job, records); err != nil {
		t.Fatalf("save() escape-heavy retained logs: %v", err)
	}
	logInfo, err := os.Stat(filepath.Join(stateDir, job.ID, jobLogsFileName))
	if err != nil {
		t.Fatalf("Stat() logs: %v", err)
	}
	if logInfo.Size() <= DefaultJobLogRetentionBytes+(256<<10) {
		t.Fatalf("logs size = %d, want regression fixture above the former load limit", logInfo.Size())
	}

	manager, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-new",
		StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("newJobManager() restart error: %v", err)
	}
	defer manager.close()
	if got := manager.jobs[job.ID].retainedBytes; got != DefaultJobLogRetentionBytes {
		t.Fatalf("retained bytes after restart = %d, want %d", got, DefaultJobLogRetentionBytes)
	}
}

func TestWorkerJobStoreAcceptsSymlinkedParentAndCleansAbandonedTransactions(t *testing.T) {
	parent := t.TempDir()
	realParent := filepath.Join(parent, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatalf("Mkdir() real parent: %v", err)
	}
	linkedParent := filepath.Join(parent, "linked")
	if err := os.Symlink(realParent, linkedParent); err != nil {
		t.Fatalf("Symlink() parent: %v", err)
	}
	store, err := newJobStore(filepath.Join(linkedParent, "jobs"))
	if err != nil {
		t.Fatalf("newJobStore() through symlinked parent: %v", err)
	}
	transactionDir := filepath.Join(store.root, jobTransactionDirPrefix+"abandoned")
	if err := os.Mkdir(transactionDir, 0o700); err != nil {
		t.Fatalf("Mkdir() abandoned transaction: %v", err)
	}
	if err := os.WriteFile(filepath.Join(transactionDir, jobLogsFileName), []byte(`{"records":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() abandoned transaction: %v", err)
	}
	jobs, err := store.loadAll()
	if err != nil {
		t.Fatalf("loadAll() with abandoned transaction: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("loadAll() jobs = %#v, want no partially published job", jobs)
	}
	if _, err := os.Lstat(transactionDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned transaction remains after load: %v", err)
	}
}

func TestWorkerJobStoreRejectsUnmarkedExistingRootWithoutMutation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatalf("Mkdir() shared root: %v", err)
	}
	unrelated := filepath.Join(root, jobTransactionDirPrefix+"unrelated")
	if err := os.Mkdir(unrelated, 0o700); err != nil {
		t.Fatalf("Mkdir() unrelated directory: %v", err)
	}

	if _, err := newJobStore(root); err == nil {
		t.Fatal("newJobStore() accepted an arbitrary existing directory")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("Stat() shared root: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("shared root permissions = %#o, want unchanged 0755", got)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated directory was mutated or removed: %v", err)
	}

	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatalf("Chmod() shared root: %v", err)
	}
	if _, err := newJobStore(root); err == nil {
		t.Fatal("newJobStore() accepted an unmarked private directory")
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated private directory was mutated or removed: %v", err)
	}
}

func TestWorkerJobCorruptDurableStateFailsSafe(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "jobs")
	if _, err := newJobStore(stateDir); err != nil {
		t.Fatalf("newJobStore() error: %v", err)
	}
	jobDir := filepath.Join(stateDir, "job-corrupt")
	if err := os.MkdirAll(jobDir, 0o700); err != nil {
		t.Fatalf("MkdirAll() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, jobStateFileName), []byte(`{"state":"running","args":["must-not-run"]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(jobDir, jobLogsFileName), []byte(`{"records":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}
	if _, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-safe",
		StateDir: stateDir,
	}); err == nil {
		t.Fatal("newJobManager() accepted corrupt durable state")
	}
}

func TestWorkerJobBoundedLogSpoolReportsTruncation(t *testing.T) {
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "bounded_driver"},
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			_, _ = io.WriteString(req.Stdout, "abcdefghijklmnop")
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	manager, err := newJobManager(jobManagerOptions{
		Context:           context.Background(),
		WorkerID:          "worker-bounded",
		StateDir:          filepath.Join(t.TempDir(), "jobs"),
		LogRetentionBytes: 8,
		LogRecordBytes:    4,
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	service := &Service{workerID: "worker-bounded", registry: registry, jobs: manager}
	job, err := manager.start(driver.ID(), driver, JobStartRequest{
		ContractVersion: JobContractVersion,
		Exec:            l2JobExecRequest("bounded-secret"),
	})
	if err != nil {
		t.Fatalf("start() error: %v", err)
	}
	terminal := waitForL2JobState(t, service, job.ID, JobStateSucceeded)
	if !terminal.LogTruncated || !terminal.StdoutTruncated {
		t.Fatalf("terminal job = %#v, want explicit stdout truncation", terminal)
	}
	logs, err := manager.logs(JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           job.ID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	if err != nil {
		t.Fatalf("logs() error: %v", err)
	}
	if !logs.Truncated || logs.NextCursor != terminal.LogCursor {
		t.Fatalf("logs = %#v, want truncation through terminal cursor %d", logs, terminal.LogCursor)
	}
}

func TestWorkerJobLogChunkingPreservesUTF8RuneBoundaries(t *testing.T) {
	manager, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-utf8",
		StateDir: filepath.Join(t.TempDir(), "jobs"),
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	defer manager.close()
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	entry := &jobEntry{job: Job{
		ContractVersion: JobContractVersion,
		ID:              "job-utf8",
		WorkerID:        "worker-utf8",
		RuntimeDriver:   "job_driver",
		State:           JobStateRunning,
		SubmittedAt:     now,
	}}
	output := strings.Repeat("a", int(DefaultJobLogRecordBytes)-1) + "€tail"
	if err := manager.appendLog(entry, JobLogStreamStdout, []byte(output)); err != nil {
		t.Fatalf("appendLog() error: %v", err)
	}
	var rendered strings.Builder
	for _, record := range entry.records {
		if !utf8.ValidString(record.Data) {
			t.Fatalf("record data is not valid UTF-8: %q", record.Data)
		}
		if int64(len(record.Data)) > DefaultJobLogRecordBytes {
			t.Fatalf("record size = %d, want at most %d", len(record.Data), DefaultJobLogRecordBytes)
		}
		rendered.WriteString(record.Data)
	}
	if got := rendered.String(); got != output {
		t.Fatalf("rendered output differs after chunking: got %q want %q", got, output)
	}
}

func TestWorkerJobInvalidUTF8LogsRemainReadableAfterRestart(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "jobs")
	manager, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-invalid-utf8",
		StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	entry := &jobEntry{job: Job{
		ContractVersion: JobContractVersion,
		ID:              "job-invalid-utf8",
		WorkerID:        "worker-invalid-utf8",
		RuntimeDriver:   "job_driver",
		State:           JobStateSucceeded,
		SubmittedAt:     now,
	}}
	manager.jobs[entry.job.ID] = entry
	output := bytes.Repeat([]byte{0xff, 'x'}, int(DefaultJobLogRecordBytes/2))
	if utf8.Valid(output) {
		t.Fatal("invalid UTF-8 fixture unexpectedly became valid")
	}
	if err := manager.appendLog(entry, JobLogStreamStdout, output); err != nil {
		t.Fatalf("appendLog() error: %v", err)
	}
	for _, record := range entry.records {
		if !utf8.ValidString(record.Data) {
			t.Fatal("appendLog() retained invalid UTF-8")
		}
		if int64(len(record.Data)) > DefaultJobLogRecordBytes {
			t.Fatalf("record size = %d, want at most %d", len(record.Data), DefaultJobLogRecordBytes)
		}
	}
	manager.close()

	restarted, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-invalid-utf8",
		StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("newJobManager() restart error: %v", err)
	}
	defer restarted.close()
	logs, err := restarted.logs(JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           entry.job.ID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	if err != nil {
		t.Fatalf("logs() after restart error: %v", err)
	}
	if err := logs.Validate(); err != nil {
		t.Fatalf("logs() after restart validation error: %v", err)
	}
}

func TestWorkerJobGenericRedactionSpansDriverWrites(t *testing.T) {
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "stream_redaction_driver"},
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			for _, chunk := range []string{
				"TOKEN=split-",
				"secret\nhttps://exa",
				"mple.invalid/private\n/tmp/pri",
				"vate/path\n",
			} {
				if _, err := io.WriteString(req.Stdout, chunk); err != nil {
					return nil, err
				}
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	service, _, daemonCancel := newL2JobTestService(t, driver)
	defer daemonCancel()
	start := service.JobStartResponse(context.Background(), "start", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		Exec:            l2JobExecRequest("unrelated-request-secret"),
	})
	if !start.OK || start.Job == nil {
		t.Fatalf("start response = %#v error=%#v", start, start.Error)
	}
	waitForL2JobState(t, service, start.Job.ID, JobStateSucceeded)
	response := service.JobLogsResponse("logs", JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           start.Job.ID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	if !response.OK || response.JobLogs == nil {
		t.Fatalf("logs response = %#v error=%#v", response, response.Error)
	}
	var rendered strings.Builder
	for _, record := range response.JobLogs.Records {
		rendered.WriteString(record.Data)
	}
	output := rendered.String()
	for _, forbidden := range []string{"split-secret", "https://example.invalid/private", "/tmp/private/path"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("split driver output exposed %q in %q", forbidden, output)
		}
	}
	for _, marker := range []string{"TOKEN=[redacted]", "[redacted-endpoint]", "[redacted-path]"} {
		if !strings.Contains(output, marker) {
			t.Fatalf("split driver output = %q, want %q", output, marker)
		}
	}
}

func TestWorkerJobRedactsLineDerivedFromStdin(t *testing.T) {
	secret := "stdin-line-secret"
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "stdin_redaction_driver"},
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			stdin, err := io.ReadAll(req.Stdin)
			if err != nil {
				return nil, err
			}
			_, err = io.WriteString(req.Stdout, strings.TrimRight(string(stdin), "\r\n"))
			return &sandboxruntime.ExecResult{ExitCode: 0}, err
		},
	}
	service, stateDir, daemonCancel := newL2JobTestService(t, driver)
	defer daemonCancel()
	defer service.Close()
	execReq := l2JobExecRequest("unrelated-request-secret")
	execReq.Stdin = workerExecStdinPayload(secret+"\n", MaxExecStdinBytes)
	start := service.JobStartResponse(context.Background(), "start", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		Exec:            execReq,
	})
	if !start.OK || start.Job == nil {
		t.Fatalf("start response = %#v error=%#v", start, start.Error)
	}
	waitForL2JobState(t, service, start.Job.ID, JobStateSucceeded)
	response := service.JobLogsResponse("logs", JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           start.Job.ID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	if !response.OK || response.JobLogs == nil {
		t.Fatalf("logs response = %#v error=%#v", response, response.Error)
	}
	var output strings.Builder
	for _, record := range response.JobLogs.Records {
		output.WriteString(record.Data)
	}
	if got := output.String(); strings.Contains(got, secret) || !strings.Contains(got, "[redacted]") {
		t.Fatalf("stdin-derived output = %q, want a redaction marker without the secret", got)
	}
	assertL2JobStatePrivateAndSanitized(t, stateDir, secret)
}

func TestWorkerJobLogPaginationPreservesRetainedRecordsBeforeTruncationGap(t *testing.T) {
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	manager := &jobManager{
		jobs: map[string]*jobEntry{
			"job-paged": {
				job: Job{
					ID:           "job-paged",
					LogCursor:    3,
					LogTruncated: true,
				},
				records: []JobLogRecord{
					{Cursor: 1, Stream: JobLogStreamStdout, Data: strings.Repeat("a", 20<<10), Timestamp: now},
					{Cursor: 2, Stream: JobLogStreamStdout, Data: strings.Repeat("b", 20<<10), Timestamp: now},
				},
			},
		},
	}

	first, err := manager.logs(JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           "job-paged",
		LimitBytes:      DefaultJobLogRecordBytes,
	})
	if err != nil {
		t.Fatalf("first logs() error: %v", err)
	}
	if len(first.Records) != 1 || first.Records[0].Cursor != 1 || first.NextCursor != 1 || !first.Truncated {
		t.Fatalf("first logs = %#v, want retained cursor 1 without skipping", first)
	}

	second, err := manager.logs(JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           "job-paged",
		Cursor:          first.NextCursor,
		LimitBytes:      DefaultJobLogRecordBytes,
	})
	if err != nil {
		t.Fatalf("second logs() error: %v", err)
	}
	if len(second.Records) != 1 || second.Records[0].Cursor != 2 || second.NextCursor != 3 || !second.Truncated {
		t.Fatalf("second logs = %#v, want retained cursor 2 then truncation cursor 3", second)
	}
}

func TestWorkerJobLogPagesEnforceRequestedByteLimit(t *testing.T) {
	req := JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           "job-bounded",
		LimitBytes:      DefaultJobLogRecordBytes - 1,
	}
	if err := req.Validate(); err == nil {
		t.Fatal("JobLogsRequest.Validate() accepted a limit smaller than one maximum-sized record")
	}

	req.LimitBytes = DefaultJobLogRecordBytes
	err := validateClientIOResponseLimits(
		Request{Operation: OperationJobLogs, JobLogs: &req},
		Response{
			Operation: OperationJobLogs,
			OK:        true,
			JobLogs: &JobLogsResponse{
				Records: []JobLogRecord{
					{Data: strings.Repeat("a", 20<<10)},
					{Data: strings.Repeat("b", 20<<10)},
				},
			},
		},
	)
	if err == nil {
		t.Fatal("validateClientIOResponseLimits() accepted aggregate job logs above the requested limit")
	}
}

func newL2JobTestService(t *testing.T, driver sandboxruntime.Driver) (*Service, string, context.CancelFunc) {
	t.Helper()
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	stateDir := filepath.Join(t.TempDir(), "jobs")
	service, err := NewService(ServiceOptions{
		WorkerID:    "worker-l2",
		HostKind:    HostKindLocal,
		Registry:    registry,
		JobContext:  daemonCtx,
		JobStateDir: stateDir,
	})
	if err != nil {
		daemonCancel()
		t.Fatalf("NewService() error: %v", err)
	}
	return service, stateDir, daemonCancel
}

func l2JobExecRequest(secret string) ExecRequest {
	return ExecRequest{
		OperationID: "operation-l2",
		Target: Target{
			Name: "box",
			Runtime: RuntimeTarget{
				Driver:    "job_driver",
				RuntimeID: "runtime-safe",
			},
		},
		Args:             []string{"command-must-not-persist", "--credential", secret},
		Env:              map[string]string{"L2_SECRET": secret},
		StdoutLimitBytes: MaxExecStdoutCaptureBytes,
		StderrLimitBytes: MaxExecStderrCaptureBytes,
	}
}

func waitForL2JobState(t *testing.T, service *Service, jobID, want string) Job {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		response := service.JobStatusResponse("status", JobStatusRequest{
			ContractVersion: JobContractVersion,
			JobID:           jobID,
		})
		if response.OK && response.Job != nil && response.Job.State == want {
			return *response.Job
		}
		time.Sleep(10 * time.Millisecond)
	}
	response := service.JobStatusResponse("status", JobStatusRequest{
		ContractVersion: JobContractVersion,
		JobID:           jobID,
	})
	t.Fatalf("job %s state = %#v, want %s", jobID, response.Job, want)
	return Job{}
}

func assertL2JobStatePrivateAndSanitized(t *testing.T, root, secret string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if info.Mode().Perm()&0o077 != 0 {
				t.Errorf("job state directory permissions = %#o, want private", info.Mode().Perm())
			}
			return nil
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("job state file permissions = %#o, want private", info.Mode().Perm())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		for _, forbidden := range []string{secret, "command-must-not-persist", `"env"`, `"args"`, `"stdin"`, `"workDir"`} {
			if strings.Contains(content, forbidden) {
				t.Errorf("private job state persisted forbidden value %q", forbidden)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir() error: %v", err)
	}
}

type l2JobRuntimeDriver struct {
	*fakeWorkerRuntimeDriver
	execFn func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error)
}

func (driver *l2JobRuntimeDriver) Exec(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	if driver.execFn == nil {
		return nil, errors.New("job exec is not configured")
	}
	return driver.execFn(ctx, req)
}
