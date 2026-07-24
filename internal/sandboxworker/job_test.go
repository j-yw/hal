package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestWorkerJobSurvivesClientDisconnectAndPersistsRedactedPrivateState(t *testing.T) {
	secret := "l2-canary-super-secret"
	started := make(chan struct{})
	release := make(chan struct{})
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "job_driver"},
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			close(started)
			_, _ = io.WriteString(req.Stdout, "before "+secret[:9])
			_, _ = io.WriteString(req.Stdout, secret[9:]+" after\n")
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
			Exec:            l2JobExecRequest(secret),
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
	if strings.Contains(rendered.String(), secret) {
		t.Fatalf("job logs exposed secret canary: %q", rendered.String())
	}
	if !strings.Contains(rendered.String(), "[redacted]") || !strings.Contains(rendered.String(), "finished") {
		t.Fatalf("job logs = %q, want redacted and completed output", rendered.String())
	}

	assertL2JobStatePrivateAndSanitized(t, stateDir, secret)
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
	capabilities := withJobs.Capabilities()
	for _, operation := range []string{OperationJobStart, OperationJobStatus, OperationJobLogs, OperationJobCancel} {
		if !stringSliceContains(capabilities.SupportedOperations, operation) {
			t.Fatalf("configured worker does not advertise %s: %#v", operation, capabilities.SupportedOperations)
		}
	}
	if len(capabilities.RuntimeDrivers) != 1 || !stringSliceContains(capabilities.RuntimeDrivers[0].Operations, OperationJobStart) {
		t.Fatalf("exec-capable runtime does not advertise job_start: %#v", capabilities.RuntimeDrivers)
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

func TestWorkerJobCorruptDurableStateFailsSafe(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "jobs")
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
