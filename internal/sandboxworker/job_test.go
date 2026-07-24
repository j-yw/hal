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
			SubmissionID:    "disconnect-submission",
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
	withoutJobsDriver := rootlessPodmanRuntimeDriverCapability()
	withoutJobsDriver.Operations = appendMissingStrings(
		withoutJobsDriver.Operations,
		OperationJobStart,
		OperationJobStatus,
		OperationJobLogs,
		OperationJobCancel,
	)
	withoutJobs, err := NewService(ServiceOptions{
		WorkerID: "worker-no-jobs",
		HostKind: HostKindLocal,
		Registry: registry,
		SupportedOperations: []string{
			OperationStatus,
			OperationCapabilities,
			OperationJobStart,
			OperationJobStatus,
			OperationJobLogs,
			OperationJobCancel,
		},
		RuntimeDrivers: map[string]RuntimeDriver{
			RuntimeDriverRootlessPodman: withoutJobsDriver,
		},
	})
	if err != nil {
		t.Fatalf("NewService(without jobs) error: %v", err)
	}
	withoutJobsCapabilities := withoutJobs.Capabilities()
	for _, operation := range []string{OperationJobStart, OperationJobStatus, OperationJobLogs, OperationJobCancel} {
		if stringSliceContains(withoutJobsCapabilities.SupportedOperations, operation) {
			t.Fatalf("worker without durable state advertised %s", operation)
		}
		if len(withoutJobsCapabilities.RuntimeDrivers) != 1 ||
			stringSliceContains(withoutJobsCapabilities.RuntimeDrivers[0].Operations, operation) {
			t.Fatalf("runtime without durable state advertised %s: %#v", operation, withoutJobsCapabilities.RuntimeDrivers)
		}
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

func TestWorkerJobStartRequiresExplicitRuntimeSupport(t *testing.T) {
	driver := &fakeWorkerRuntimeDriver{id: "ordinary_exec_driver"}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:    "worker-ordinary-exec",
		HostKind:    HostKindLocal,
		Registry:    registry,
		JobStateDir: filepath.Join(t.TempDir(), "jobs"),
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	defer service.Close()
	if stringSliceContains(service.Capabilities().SupportedOperations, OperationJobStart) {
		t.Fatal("ordinary exec driver advertised daemon-owned job execution")
	}
	response := service.JobStartResponse(context.Background(), "unsupported-job", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "unsupported-job-submission",
		Exec:            l2JobExecRequest("unsupported-secret"),
	})
	if response.OK || response.Error == nil || response.Error.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("job start response = %#v, want unsupported operation", response)
	}
	if driver.execCalls != 0 {
		t.Fatalf("ordinary driver exec calls = %d, want none", driver.execCalls)
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
		SubmissionID:    "capacity-first",
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
		SubmissionID:    "capacity-second",
		Exec:            l2JobExecRequest("second-secret"),
	})
	if second.OK || second.Error == nil || second.Error.Code != ErrorCodeCapacityExceeded {
		t.Fatalf("second start = %#v, want stable capacity error", second)
	}

	close(release)
	waitForL2JobState(t, service, first.Job.ID, JobStateSucceeded)
	third := service.JobStartResponse(context.Background(), "third", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "capacity-third",
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

func TestWorkerJobStartIsIdempotentAcrossLostResponseAndRestart(t *testing.T) {
	var execCalls atomic.Int32
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "idempotent_driver"},
		execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			execCalls.Add(1)
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	stateDir := filepath.Join(t.TempDir(), "jobs")
	newService := func(serviceRegistry *DriverRegistry) *Service {
		service, serviceErr := NewService(ServiceOptions{
			WorkerID:    "worker-idempotent",
			HostKind:    HostKindLocal,
			Registry:    serviceRegistry,
			JobStateDir: stateDir,
		})
		if serviceErr != nil {
			t.Fatalf("NewService() error: %v", serviceErr)
		}
		return service
	}
	request := JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "caller-stable-submission",
		Exec:            l2JobExecRequest("idempotent-secret"),
	}

	service := newService(registry)
	first := service.JobStartResponse(context.Background(), "lost-response", driver.ID(), request)
	if !first.OK || first.Job == nil {
		t.Fatalf("first start = %#v error=%#v, want accepted", first, first.Error)
	}
	retry := service.JobStartResponse(context.Background(), "retry", driver.ID(), request)
	if !retry.OK || retry.Job == nil || retry.Job.ID != first.Job.ID {
		t.Fatalf("retry start = %#v error=%#v, want original job %q", retry, retry.Error, first.Job.ID)
	}
	waitForL2JobState(t, service, first.Job.ID, JobStateSucceeded)
	service.Close()
	if first.Job.SubmissionKey == "" || first.Job.SubmissionKey == request.SubmissionID {
		t.Fatalf("job submission key = %q, want a durable opaque digest", first.Job.SubmissionKey)
	}
	assertL2JobStatePrivateAndSanitized(t, stateDir, request.SubmissionID)

	restarted := newService(&DriverRegistry{})
	defer restarted.Close()
	retryAfterRestart := restarted.JobStartResponse(context.Background(), "retry-after-restart", driver.ID(), request)
	if !retryAfterRestart.OK || retryAfterRestart.Job == nil || retryAfterRestart.Job.ID != first.Job.ID {
		t.Fatalf("restart retry = %#v error=%#v, want original job %q", retryAfterRestart, retryAfterRestart.Error, first.Job.ID)
	}
	runtimeMismatchRequest := request
	runtimeMismatchRequest.Exec = cloneJobExecRequest(request.Exec)
	runtimeMismatchRequest.Exec.Target.Runtime.RuntimeID = "runtime-different"
	runtimeMismatch := restarted.JobStartResponse(context.Background(), "retry-wrong-runtime", driver.ID(), runtimeMismatchRequest)
	if runtimeMismatch.OK || runtimeMismatch.Error == nil {
		t.Fatalf("runtime-mismatched retry = %#v, want safe rejection", runtimeMismatch)
	}
	requestMismatch := request
	requestMismatch.Exec = cloneJobExecRequest(request.Exec)
	requestMismatch.Exec.Args = append(requestMismatch.Exec.Args, "--different-work")
	requestConflict := restarted.JobStartResponse(context.Background(), "retry-changed-request", driver.ID(), requestMismatch)
	if requestConflict.OK || requestConflict.Error == nil || requestConflict.Error.Code != "submission_conflict" {
		t.Fatalf("request-mismatched retry = %#v, want submission conflict", requestConflict)
	}
	if encoded, err := json.Marshal(first.Job); err != nil {
		t.Fatalf("json.Marshal(job) error: %v", err)
	} else if strings.Contains(string(encoded), "requestKey") {
		t.Fatalf("public job exposed private request identity: %s", encoded)
	}
	mismatch := restarted.JobStartResponse(context.Background(), "retry-wrong-driver", "different_driver", request)
	if mismatch.OK || mismatch.Error == nil || mismatch.Error.Code != "submission_conflict" {
		t.Fatalf("mismatched retry = %#v, want safe rejection", mismatch)
	}
	if got := execCalls.Load(); got != 1 {
		t.Fatalf("driver exec calls = %d, want one durable submission", got)
	}
}

func TestWorkerJobStartRejectsCanceledAdmissionContext(t *testing.T) {
	var execCalls atomic.Int32
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "admission_context_driver"},
		execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			execCalls.Add(1)
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	service, _, daemonCancel := newL2JobTestService(t, driver)
	defer daemonCancel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := service.jobs.start(ctx, driver.ID(), driver, JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "canceled-admission",
		Exec:            l2JobExecRequest("canceled-secret"),
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("start() error = %v, want context.Canceled", err)
	}
	if got := execCalls.Load(); got != 0 {
		t.Fatalf("driver exec calls = %d, want none", got)
	}
}

func TestWorkerJobRequestIdentityBindsAcceptedExecution(t *testing.T) {
	base := l2JobExecRequest("request-identity-secret")
	base.Stdin = workerExecStdinPayload("stdin-secret", MaxExecStdinBytes)
	base.Env = map[string]string{"B": "two", "A": "one"}
	baseKey, err := jobRequestKey("job_driver", base)
	if err != nil {
		t.Fatalf("jobRequestKey() error: %v", err)
	}
	if !validJobRequestKey(baseKey) || !strings.HasPrefix(baseKey, "request-v1-") {
		t.Fatalf("job request identity = %q, want versioned opaque digest", baseKey)
	}
	for _, forbidden := range []string{"request-identity-secret", "stdin-secret", "runtime-safe"} {
		if strings.Contains(baseKey, forbidden) {
			t.Fatalf("job request identity exposed request value %q", forbidden)
		}
	}

	reordered := cloneJobExecRequest(base)
	reordered.Env = map[string]string{"A": "one", "B": "two"}
	reorderedKey, err := jobRequestKey("job_driver", reordered)
	if err != nil || reorderedKey != baseKey {
		t.Fatalf("map-reordered request key = %q, %v; want %q", reorderedKey, err, baseKey)
	}

	tests := []struct {
		name   string
		driver string
		change func(*ExecRequest)
	}{
		{name: "driver", driver: "different_driver"},
		{name: "operation", change: func(req *ExecRequest) { req.OperationID = "different-operation" }},
		{name: "target", change: func(req *ExecRequest) { req.Target.Runtime.RuntimeID = "runtime-different" }},
		{name: "args", change: func(req *ExecRequest) { req.Args = append(req.Args, "--different") }},
		{name: "environment", change: func(req *ExecRequest) { req.Env["A"] = "different" }},
		{name: "workdir", change: func(req *ExecRequest) { req.WorkDir = "/different" }},
		{name: "stdin", change: func(req *ExecRequest) { req.Stdin = workerExecStdinPayload("different-stdin", MaxExecStdinBytes) }},
		{name: "stdout limit", change: func(req *ExecRequest) { req.StdoutLimitBytes-- }},
		{name: "stderr limit", change: func(req *ExecRequest) { req.StderrLimitBytes-- }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := cloneJobExecRequest(base)
			changed.Env = cloneStringMap(base.Env)
			driverID := test.driver
			if driverID == "" {
				driverID = "job_driver"
			}
			if test.change != nil {
				test.change(&changed)
			}
			key, err := jobRequestKey(driverID, changed)
			if err != nil {
				t.Fatalf("jobRequestKey() error: %v", err)
			}
			if key == baseKey {
				t.Fatal("changed accepted request produced the original request identity")
			}
		})
	}
}

func TestWorkerJobLegacySubmissionWithoutRequestIdentityFailsClosed(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "jobs")
	store, err := newJobStore(stateDir)
	if err != nil {
		t.Fatalf("newJobStore() error: %v", err)
	}
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	job := Job{
		ContractVersion: JobContractVersion,
		ID:              "job-legacy-request-key",
		SubmissionKey:   jobSubmissionKey("legacy-submission"),
		WorkerID:        "worker-legacy-request-key",
		HostID:          "worker-legacy-request-key",
		RuntimeDriver:   "job_driver",
		RuntimeID:       "runtime-safe",
		State:           JobStateSucceeded,
		SubmittedAt:     now,
		StartedAt:       timePointer(now),
		HeartbeatAt:     timePointer(now),
		FinishedAt:      timePointer(now),
	}
	if err := store.save(job, nil); err != nil {
		t.Fatalf("seed legacy job: %v", err)
	}
	manager, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-legacy-request-key",
		StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	defer manager.close()
	_, exists, err := manager.existingSubmission(JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "legacy-submission",
		Exec:            l2JobExecRequest("legacy-secret"),
	}, "job_driver")
	if exists || !errors.Is(err, errJobSubmissionConflict) {
		t.Fatalf("legacy retry = exists %v error %v, want safe submission conflict", exists, err)
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
				return &sandboxruntime.ExecResult{
					ExitCode: -1,
					Cancellation: &sandboxruntime.ExecCancellationResult{
						ProcessGroupTerminated: true,
					},
				}, ctx.Err()
			},
		}
		service, _, daemonCancel := newL2JobTestService(t, driver)
		defer daemonCancel()
		start := service.JobStartResponse(context.Background(), "start", driver.ID(), JobStartRequest{
			ContractVersion: JobContractVersion,
			SubmissionID:    "cancel-proven",
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

	t.Run("unconfirmed cancel becomes unknown", func(t *testing.T) {
		started := make(chan struct{})
		driver := &l2JobRuntimeDriver{
			fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "unconfirmed_cancel_driver"},
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
			SubmissionID:    "cancel-unproven",
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
		terminal := waitForL2JobState(t, service, start.Job.ID, JobStateUnknown)
		if terminal.FailureCode != "cancel_termination_unconfirmed" {
			t.Fatalf("canceled job = %#v, want sanitized unconfirmed termination failure", terminal)
		}
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
			SubmissionID:    "cancel-terminal",
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

func TestWorkerJobCancellationIsDurableBeforeAcknowledgment(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "jobs")
	manager, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-cancel-durable",
		StateDir: stateDir,
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	defer manager.close()

	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	job := Job{
		ContractVersion: JobContractVersion,
		ID:              "job-cancel-durable",
		WorkerID:        "worker-cancel-durable",
		RuntimeDriver:   "job_driver",
		State:           JobStateRunning,
		SubmittedAt:     now,
		StartedAt:       timePointer(now),
		HeartbeatAt:     timePointer(now),
	}
	if err := manager.store.save(job, nil); err != nil {
		t.Fatalf("save() running job: %v", err)
	}
	persistedBeforeCancel := false
	entry := &jobEntry{
		job: job,
		cancel: func() {
			loaded, loadErr := manager.store.loadAll()
			if loadErr == nil && len(loaded) == 1 {
				persistedBeforeCancel = loaded[0].Job.CancelRequested
			}
		},
	}
	manager.jobs[job.ID] = entry

	got, err := manager.cancelJob(job.ID)
	if err != nil {
		t.Fatalf("cancelJob() error: %v", err)
	}
	if !persistedBeforeCancel {
		t.Fatal("cancel function ran before durable cancellation intent was published")
	}
	if !got.CancelRequested {
		t.Fatalf("cancelJob() snapshot = %#v, want pending cancellation evidence", got)
	}
}

func TestWorkerJobTerminalTransitionReleasesChildContext(t *testing.T) {
	manager, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-context-release",
		StateDir: filepath.Join(t.TempDir(), "jobs"),
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	defer manager.close()
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	cancelCalled := false
	entry := &jobEntry{
		job: Job{
			ContractVersion: JobContractVersion,
			ID:              "job-context-release",
			WorkerID:        "worker-context-release",
			RuntimeDriver:   "job_driver",
			State:           JobStateRunning,
			SubmittedAt:     now,
			StartedAt:       timePointer(now),
			HeartbeatAt:     timePointer(now),
		},
		cancel: func() {
			cancelCalled = true
		},
	}

	manager.finishLocked(entry, JobStateSucceeded, &sandboxruntime.ExecResult{ExitCode: 0}, "")

	if !cancelCalled || entry.cancel != nil {
		t.Fatalf("terminal transition retained child cancellation context: %#v", entry)
	}
	if entry.job.State != JobStateSucceeded || entry.job.FinishedAt == nil {
		t.Fatalf("terminal transition = %#v, want succeeded with finishedAt", entry.job)
	}
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
		SubmissionID:    "shutdown-submission",
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
		id              string
		state           string
		cancelRequested bool
	}{
		{id: "job-queued", state: JobStateQueued},
		{id: "job-running", state: JobStateRunning},
		{id: "job-canceling-before-start", state: JobStateQueued, cancelRequested: true},
		{id: "job-canceling-while-running", state: JobStateRunning, cancelRequested: true},
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
			CancelRequested: item.cancelRequested,
		}
		if item.state == JobStateRunning || item.state == JobStateSucceeded {
			job.StartedAt = timePointer(now)
			job.HeartbeatAt = timePointer(now)
		}
		if item.state == JobStateSucceeded {
			job.FinishedAt = timePointer(now)
		}
		if err := store.save(job, nil); err != nil {
			t.Fatalf("seed %s: %v", item.id, err)
		}
	}

	if mismatched, mismatchErr := newJobManager(jobManagerOptions{
		Context:  context.Background(),
		WorkerID: "worker-new",
		StateDir: stateDir,
		Now:      func() time.Time { return now.Add(time.Minute) },
	}); mismatchErr == nil {
		mismatched.close()
		t.Fatal("newJobManager() accepted durable state from a different worker")
	}
	manager, err := newJobManager(jobManagerOptions{
		Context:  context.Background(),
		WorkerID: "worker-old",
		StateDir: stateDir,
		Now:      func() time.Time { return now.Add(time.Minute) },
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	defer manager.close()
	for jobID, want := range map[string]string{
		"job-queued":                  JobStateInterrupted,
		"job-running":                 JobStateUnknown,
		"job-canceling-before-start":  JobStateCanceled,
		"job-canceling-while-running": JobStateUnknown,
		"job-succeeded":               JobStateSucceeded,
	} {
		got, err := manager.status(jobID)
		if err != nil {
			t.Fatalf("status(%s): %v", jobID, err)
		}
		if got.State != want {
			t.Fatalf("status(%s) state = %q, want %q", jobID, got.State, want)
		}
		if jobID == "job-canceling-while-running" {
			if !got.CancelRequested || got.FailureCode != "daemon_restarted_cancel_state_unknown" {
				t.Fatalf("status(%s) = %#v, want unknown with durable cancellation evidence", jobID, got)
			}
		} else if got.CancelRequested {
			t.Fatalf("status(%s) retained cancellation marker after reconciliation", jobID)
		}
	}
}

func TestWorkerJobManagerDeadlinePersistsInterruption(t *testing.T) {
	managerCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := make(chan struct{})
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "deadline_driver"},
		execFn: func(ctx context.Context, _ sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	manager, err := newJobManager(jobManagerOptions{
		Context:  managerCtx,
		WorkerID: "worker-deadline",
		StateDir: filepath.Join(t.TempDir(), "jobs"),
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	defer manager.close()
	job, err := manager.start(context.Background(), driver.ID(), driver, JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "deadline-submission",
		Exec:            l2JobExecRequest("deadline-secret"),
	})
	if err != nil {
		t.Fatalf("start() error: %v", err)
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("job did not start before manager deadline")
	}
	terminal := waitForL2JobState(t, &Service{jobs: manager}, job.ID, JobStateInterrupted)
	if terminal.FailureCode != "daemon_stopped" || terminal.FinishedAt == nil {
		t.Fatalf("deadline terminal job = %#v, want durable daemon interruption", terminal)
	}
}

func TestWorkerJobLifecycleClockRollbackIsClamped(t *testing.T) {
	submitted := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	started := submitted.Add(time.Minute)
	heartbeat := started.Add(time.Minute)
	manager := &jobManager{now: func() time.Time { return submitted.Add(-time.Hour) }}
	got := manager.lifecycleNow(Job{
		SubmittedAt: submitted,
		StartedAt:   timePointer(started),
		HeartbeatAt: timePointer(heartbeat),
	})
	if !got.Equal(heartbeat) {
		t.Fatalf("lifecycleNow() = %s, want prior heartbeat %s after clock rollback", got, heartbeat)
	}
}

func TestWorkerJobValidationRejectsIncoherentLifecycleTimestamps(t *testing.T) {
	submitted := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	started := submitted.Add(time.Second)
	heartbeat := started.Add(time.Second)
	finished := heartbeat.Add(time.Second)
	base := Job{
		ContractVersion: JobContractVersion,
		ID:              "job-lifecycle",
		WorkerID:        "worker-lifecycle",
		RuntimeDriver:   "job_driver",
		State:           JobStateQueued,
		SubmittedAt:     submitted,
	}
	tests := []struct {
		name   string
		mutate func(*Job)
	}{
		{
			name: "queued with started timestamp",
			mutate: func(job *Job) {
				job.StartedAt = timePointer(started)
			},
		},
		{
			name: "running without started timestamp",
			mutate: func(job *Job) {
				job.State = JobStateRunning
			},
		},
		{
			name: "running with finished timestamp",
			mutate: func(job *Job) {
				job.State = JobStateRunning
				job.StartedAt = timePointer(started)
				job.FinishedAt = timePointer(finished)
			},
		},
		{
			name: "succeeded without started timestamp",
			mutate: func(job *Job) {
				job.State = JobStateSucceeded
				job.FinishedAt = timePointer(finished)
			},
		},
		{
			name: "terminal without finished timestamp",
			mutate: func(job *Job) {
				job.State = JobStateFailed
				job.StartedAt = timePointer(started)
			},
		},
		{
			name: "started before submitted",
			mutate: func(job *Job) {
				job.State = JobStateRunning
				job.StartedAt = timePointer(submitted.Add(-time.Second))
			},
		},
		{
			name: "heartbeat before started",
			mutate: func(job *Job) {
				job.State = JobStateRunning
				job.StartedAt = timePointer(started)
				job.HeartbeatAt = timePointer(submitted)
			},
		},
		{
			name: "finished before heartbeat",
			mutate: func(job *Job) {
				job.State = JobStateSucceeded
				job.StartedAt = timePointer(started)
				job.HeartbeatAt = timePointer(heartbeat)
				job.FinishedAt = timePointer(started)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			job := base
			test.mutate(&job)
			if err := job.Validate(); err == nil {
				t.Fatalf("Job.Validate() accepted incoherent lifecycle: %#v", job)
			}
		})
	}

	for _, job := range []Job{
		base,
		{
			ContractVersion: JobContractVersion,
			ID:              "job-running-valid",
			WorkerID:        "worker-lifecycle",
			RuntimeDriver:   "job_driver",
			State:           JobStateRunning,
			SubmittedAt:     submitted,
			StartedAt:       timePointer(started),
			HeartbeatAt:     timePointer(heartbeat),
		},
		{
			ContractVersion: JobContractVersion,
			ID:              "job-succeeded-valid",
			WorkerID:        "worker-lifecycle",
			RuntimeDriver:   "job_driver",
			State:           JobStateSucceeded,
			SubmittedAt:     submitted,
			StartedAt:       timePointer(started),
			HeartbeatAt:     timePointer(heartbeat),
			FinishedAt:      timePointer(finished),
		},
		{
			ContractVersion: JobContractVersion,
			ID:              "job-canceled-valid",
			WorkerID:        "worker-lifecycle",
			RuntimeDriver:   "job_driver",
			State:           JobStateCanceled,
			SubmittedAt:     submitted,
			HeartbeatAt:     timePointer(heartbeat),
			FinishedAt:      timePointer(finished),
		},
	} {
		if err := job.Validate(); err != nil {
			t.Fatalf("Job.Validate() rejected coherent lifecycle %#v: %v", job, err)
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
		StartedAt:       timePointer(now),
		HeartbeatAt:     timePointer(now),
		FinishedAt:      timePointer(now),
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
	if mismatched, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-restarted",
		StateDir: stateDir,
	}); err == nil {
		mismatched.close()
		t.Fatal("newJobManager() accepted a different worker after owner shutdown")
	}
	restarted, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-first",
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
		StartedAt:       timePointer(now),
		HeartbeatAt:     timePointer(now),
		FinishedAt:      timePointer(now),
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
		WorkerID: "worker-old",
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
	job, err := manager.start(context.Background(), driver.ID(), driver, JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "bounded-submission",
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
		StartedAt:       timePointer(now),
		HeartbeatAt:     timePointer(now),
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
		StartedAt:       timePointer(now),
		HeartbeatAt:     timePointer(now),
		FinishedAt:      timePointer(now),
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
		SubmissionID:    "stream-redaction",
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

func TestWorkerJobPersistsBoundedNoNewlineOutputWhileRunning(t *testing.T) {
	wrote := make(chan struct{})
	release := make(chan struct{})
	safePrefix := strings.Repeat("a", jobStreamSanitizerSuffixBytes+512)
	longSecret := strings.Repeat("sensitive-value-", 400)
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "no_newline_driver"},
		execFn: func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			_, _ = io.WriteString(req.Stdout, safePrefix+" TOKEN="+longSecret)
			close(wrote)
			<-release
			_, _ = io.WriteString(req.Stdout, " safe-tail")
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	service, _, daemonCancel := newL2JobTestService(t, driver)
	defer daemonCancel()
	start := service.JobStartResponse(context.Background(), "start", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "no-newline-stream",
		Exec:            l2JobExecRequest("unrelated-request-secret"),
	})
	if !start.OK || start.Job == nil {
		t.Fatalf("start response = %#v error=%#v", start, start.Error)
	}
	select {
	case <-wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("driver did not write no-newline output")
	}
	runningLogs := service.JobLogsResponse("running-logs", JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           start.Job.ID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	if !runningLogs.OK || runningLogs.JobLogs == nil || len(runningLogs.JobLogs.Records) == 0 {
		t.Fatalf("running logs = %#v error=%#v, want durable no-newline prefix", runningLogs, runningLogs.Error)
	}
	close(release)
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
	if strings.Contains(output, longSecret) || strings.Contains(output, "sensitive-value") {
		t.Fatalf("no-newline logs exposed secret continuation: %q", output)
	}
	if !strings.Contains(output, "TOKEN=[redacted]") || !strings.Contains(output, "safe-tail") {
		t.Fatalf("no-newline logs = %q, want redaction marker and safe tail", output)
	}
}

func TestWorkerJobPersistsCompleteShortLineWhileRunning(t *testing.T) {
	wrote := make(chan struct{})
	release := make(chan struct{})
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "short_line_driver"},
		execFn: func(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if _, err := io.WriteString(req.Stdout, "ready\n"); err != nil {
				return nil, err
			}
			close(wrote)
			select {
			case <-release:
				return &sandboxruntime.ExecResult{ExitCode: 0}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	service, _, daemonCancel := newL2JobTestService(t, driver)
	defer daemonCancel()
	start := service.JobStartResponse(context.Background(), "start", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "short-line-stream",
		Exec:            l2JobExecRequest("unrelated-request-secret"),
	})
	if !start.OK || start.Job == nil {
		t.Fatalf("start response = %#v error=%#v", start, start.Error)
	}
	select {
	case <-wrote:
	case <-time.After(2 * time.Second):
		t.Fatal("driver did not write short line")
	}
	runningLogs := service.JobLogsResponse("running-logs", JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           start.Job.ID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	if !runningLogs.OK || runningLogs.JobLogs == nil || len(runningLogs.JobLogs.Records) == 0 {
		t.Fatalf("running logs = %#v error=%#v, want durable short line", runningLogs, runningLogs.Error)
	}
	if got := runningLogs.JobLogs.Records[0].Data; got != "ready\n" {
		t.Fatalf("running log = %q, want complete short line", got)
	}
	close(release)
	waitForL2JobState(t, service, start.Job.ID, JobStateSucceeded)
}

func TestWorkerJobStreamsCompleteLineWithoutLeakingSplitSecretSuffix(t *testing.T) {
	wrote := make(chan struct{})
	release := make(chan struct{})
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "line_suffix_driver"},
		execFn: func(ctx context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			if _, err := io.WriteString(req.Stdout, "ready\nTOKEN=split-"); err != nil {
				return nil, err
			}
			close(wrote)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			if _, err := io.WriteString(req.Stdout, "secret\n"); err != nil {
				return nil, err
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	service, _, daemonCancel := newL2JobTestService(t, driver)
	defer daemonCancel()
	start := service.JobStartResponse(context.Background(), "start", driver.ID(), JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "line-suffix-stream",
		Exec:            l2JobExecRequest("unrelated-request-secret"),
	})
	if !start.OK || start.Job == nil {
		t.Fatalf("start response = %#v error=%#v", start, start.Error)
	}
	<-wrote
	running := service.JobLogsResponse("running", JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           start.Job.ID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	if !running.OK || running.JobLogs == nil || len(running.JobLogs.Records) != 1 ||
		running.JobLogs.Records[0].Data != "ready\n" {
		t.Fatalf("running logs = %#v error=%#v, want only complete safe line", running.JobLogs, running.Error)
	}
	close(release)
	waitForL2JobState(t, service, start.Job.ID, JobStateSucceeded)
	terminal := service.JobLogsResponse("terminal", JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           start.Job.ID,
		LimitBytes:      DefaultJobLogReadBytes,
	})
	var output strings.Builder
	for _, record := range terminal.JobLogs.Records {
		output.WriteString(record.Data)
	}
	if got := output.String(); strings.Contains(got, "split-secret") || !strings.Contains(got, "TOKEN=[redacted]") {
		t.Fatalf("terminal logs = %q, want split secret redacted", got)
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
		SubmissionID:    "stdin-redaction",
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

func TestWorkerJobClientRejectsMismatchedResponseJobIDs(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		resp Response
	}{
		{
			name: "status",
			req: Request{
				Operation: OperationJobStatus,
				JobStatus: &JobStatusRequest{
					JobID: "job-requested",
				},
			},
			resp: Response{
				Operation: OperationJobStatus,
				OK:        true,
				Job:       &Job{ID: "job-other"},
			},
		},
		{
			name: "logs",
			req: Request{
				Operation: OperationJobLogs,
				JobLogs: &JobLogsRequest{
					JobID:      "job-requested",
					LimitBytes: DefaultJobLogReadBytes,
				},
			},
			resp: Response{
				Operation: OperationJobLogs,
				OK:        true,
				JobLogs:   &JobLogsResponse{JobID: "job-other"},
			},
		},
		{
			name: "cancel",
			req: Request{
				Operation: OperationJobCancel,
				JobCancel: &JobCancelRequest{
					JobID: "job-requested",
				},
			},
			resp: Response{
				Operation: OperationJobCancel,
				OK:        true,
				Job:       &Job{ID: "job-other"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateClientIOResponseLimits(test.req, test.resp)
			if err == nil || !strings.Contains(err.Error(), "jobId did not match request") {
				t.Fatalf("validateClientIOResponseLimits() error = %v, want mismatched jobId rejection", err)
			}
		})
	}
}

func TestWorkerJobClientRejectsMismatchedStartIdentity(t *testing.T) {
	request := JobStartRequest{
		SubmissionID: "submission-client-match",
		Exec: ExecRequest{
			Target: Target{
				Runtime: RuntimeTarget{RuntimeID: "runtime-requested"},
			},
		},
	}
	baseRequest := Request{
		Operation: OperationJobStart,
		DriverID:  "job_driver",
		JobStart:  &request,
	}
	for _, test := range []struct {
		name string
		job  Job
	}{
		{
			name: "submission key",
			job: Job{
				SubmissionKey: "submission-wrong",
				RuntimeDriver: "job_driver",
				RuntimeID:     "runtime-requested",
			},
		},
		{
			name: "runtime driver",
			job: Job{
				SubmissionKey: jobSubmissionKey(request.SubmissionID),
				RuntimeDriver: "different_driver",
				RuntimeID:     "runtime-requested",
			},
		},
		{
			name: "runtime ID",
			job: Job{
				SubmissionKey: jobSubmissionKey(request.SubmissionID),
				RuntimeDriver: "job_driver",
				RuntimeID:     "runtime-different",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateClientIOResponseLimits(baseRequest, Response{
				Operation: OperationJobStart,
				OK:        true,
				Job:       &test.job,
			})
			if err == nil {
				t.Fatalf("validateClientIOResponseLimits() accepted mismatched %s", test.name)
			}
		})
	}
}

func TestWorkerJobLogWriterReportsTruncationPersistenceFailure(t *testing.T) {
	manager := &jobManager{}
	entry := &jobEntry{}
	writer := newJobLogWriter(manager, entry, JobLogStreamStdout, 1, nil)

	if _, err := writer.Write([]byte("a")); err != nil {
		t.Fatalf("first Write() error: %v", err)
	}
	written, err := writer.Write([]byte("b"))
	if err == nil {
		t.Fatal("second Write() error = nil, want truncation persistence failure")
	}
	if written != 1 {
		t.Fatalf("second Write() wrote %d bytes, want 1", written)
	}
	if writer.Err() == nil {
		t.Fatal("Err() = nil, want truncation persistence failure")
	}
	if entry.job.LogTruncated || entry.job.StdoutTruncated {
		t.Fatalf("truncation flags = %#v, want failed persistence to remain unpublished", entry.job)
	}
}

func TestWorkerJobLogAppendPersistenceFailureRemainsUnpublished(t *testing.T) {
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	manager := &jobManager{
		logRecordBytes:    DefaultJobLogRecordBytes,
		logRetentionBytes: DefaultJobLogRetentionBytes,
		now:               func() time.Time { return now },
	}
	entry := &jobEntry{job: Job{
		ContractVersion: JobContractVersion,
		ID:              "job-log-persistence-failure",
		WorkerID:        "worker-log-persistence-failure",
		RuntimeDriver:   "job_driver",
		State:           JobStateRunning,
		SubmittedAt:     now,
		StartedAt:       timePointer(now),
		HeartbeatAt:     timePointer(now),
	}}
	if err := manager.appendLog(entry, JobLogStreamStdout, []byte("safe output\n")); err == nil {
		t.Fatal("appendLog() error = nil, want persistence failure")
	}
	if entry.job.LogCursor != 0 || entry.retainedBytes != 0 || len(entry.records) != 0 {
		t.Fatalf("failed append published cursor=%d bytes=%d records=%d", entry.job.LogCursor, entry.retainedBytes, len(entry.records))
	}
}

func TestWorkerJobLogWriterRedactsLiteralPrefixAtCaptureLimit(t *testing.T) {
	manager, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-partial-redaction",
		StateDir: filepath.Join(t.TempDir(), "jobs"),
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	defer manager.close()
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	entry := &jobEntry{job: Job{
		ContractVersion: JobContractVersion,
		ID:              "job-partial-redaction",
		WorkerID:        "worker-partial-redaction",
		RuntimeDriver:   "job_driver",
		State:           JobStateRunning,
		SubmittedAt:     now,
		StartedAt:       timePointer(now),
		HeartbeatAt:     timePointer(now),
	}}
	writer := newJobLogWriter(
		manager,
		entry,
		JobLogStreamStdout,
		4,
		newJobLiteralRedactor(ExecRequest{Args: []string{"supersecret"}}),
	)

	if written, err := writer.Write([]byte("supersecret")); err != nil || written != len("supersecret") {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", written, err, len("supersecret"))
	}
	writer.Flush()
	if err := writer.Err(); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}
	var output strings.Builder
	for _, record := range entry.records {
		output.WriteString(record.Data)
	}
	if got := output.String(); got != "[redacted]" {
		t.Fatalf("captured output = %q, want redacted partial literal", got)
	}
}

func TestWorkerJobLogWriterPersistsCaptureTruncationOnce(t *testing.T) {
	manager, err := newJobManager(jobManagerOptions{
		WorkerID: "worker-single-truncation",
		StateDir: filepath.Join(t.TempDir(), "jobs"),
	})
	if err != nil {
		t.Fatalf("newJobManager() error: %v", err)
	}
	defer manager.close()
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	entry := &jobEntry{job: Job{
		ContractVersion: JobContractVersion,
		ID:              "job-single-truncation",
		WorkerID:        "worker-single-truncation",
		RuntimeDriver:   "job_driver",
		State:           JobStateRunning,
		SubmittedAt:     now,
		StartedAt:       timePointer(now),
		HeartbeatAt:     timePointer(now),
	}}
	writer := newJobLogWriter(manager, entry, JobLogStreamStdout, 1, nil)

	if _, err := writer.Write([]byte("a")); err != nil {
		t.Fatalf("first Write() error: %v", err)
	}
	if _, err := writer.Write([]byte("b")); err != nil {
		t.Fatalf("first post-limit Write() error: %v", err)
	}
	statePath := filepath.Join(manager.store.root, entry.job.ID, jobStateFileName)
	before, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("Stat() after truncation: %v", err)
	}
	for _, output := range []string{"c", "d", "e"} {
		if _, err := writer.Write([]byte(output)); err != nil {
			t.Fatalf("repeated post-limit Write(%q) error: %v", output, err)
		}
	}
	after, err := os.Stat(statePath)
	if err != nil {
		t.Fatalf("Stat() after repeated writes: %v", err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("repeated post-limit writes persisted truncation more than once")
	}
}

func TestWorkerJobClientRejectsInvalidLogCursorProgression(t *testing.T) {
	req := JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           "job-cursors",
		Cursor:          4,
		LimitBytes:      DefaultJobLogReadBytes,
	}
	record := func(cursor uint64) JobLogRecord {
		return JobLogRecord{
			Cursor:    cursor,
			Stream:    JobLogStreamStdout,
			Data:      "safe",
			Timestamp: time.Unix(1, 0).UTC(),
		}
	}
	tests := []struct {
		name     string
		response JobLogsResponse
		wantErr  bool
	}{
		{
			name:     "next cursor regresses",
			response: JobLogsResponse{NextCursor: 3},
			wantErr:  true,
		},
		{
			name:     "record replays requested cursor",
			response: JobLogsResponse{Records: []JobLogRecord{record(4)}, NextCursor: 4},
			wantErr:  true,
		},
		{
			name:     "record starts after unexplained gap",
			response: JobLogsResponse{Records: []JobLogRecord{record(6)}, NextCursor: 6},
			wantErr:  true,
		},
		{
			name:     "records contain unexplained gap",
			response: JobLogsResponse{Records: []JobLogRecord{record(5), record(7)}, NextCursor: 7},
			wantErr:  true,
		},
		{
			name:     "next cursor advances beyond records without explanation",
			response: JobLogsResponse{Records: []JobLogRecord{record(5)}, NextCursor: 6},
			wantErr:  true,
		},
		{
			name:     "contiguous page",
			response: JobLogsResponse{Records: []JobLogRecord{record(5), record(6)}, NextCursor: 6},
		},
		{
			name:     "truncated page explains gaps",
			response: JobLogsResponse{Records: []JobLogRecord{record(6), record(8)}, NextCursor: 9, Truncated: true},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.response.ContractVersion = JobContractVersion
			test.response.JobID = req.JobID
			err := validateClientIOResponseLimits(
				Request{Operation: OperationJobLogs, JobLogs: &req},
				Response{Operation: OperationJobLogs, OK: true, JobLogs: &test.response},
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateClientIOResponseLimits() error = %v, wantErr %v", err, test.wantErr)
			}
		})
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

func (driver *l2JobRuntimeDriver) SupportsJobExecution() bool {
	return true
}
