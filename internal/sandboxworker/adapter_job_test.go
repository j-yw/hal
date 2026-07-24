package sandboxworker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestClientDriverJobStartPreservesExecIdentityWithoutSynchronousExecOrPublicSecrets(t *testing.T) {
	lifecycleClient := &recordingRuntimeDriverClient{}
	jobClient := &recordingRuntimeDriverJobClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID:  "fake_runtime",
		Client:    lifecycleClient,
		JobClient: jobClient,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	args := []string{"sh", "-lc", "cat"}
	env := map[string]string{"TOKEN": "raw-secret"}
	job, err := driver.JobStart(context.Background(), "submission-1", sandboxruntime.ExecRequest{
		Target: sandboxruntime.Target{
			ID:     "target-dev",
			Name:   "dev",
			Status: "running",
			Runtime: sandboxruntime.RuntimeState{
				RuntimeID:      "runtime-dev",
				Image:          "image-ref",
				WorkerID:       "worker-001",
				IsolationLevel: IsolationLevelContainer,
			},
		},
		Args:    args,
		Env:     env,
		WorkDir: " /workspace/private ",
		Stdin:   strings.NewReader("stdin-secret"),
	})
	if err != nil {
		t.Fatalf("JobStart() error: %v", err)
	}
	args[0] = "changed"
	env["TOKEN"] = "changed"

	if len(lifecycleClient.calls) != 0 {
		t.Fatalf("lifecycle worker calls = %#v, want no synchronous Exec dispatch", lifecycleClient.calls)
	}
	if jobClient.startCalls != 1 || jobClient.startDriverID != "fake_runtime" {
		t.Fatalf("JobStart() calls = %d driver = %q, want one fake_runtime call", jobClient.startCalls, jobClient.startDriverID)
	}
	req := jobClient.startReq
	if req.ContractVersion != JobContractVersion || req.SubmissionID != "submission-1" {
		t.Fatalf("JobStart() request identity = %#v, want sandboxjob-v1 submission-1", req)
	}
	if req.Exec.OperationID != clientDriverExecOperationID {
		t.Fatalf("JobStart() operationID = %q, want %q", req.Exec.OperationID, clientDriverExecOperationID)
	}
	if req.Exec.Target.ID != "target-dev" || req.Exec.Target.Runtime.Driver != "fake_runtime" || req.Exec.Target.Runtime.RuntimeID != "runtime-dev" {
		t.Fatalf("JobStart() target = %#v, want preserved target/runtime identity", req.Exec.Target)
	}
	if !reflect.DeepEqual(req.Exec.Args, []string{"sh", "-lc", "cat"}) || req.Exec.Env["TOKEN"] != "raw-secret" {
		t.Fatalf("JobStart() exec identity = args %#v env %#v, want cloned values", req.Exec.Args, req.Exec.Env)
	}
	if req.Exec.WorkDir != "/workspace/private" {
		t.Fatalf("JobStart() workDir = %q, want trimmed original", req.Exec.WorkDir)
	}
	if req.Exec.Stdin == nil || req.Exec.Stdin.Data != base64.StdEncoding.EncodeToString([]byte("stdin-secret")) {
		t.Fatalf("JobStart() stdin = %#v, want bounded encoded payload", req.Exec.Stdin)
	}
	if req.Exec.StdoutLimitBytes != MaxExecStdoutCaptureBytes || req.Exec.StderrLimitBytes != MaxExecStderrCaptureBytes {
		t.Fatalf("JobStart() output limits = %d/%d, want worker bounds", req.Exec.StdoutLimitBytes, req.Exec.StderrLimitBytes)
	}

	encoded, err := json.Marshal(job)
	if err != nil {
		t.Fatalf("json.Marshal(job) error: %v", err)
	}
	for _, forbidden := range []string{"raw-secret", "stdin-secret", "/workspace/private", "sh", "cat"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("public JobStart() result exposed %q: %s", forbidden, encoded)
		}
	}
}

func TestClientDriverJobOperationsPreserveRequestIdentityAndValidateResponses(t *testing.T) {
	jobClient := &recordingRuntimeDriverJobClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID:  "fake_runtime",
		Client:    &recordingRuntimeDriverClient{},
		JobClient: jobClient,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	resolved, err := driver.JobResolve(context.Background(), "submission-resolve")
	if err != nil {
		t.Fatalf("JobResolve() error: %v", err)
	}
	if resolved.SubmissionKey != jobSubmissionKey("submission-resolve") {
		t.Fatalf("JobResolve() submissionKey = %q, want request digest", resolved.SubmissionKey)
	}
	if jobClient.resolveReq != (JobResolveRequest{ContractVersion: JobContractVersion, SubmissionID: "submission-resolve"}) {
		t.Fatalf("JobResolve() request = %#v, want exact caller identity", jobClient.resolveReq)
	}

	status, err := driver.JobStatus(context.Background(), "job-status")
	if err != nil {
		t.Fatalf("JobStatus() error: %v", err)
	}
	if status.ID != "job-status" {
		t.Fatalf("JobStatus() jobId = %q, want job-status", status.ID)
	}
	if jobClient.statusReq != (JobStatusRequest{ContractVersion: JobContractVersion, JobID: "job-status"}) {
		t.Fatalf("JobStatus() request = %#v, want exact job identity", jobClient.statusReq)
	}

	logs, err := driver.JobLogs(context.Background(), "job-logs", 7, DefaultJobLogRecordBytes)
	if err != nil {
		t.Fatalf("JobLogs() error: %v", err)
	}
	if logs.JobID != "job-logs" || logs.NextCursor != 8 {
		t.Fatalf("JobLogs() response = %#v, want job-logs cursor 8", logs)
	}
	if jobClient.logsReq != (JobLogsRequest{
		ContractVersion: JobContractVersion,
		JobID:           "job-logs",
		Cursor:          7,
		LimitBytes:      DefaultJobLogRecordBytes,
	}) {
		t.Fatalf("JobLogs() request = %#v, want exact bounded request", jobClient.logsReq)
	}

	jobClient.resolveResponse = queuedAdapterJob("job-wrong", "other-submission", "fake_runtime", "runtime-dev")
	if _, err := driver.JobResolve(context.Background(), "submission-resolve"); err == nil {
		t.Fatal("JobResolve(mismatched submission) error = nil, want identity rejection")
	} else {
		assertClientDriverError(t, err, OperationJobResolve, "fake_runtime")
	}

	jobClient.statusResponse = queuedAdapterJob("job-wrong", "submission-status", "fake_runtime", "runtime-dev")
	if _, err := driver.JobStatus(context.Background(), "job-status"); err == nil {
		t.Fatal("JobStatus(mismatched job) error = nil, want identity rejection")
	} else {
		assertClientDriverError(t, err, OperationJobStatus, "fake_runtime")
	}

	jobClient.logsResponse = JobLogsResponse{
		ContractVersion: JobContractVersion,
		JobID:           "job-wrong",
		NextCursor:      7,
	}
	if _, err := driver.JobLogs(context.Background(), "job-logs", 7, DefaultJobLogRecordBytes); err == nil {
		t.Fatal("JobLogs(mismatched job) error = nil, want identity rejection")
	} else {
		assertClientDriverError(t, err, OperationJobLogs, "fake_runtime")
	}

	jobClient.startResponse = queuedAdapterJob("job-start-wrong", "other-submission", "fake_runtime", "runtime-dev")
	if _, err := driver.JobStart(context.Background(), "submission-start", sandboxruntime.ExecRequest{
		Target: adapterJobRuntimeTarget(),
		Args:   []string{"true"},
	}); err == nil {
		t.Fatal("JobStart(mismatched submission) error = nil, want identity rejection")
	} else {
		assertClientDriverError(t, err, OperationJobStart, "fake_runtime")
	}

	jobClient.logsResponse = JobLogsResponse{
		ContractVersion: JobContractVersion,
		JobID:           "job-logs",
		Records: []JobLogRecord{
			{Cursor: 8, Stream: JobLogStreamStdout, Data: strings.Repeat("a", 20<<10), Timestamp: time.Date(2026, 7, 25, 1, 2, 4, 0, time.UTC)},
			{Cursor: 9, Stream: JobLogStreamStdout, Data: strings.Repeat("b", 20<<10), Timestamp: time.Date(2026, 7, 25, 1, 2, 5, 0, time.UTC)},
		},
		NextCursor: 9,
	}
	if _, err := driver.JobLogs(context.Background(), "job-logs", 7, DefaultJobLogRecordBytes); err == nil {
		t.Fatal("JobLogs(oversized page) error = nil, want requested bound rejection")
	} else {
		assertClientDriverError(t, err, OperationJobLogs, "fake_runtime")
	}
}

func TestClientDriverJobResponsesRejectDifferentRuntimeDriver(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		configure func(*recordingRuntimeDriverJobClient)
		call      func(*ClientDriver) error
	}{
		{
			name:      "start",
			operation: OperationJobStart,
			configure: func(client *recordingRuntimeDriverJobClient) {
				client.startResponse = queuedAdapterJob("job-start", "submission-start", "other_runtime", "runtime-dev")
			},
			call: func(driver *ClientDriver) error {
				_, err := driver.JobStart(context.Background(), "submission-start", sandboxruntime.ExecRequest{
					Target: adapterJobRuntimeTarget(),
					Args:   []string{"true"},
				})
				return err
			},
		},
		{
			name:      "resolve",
			operation: OperationJobResolve,
			configure: func(client *recordingRuntimeDriverJobClient) {
				client.resolveResponse = queuedAdapterJob("job-resolve", "submission-resolve", "other_runtime", "runtime-dev")
			},
			call: func(driver *ClientDriver) error {
				_, err := driver.JobResolve(context.Background(), "submission-resolve")
				return err
			},
		},
		{
			name:      "status",
			operation: OperationJobStatus,
			configure: func(client *recordingRuntimeDriverJobClient) {
				client.statusResponse = queuedAdapterJob("job-status", "submission-status", "other_runtime", "runtime-dev")
			},
			call: func(driver *ClientDriver) error {
				_, err := driver.JobStatus(context.Background(), "job-status")
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jobClient := &recordingRuntimeDriverJobClient{}
			test.configure(jobClient)
			driver, err := NewClientDriver(ClientDriverOptions{
				DriverID:  "fake_runtime",
				Client:    &recordingRuntimeDriverClient{},
				JobClient: jobClient,
			})
			if err != nil {
				t.Fatalf("NewClientDriver() error: %v", err)
			}

			err = test.call(driver)
			if err == nil {
				t.Fatalf("%s(different runtimeDriver) error = nil, want identity rejection", test.operation)
			}
			assertClientDriverError(t, err, test.operation, "fake_runtime")
			if strings.Contains(err.Error(), "other_runtime") {
				t.Fatalf("%s error exposed returned runtime identity: %v", test.operation, err)
			}
		})
	}
}

func TestClientDriverJobResponsesAreCloned(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*recordingRuntimeDriverJobClient)
		call      func(*ClientDriver) (*Job, error)
	}{
		{
			name: "start",
			configure: func(client *recordingRuntimeDriverJobClient) {
				client.startResponse = completedAdapterJob("job-start", "submission-start", "fake_runtime", "runtime-dev")
			},
			call: func(driver *ClientDriver) (*Job, error) {
				return driver.JobStart(context.Background(), "submission-start", sandboxruntime.ExecRequest{
					Target: adapterJobRuntimeTarget(),
					Args:   []string{"true"},
				})
			},
		},
		{
			name: "resolve",
			configure: func(client *recordingRuntimeDriverJobClient) {
				client.resolveResponse = completedAdapterJob("job-resolve", "submission-resolve", "fake_runtime", "runtime-dev")
			},
			call: func(driver *ClientDriver) (*Job, error) {
				return driver.JobResolve(context.Background(), "submission-resolve")
			},
		},
		{
			name: "status",
			configure: func(client *recordingRuntimeDriverJobClient) {
				client.statusResponse = completedAdapterJob("job-status", "submission-status", "fake_runtime", "runtime-dev")
			},
			call: func(driver *ClientDriver) (*Job, error) {
				return driver.JobStatus(context.Background(), "job-status")
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			jobClient := &recordingRuntimeDriverJobClient{}
			test.configure(jobClient)
			driver, err := NewClientDriver(ClientDriverOptions{
				DriverID:  "fake_runtime",
				Client:    &recordingRuntimeDriverClient{},
				JobClient: jobClient,
			})
			if err != nil {
				t.Fatalf("NewClientDriver() error: %v", err)
			}

			job, err := test.call(driver)
			if err != nil {
				t.Fatalf("%s() error: %v", test.name, err)
			}
			if jobClient.lastJobResponse == nil || job.StartedAt == nil || job.ExitCode == nil {
				t.Fatalf("%s() response = %#v source = %#v, want completed job", test.name, job, jobClient.lastJobResponse)
			}
			originalID := job.ID
			originalStartedAt := *job.StartedAt
			originalExitCode := *job.ExitCode
			jobClient.lastJobResponse.ID = "job-mutated"
			*jobClient.lastJobResponse.StartedAt = jobClient.lastJobResponse.StartedAt.Add(time.Hour)
			*jobClient.lastJobResponse.ExitCode = 99
			if job.ID != originalID || !job.StartedAt.Equal(originalStartedAt) || *job.ExitCode != originalExitCode {
				t.Fatalf("%s() response changed after client mutation: %#v", test.name, job)
			}
		})
	}
}

func TestClientDriverJobOperationsRejectUnsupportedClientAndMalformedRequestsBeforeCalls(t *testing.T) {
	lifecycleClient := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   lifecycleClient,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	if _, err := driver.JobStart(context.Background(), "submission-1", sandboxruntime.ExecRequest{
		Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
		Args:   []string{"true"},
	}); !errors.Is(err, ErrWorkerJobClientRequired) {
		t.Fatalf("JobStart(unsupported) error = %v, want ErrWorkerJobClientRequired", err)
	}
	if len(lifecycleClient.calls) != 0 {
		t.Fatalf("unsupported job client made lifecycle calls: %#v", lifecycleClient.calls)
	}

	jobClient := &recordingRuntimeDriverJobClient{}
	driver, err = NewClientDriver(ClientDriverOptions{
		DriverID:  "fake_runtime",
		Client:    lifecycleClient,
		JobClient: jobClient,
	})
	if err != nil {
		t.Fatalf("NewClientDriver(job client) error: %v", err)
	}

	if _, err := driver.JobResolve(context.Background(), "../unsafe"); err == nil {
		t.Fatal("JobResolve(unsafe identity) error = nil")
	}
	if _, err := driver.JobStatus(context.Background(), ""); err == nil {
		t.Fatal("JobStatus(empty identity) error = nil")
	}
	if _, err := driver.JobLogs(context.Background(), "job-1", 0, DefaultJobLogRecordBytes-1); err == nil {
		t.Fatal("JobLogs(unbounded read) error = nil")
	}
	if jobClient.resolveCalls != 0 || jobClient.statusCalls != 0 || jobClient.logsCalls != 0 {
		t.Fatalf("malformed requests dispatched: resolve=%d status=%d logs=%d", jobClient.resolveCalls, jobClient.statusCalls, jobClient.logsCalls)
	}
}

func TestClientDriverJobOperationsWrapClientFailuresWithStableContext(t *testing.T) {
	sentinel := errors.New("transport unavailable")
	jobClient := &recordingRuntimeDriverJobClient{
		errByOperation: map[string]error{
			OperationJobStart:   sentinel,
			OperationJobResolve: sentinel,
			OperationJobStatus:  sentinel,
			OperationJobLogs:    sentinel,
		},
	}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID:  "fake_runtime",
		Client:    &recordingRuntimeDriverClient{},
		JobClient: jobClient,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	tests := []struct {
		operation string
		call      func() error
	}{
		{
			operation: OperationJobStart,
			call: func() error {
				_, err := driver.JobStart(context.Background(), "submission-1", sandboxruntime.ExecRequest{
					Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
					Args:   []string{"true"},
				})
				return err
			},
		},
		{
			operation: OperationJobResolve,
			call: func() error {
				_, err := driver.JobResolve(context.Background(), "submission-1")
				return err
			},
		},
		{
			operation: OperationJobStatus,
			call: func() error {
				_, err := driver.JobStatus(context.Background(), "job-1")
				return err
			},
		},
		{
			operation: OperationJobLogs,
			call: func() error {
				_, err := driver.JobLogs(context.Background(), "job-1", 0, DefaultJobLogRecordBytes)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			err := test.call()
			if !errors.Is(err, sentinel) {
				t.Fatalf("%s error = %v, want wrapped sentinel", test.operation, err)
			}
			assertClientDriverError(t, err, test.operation, "fake_runtime")
		})
	}
}

func TestClientDriverJobStartContextLossAfterAcceptanceNeverCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	jobClient := &recordingRuntimeDriverJobClient{cancelAfterStart: cancel}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID:  "fake_runtime",
		Client:    &recordingRuntimeDriverClient{},
		JobClient: jobClient,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	job, err := driver.JobStart(ctx, "submission-accepted", sandboxruntime.ExecRequest{
		Target: lifecycleRuntimeTarget("fake_runtime", "dev", "running"),
		Args:   []string{"true"},
	})
	if err != nil {
		t.Fatalf("JobStart() after accepted context loss error: %v", err)
	}
	if job == nil || job.SubmissionKey != jobSubmissionKey("submission-accepted") {
		t.Fatalf("JobStart() job = %#v, want accepted durable identity", job)
	}
	if ctx.Err() != context.Canceled {
		t.Fatalf("start context error = %v, want canceled after acceptance", ctx.Err())
	}
	if jobClient.cancelCalls != 0 {
		t.Fatalf("job cancel calls = %d, want no cancellation from adapter", jobClient.cancelCalls)
	}
}

func TestClientDriverDiscoversOptionalJobClientWithoutChangingLifecycleInterface(t *testing.T) {
	combined := &combinedRuntimeDriverJobClient{
		recordingRuntimeDriverClient:    recordingRuntimeDriverClient{},
		recordingRuntimeDriverJobClient: recordingRuntimeDriverJobClient{},
	}
	var _ RuntimeDriverClient = combined
	var _ RuntimeDriverJobClient = combined

	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   combined,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}
	if _, err := driver.JobStatus(context.Background(), "job-status"); err != nil {
		t.Fatalf("JobStatus(auto-discovered optional client) error: %v", err)
	}
	if combined.statusCalls != 1 {
		t.Fatalf("JobStatus() calls = %d, want optional job client dispatch", combined.statusCalls)
	}
}

type recordingRuntimeDriverJobClient struct {
	startCalls       int
	startDriverID    string
	startReq         JobStartRequest
	startResponse    Job
	resolveCalls     int
	resolveReq       JobResolveRequest
	resolveResponse  Job
	statusCalls      int
	statusReq        JobStatusRequest
	statusResponse   Job
	logsCalls        int
	logsReq          JobLogsRequest
	logsResponse     JobLogsResponse
	cancelAfterStart context.CancelFunc
	cancelCalls      int
	errByOperation   map[string]error
	lastJobResponse  *Job
}

func (client *recordingRuntimeDriverJobClient) JobStart(ctx context.Context, driverID string, req JobStartRequest) (*Job, error) {
	client.startCalls++
	client.startDriverID = driverID
	client.startReq = cloneAdapterJobStartRequest(req)
	if err := client.errByOperation[OperationJobStart]; err != nil {
		return nil, err
	}
	job := client.startResponse
	if job.ID == "" {
		job = queuedAdapterJob("job-start", req.SubmissionID, driverID, req.Exec.Target.Runtime.RuntimeID)
	}
	if client.cancelAfterStart != nil {
		client.cancelAfterStart()
	}
	client.lastJobResponse = &job
	return &job, nil
}

func (client *recordingRuntimeDriverJobClient) JobResolve(ctx context.Context, req JobResolveRequest) (*Job, error) {
	client.resolveCalls++
	client.resolveReq = req
	if err := client.errByOperation[OperationJobResolve]; err != nil {
		return nil, err
	}
	job := client.resolveResponse
	if job.ID == "" {
		job = queuedAdapterJob("job-resolve", req.SubmissionID, "fake_runtime", "runtime-dev")
	}
	client.lastJobResponse = &job
	return &job, nil
}

func (client *recordingRuntimeDriverJobClient) JobStatus(ctx context.Context, req JobStatusRequest) (*Job, error) {
	client.statusCalls++
	client.statusReq = req
	if err := client.errByOperation[OperationJobStatus]; err != nil {
		return nil, err
	}
	job := client.statusResponse
	if job.ID == "" {
		job = queuedAdapterJob(req.JobID, "submission-status", "fake_runtime", "runtime-dev")
	}
	client.lastJobResponse = &job
	return &job, nil
}

func (client *recordingRuntimeDriverJobClient) JobLogs(ctx context.Context, req JobLogsRequest) (*JobLogsResponse, error) {
	client.logsCalls++
	client.logsReq = req
	if err := client.errByOperation[OperationJobLogs]; err != nil {
		return nil, err
	}
	logs := client.logsResponse
	if logs.JobID == "" {
		logs = JobLogsResponse{
			ContractVersion: JobContractVersion,
			JobID:           req.JobID,
			NextCursor:      req.Cursor + 1,
			Truncated:       true,
		}
	}
	return &logs, nil
}

// JobCancel is deliberately outside RuntimeDriverJobClient. It exists only to
// detect accidental adapter cancellation after durable acceptance.
func (client *recordingRuntimeDriverJobClient) JobCancel(context.Context, JobCancelRequest) (*Job, error) {
	client.cancelCalls++
	return nil, errors.New("adapter must not cancel accepted jobs")
}

type combinedRuntimeDriverJobClient struct {
	recordingRuntimeDriverClient
	recordingRuntimeDriverJobClient
}

func queuedAdapterJob(jobID, submissionID, driverID, runtimeID string) Job {
	return Job{
		ContractVersion: JobContractVersion,
		ID:              jobID,
		SubmissionKey:   jobSubmissionKey(submissionID),
		WorkerID:        "worker-1",
		RuntimeDriver:   driverID,
		RuntimeID:       runtimeID,
		State:           JobStateQueued,
		SubmittedAt:     time.Date(2026, 7, 25, 1, 2, 3, 0, time.UTC),
	}
}

func completedAdapterJob(jobID, submissionID, driverID, runtimeID string) Job {
	job := queuedAdapterJob(jobID, submissionID, driverID, runtimeID)
	startedAt := job.SubmittedAt.Add(time.Second)
	heartbeatAt := startedAt.Add(time.Second)
	finishedAt := heartbeatAt.Add(time.Second)
	exitCode := 0
	job.State = JobStateSucceeded
	job.StartedAt = &startedAt
	job.HeartbeatAt = &heartbeatAt
	job.FinishedAt = &finishedAt
	job.ExitCode = &exitCode
	return job
}

func adapterJobRuntimeTarget() sandboxruntime.Target {
	target := lifecycleRuntimeTarget("fake_runtime", "dev", "running")
	target.Runtime.RuntimeID = "runtime-dev"
	return target
}

func cloneAdapterJobStartRequest(req JobStartRequest) JobStartRequest {
	cloned := req
	cloned.Exec = cloneJobExecRequest(req.Exec)
	return cloned
}
