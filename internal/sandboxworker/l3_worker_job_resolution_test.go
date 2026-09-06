package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestWorkerJobResolveFindsAcceptedSubmissionAfterRestartWithoutExecuting(t *testing.T) {
	var execCalls atomic.Int32
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "resolve_driver"},
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
		t.Helper()
		service, serviceErr := NewService(ServiceOptions{
			WorkerID:    "worker-resolve",
			HostKind:    HostKindLocal,
			Registry:    serviceRegistry,
			JobStateDir: stateDir,
		})
		if serviceErr != nil {
			t.Fatalf("NewService() error: %v", serviceErr)
		}
		return service
	}

	submissionID := "lost-acknowledgement-submission"
	request := JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    submissionID,
		Exec:            l2JobExecRequest("resolve-secret"),
	}
	request.Exec.Target.Runtime.Driver = driver.ID()

	service := newService(registry)
	started := service.JobStartResponse(context.Background(), "lost-response", driver.ID(), request)
	if !started.OK || started.Job == nil {
		t.Fatalf("JobStartResponse() = %#v, want accepted job", started)
	}
	waitForL2JobState(t, service, started.Job.ID, JobStateSucceeded)
	service.Close()

	restarted := newService(&DriverRegistry{})
	defer restarted.Close()
	if !stringSliceContains(restarted.Capabilities().SupportedOperations, OperationJobResolve) {
		t.Fatalf("durable worker operations = %#v, want %q", restarted.Capabilities().SupportedOperations, OperationJobResolve)
	}
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(ctx context.Context, req Request) (Response, error) {
			return restarted.HandleRequest(ctx, req), nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	resolved, err := client.JobResolve(context.Background(), JobResolveRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    submissionID,
	})
	if err != nil {
		t.Fatalf("JobResolve() error: %v", err)
	}
	if resolved.ID != started.Job.ID {
		t.Fatalf("JobResolve() jobId = %q, want original %q", resolved.ID, started.Job.ID)
	}
	if resolved.SubmissionKey != jobSubmissionKey(submissionID) {
		t.Fatalf("JobResolve() submissionKey = %q, want caller identity digest", resolved.SubmissionKey)
	}
	if got := execCalls.Load(); got != 1 {
		t.Fatalf("driver exec calls = %d, want one admitted job", got)
	}
	assertL2JobStatePrivateAndSanitized(t, stateDir, submissionID)

	missingSubmission := "missing-submission-canary"
	_, err = client.JobResolve(context.Background(), JobResolveRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    missingSubmission,
	})
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) || protocolErr.Code != ErrorCodeJobNotFound {
		t.Fatalf("JobResolve(missing) error = %#v, want %s", err, ErrorCodeJobNotFound)
	}
	if strings.Contains(err.Error(), missingSubmission) {
		t.Fatalf("JobResolve(missing) error exposed submission identity: %v", err)
	}
	assertL2JobStatePrivateAndSanitized(t, stateDir, missingSubmission)
	if got := execCalls.Load(); got != 1 {
		t.Fatalf("driver exec calls after missing resolution = %d, want no new job", got)
	}
}

func TestWorkerJobResolveClientValidatesResponseSubmissionIdentity(t *testing.T) {
	submissionID := "client-resolution-submission"
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
			if req.Operation != OperationJobResolve || req.JobResolve == nil {
				t.Fatalf("resolve request = %#v, want %s payload", req, OperationJobResolve)
			}
			if req.JobResolve.SubmissionID != submissionID {
				t.Fatalf("resolve submissionId = %q, want %q", req.JobResolve.SubmissionID, submissionID)
			}
			return Response{
				ProtocolVersion: ProtocolVersion,
				RequestID:       req.RequestID,
				Operation:       OperationJobResolve,
				OK:              true,
				Job: &Job{
					ContractVersion: JobContractVersion,
					ID:              "job-client-resolve",
					SubmissionKey:   jobSubmissionKey("different-submission"),
					WorkerID:        "worker-client-resolve",
					RuntimeDriver:   "resolve_driver",
					RuntimeID:       "runtime-client-resolve",
					State:           JobStateQueued,
					SubmittedAt:     time.Unix(1_700_000_000, 0).UTC(),
				},
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = client.JobResolve(context.Background(), JobResolveRequest{
		SubmissionID: submissionID,
	})
	var clientErr *ClientError
	if !errors.As(err, &clientErr) || clientErr.Code != ErrorCodeMalformedRequest {
		t.Fatalf("JobResolve() error = %#v, want malformed response rejection", err)
	}
	if strings.Contains(err.Error(), submissionID) {
		t.Fatalf("JobResolve() validation error exposed submission identity: %v", err)
	}
}

func TestWorkerStatusCountsDistinctActiveJobRuntimeIDsAndConverges(t *testing.T) {
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	driver := &l2JobRuntimeDriver{
		fakeWorkerRuntimeDriver: &fakeWorkerRuntimeDriver{id: "status_jobs_driver"},
		execFn: func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			started <- struct{}{}
			<-release
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:    "worker-active-runtime-count",
		HostKind:    HostKindLocal,
		Registry:    registry,
		JobStateDir: filepath.Join(t.TempDir(), "jobs"),
		Capacity: WorkerCapacity{
			MaxConcurrentSandboxes: 3,
			ActiveSandboxes:        1,
		},
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	defer service.Close()
	if got := service.Status().Capacity.ActiveSandboxes; got != 0 {
		t.Fatalf("initial activeSandboxes = %d, want durable active-job projection", got)
	}

	type submission struct {
		id        string
		runtimeID string
	}
	submissions := []submission{
		{id: "active-runtime-a-first", runtimeID: "runtime-a"},
		{id: "active-runtime-a-second", runtimeID: "runtime-a"},
		{id: "active-runtime-b", runtimeID: "runtime-b"},
	}
	jobIDs := make([]string, 0, len(submissions))
	for _, submission := range submissions {
		req := l2JobExecRequest("active-count-secret")
		req.OperationID = submission.id
		req.Target.Runtime.Driver = driver.ID()
		req.Target.Runtime.RuntimeID = submission.runtimeID
		response := service.JobStartResponse(context.Background(), submission.id, driver.ID(), JobStartRequest{
			ContractVersion: JobContractVersion,
			SubmissionID:    submission.id,
			Exec:            req,
		})
		if !response.OK || response.Job == nil {
			t.Fatalf("JobStartResponse(%s) = %#v, want accepted job", submission.id, response)
		}
		jobIDs = append(jobIDs, response.Job.ID)
	}
	for range submissions {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("durable jobs did not all enter running state")
		}
	}

	if got := service.Status().Capacity.ActiveSandboxes; got != 2 {
		t.Fatalf("activeSandboxes with two runtime IDs = %d, want 2", got)
	}

	close(release)
	for _, jobID := range jobIDs {
		waitForL2JobState(t, service, jobID, JobStateSucceeded)
	}
	if got := service.Status().Capacity.ActiveSandboxes; got != 0 {
		t.Fatalf("terminal activeSandboxes = %d, want 0", got)
	}

	statusJSON, err := json.Marshal(service.Status())
	if err != nil {
		t.Fatalf("json.Marshal(Status()) error: %v", err)
	}
	if strings.Contains(string(statusJSON), "active-count-secret") {
		t.Fatalf("worker status exposed job request data: %s", statusJSON)
	}
}
