package sandboxworker

import (
	"testing"
	"time"
)

func (fixtures l8WorkerV2RequestPayloadFixtures) setV1Payload(request *Request, index int) {
	switch index {
	case 0:
		request.JobStart = &fixtures.startV1
	case 1:
		request.JobResolve = &fixtures.resolveV1
	case 2:
		request.JobStatus = &fixtures.statusV1
	case 3:
		request.JobLogs = &fixtures.logsV1
	case 4:
		request.JobCancel = &fixtures.cancelV1
	}
}

func (fixtures l8WorkerV2RequestPayloadFixtures) setV2Payload(request *Request, index int) {
	switch index {
	case 0:
		request.JobStartV2 = &fixtures.startV2
	case 1:
		request.JobResolveV2 = &fixtures.resolveV2
	case 2:
		request.JobStatusV2 = &fixtures.statusV2
	case 3:
		request.JobLogsV2 = &fixtures.logsV2
	case 4:
		request.JobCancelV2 = &fixtures.cancelV2
	}
}

func (fixtures l8WorkerV2RequestPayloadFixtures) v1Names() []string {
	return []string{OperationJobStart, OperationJobResolve, OperationJobStatus, OperationJobLogs, OperationJobCancel}
}

func (fixtures l8WorkerV2RequestPayloadFixtures) v2Requests() []l8WorkerV2NamedRequest {
	return []l8WorkerV2NamedRequest{
		{name: OperationJobStartV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-start-v2", Operation: OperationJobStartV2, DriverID: RuntimeDriverMicroVM, JobStartV2: &fixtures.startV2}},
		{name: OperationJobResolveV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-resolve-v2", Operation: OperationJobResolveV2, JobResolveV2: &fixtures.resolveV2}},
		{name: OperationJobStatusV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-status-v2", Operation: OperationJobStatusV2, JobStatusV2: &fixtures.statusV2}},
		{name: OperationJobLogsV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-logs-v2", Operation: OperationJobLogsV2, JobLogsV2: &fixtures.logsV2}},
		{name: OperationJobCancelV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-cancel-v2", Operation: OperationJobCancelV2, JobCancelV2: &fixtures.cancelV2}},
	}
}

func TestL8WorkerV2RequestValidationDispatchesOnlyTheMatchingPayload(t *testing.T) {
	fixtures := l8WorkerV2RequestPayloadFixturesForTest(t)
	requests := fixtures.v2Requests()
	for _, tt := range requests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.req.Validate(); err != nil {
				t.Fatalf("valid v2 dispatch request: %v", err)
			}
		})
	}

	for matchingIndex, matching := range requests {
		for extraIndex, extra := range requests {
			if extraIndex == matchingIndex {
				continue
			}
			t.Run(matching.name+"/smuggled-v2/"+extra.name, func(t *testing.T) {
				candidate := matching.req
				fixtures.setV2Payload(&candidate, extraIndex)
				if err := candidate.Validate(); err == nil {
					t.Fatal("matching V2 request accepted a nonmatching V2 payload")
				}
			})
		}
		for v1Index, v1Name := range fixtures.v1Names() {
			t.Run(matching.name+"/smuggled-v1/"+v1Name, func(t *testing.T) {
				candidate := matching.req
				fixtures.setV1Payload(&candidate, v1Index)
				if err := candidate.Validate(); err == nil {
					t.Fatal("matching V2 request accepted a V1 payload")
				}
			})
		}
	}

	invalidOperation := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-invalid-v1-operation",
		Operation:       OperationJobStart,
		DriverID:        RuntimeDriverMicroVM,
		JobStartV2:      &fixtures.startV2,
	}
	if err := invalidOperation.Validate(); err == nil {
		t.Fatal("V1 operation accepted an isolated valid V2 payload")
	}
}

func TestL8WorkerV2ResponseValidationRejectsSmuggledPayloads(t *testing.T) {
	v1Job := l8WorkerV1ValidQueuedJob(t)
	v1Logs := JobLogsResponse{ContractVersion: JobContractVersion, JobID: v1Job.ID}
	if err := v1Logs.Validate(); err != nil {
		t.Fatalf("valid V1 logs smuggling fixture: %v", err)
	}
	v2Job := l8WorkerV2QueuedJob()
	v2Logs := JobLogsResponseV2{ContractVersion: JobContractVersionV2, JobID: v2Job.ID}
	if err := v2Logs.Validate(); err != nil {
		t.Fatalf("valid V2 logs fixture: %v", err)
	}

	for _, operation := range []string{OperationJobStartV2, OperationJobResolveV2, OperationJobStatusV2, OperationJobLogsV2, OperationJobCancelV2} {
		matching := Response{ProtocolVersion: ProtocolVersion, RequestID: "request-v2", Operation: operation, OK: true}
		if operation == OperationJobLogsV2 {
			matching.JobLogsV2 = &v2Logs
		} else {
			matching.JobV2 = &v2Job
		}
		if err := matching.Validate(); err != nil {
			t.Fatalf("valid matching %s V2 response: %v", operation, err)
		}

		mutations := []struct {
			name   string
			mutate func(*Response)
		}{
			{name: "nonmatching V2 payload", mutate: func(response *Response) {
				if operation == OperationJobLogsV2 {
					response.JobV2 = &v2Job
				} else {
					response.JobLogsV2 = &v2Logs
				}
			}},
			{name: "V1 job payload", mutate: func(response *Response) { response.Job = &v1Job }},
			{name: "V1 logs payload", mutate: func(response *Response) { response.JobLogs = &v1Logs }},
		}
		for _, fixture := range l8WorkerV2ValidNonJobResponsePointerFixtures(t) {
			mutations = append(mutations, struct {
				name   string
				mutate func(*Response)
			}{name: fixture.name, mutate: fixture.attach})
		}
		for _, mutation := range mutations {
			t.Run(operation+"/"+mutation.name, func(t *testing.T) {
				candidate := matching
				mutation.mutate(&candidate)
				if err := candidate.Validate(); err == nil {
					t.Fatal("successful V2 response accepted a smuggled payload")
				}
			})
		}
	}
}

func l8WorkerV1ValidQueuedJob(t *testing.T) Job {
	t.Helper()
	job := Job{
		ContractVersion: JobContractVersion,
		ID:              "job-v1-valid",
		SubmissionKey:   jobSubmissionKey("submission-v1-valid"),
		WorkerID:        "worker-v1-valid",
		HostID:          "host-v1-valid",
		RuntimeDriver:   RuntimeDriverMicroVM,
		RuntimeID:       "runtime-v1-valid",
		State:           JobStateQueued,
		SubmittedAt:     time.Date(2026, time.August, 3, 2, 3, 4, 0, time.UTC),
	}
	if err := job.Validate(); err != nil {
		t.Fatalf("valid v1 success fixture: %v", err)
	}
	return job
}

func l8WorkerV2RequestPayloadFixturesForTest(t *testing.T) l8WorkerV2RequestPayloadFixtures {
	t.Helper()
	start := l8WorkerV2StartRequest()
	fixtures := l8WorkerV2RequestPayloadFixtures{
		startV2:   start,
		resolveV2: JobResolveRequestV2{ContractVersion: JobContractVersionV2, SubmissionID: start.SubmissionID},
		statusV2:  JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary"},
		logsV2:    JobLogsRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary", LimitBytes: DefaultJobLogRecordBytes},
		cancelV2:  JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary"},
		startV1:   JobStartRequest{ContractVersion: JobContractVersion, SubmissionID: "submission-v1-valid", Exec: l8WorkerV2ExecRequest()},
		resolveV1: JobResolveRequest{ContractVersion: JobContractVersion, SubmissionID: "submission-v1-valid"},
		statusV1:  JobStatusRequest{ContractVersion: JobContractVersion, JobID: "job-v1-valid"},
		logsV1:    JobLogsRequest{ContractVersion: JobContractVersion, JobID: "job-v1-valid", LimitBytes: DefaultJobLogRecordBytes},
		cancelV1:  JobCancelRequest{ContractVersion: JobContractVersion, JobID: "job-v1-valid"},
	}
	for _, fixture := range []struct {
		name     string
		validate func() error
	}{
		{name: "start", validate: fixtures.startV1.Validate},
		{name: "resolve", validate: fixtures.resolveV1.Validate},
		{name: "status", validate: fixtures.statusV1.Validate},
		{name: "logs", validate: fixtures.logsV1.Validate},
		{name: "cancel", validate: fixtures.cancelV1.Validate},
	} {
		if err := fixture.validate(); err != nil {
			t.Fatalf("valid V1 %s smuggling fixture: %v", fixture.name, err)
		}
	}
	return fixtures
}

func l8WorkerV2ValidNonJobResponsePointerFixtures(t *testing.T) []l8WorkerV2ResponsePointerFixture {
	t.Helper()
	status := Status{
		WorkerID: "worker-valid",
		HostKind: HostKindLocal,
		Health:   WorkerHealth{Status: HealthStatusHealthy},
	}
	if err := status.Validate(); err != nil {
		t.Fatalf("valid smuggled status fixture: %v", err)
	}
	capabilities := Capabilities{
		WorkerID: "worker-valid",
	}
	if err := capabilities.Validate(); err != nil {
		t.Fatalf("valid smuggled capabilities fixture: %v", err)
	}
	target := Target{
		Name: "sandbox-valid",
		Runtime: RuntimeTarget{
			Driver: RuntimeDriverMicroVM,
		},
	}
	if err := target.Validate(); err != nil {
		t.Fatalf("valid smuggled target fixture: %v", err)
	}
	return []l8WorkerV2ResponsePointerFixture{
		{name: "status payload", attach: func(response *Response) {
			copy := status
			response.Status = &copy
		}},
		{name: "capabilities payload", attach: func(response *Response) {
			copy := capabilities
			response.Capabilities = &copy
		}},
		{name: "target payload", attach: func(response *Response) {
			copy := target
			response.Target = &copy
		}},
	}
}

type l8WorkerV2NamedRequest struct {
	name string
	req  Request
}

type l8WorkerV2RequestPayloadFixtures struct {
	startV2   JobStartRequestV2
	resolveV2 JobResolveRequestV2
	statusV2  JobStatusRequestV2
	logsV2    JobLogsRequestV2
	cancelV2  JobCancelRequestV2
	startV1   JobStartRequest
	resolveV1 JobResolveRequest
	statusV1  JobStatusRequest
	logsV1    JobLogsRequest
	cancelV1  JobCancelRequest
}

type l8WorkerV2ResponsePointerFixture struct {
	name   string
	attach func(*Response)
}
