package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

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

type l8WorkerV2NamedRequest struct {
	name string
	req  Request
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

func (fixtures l8WorkerV2RequestPayloadFixtures) v2Requests() []l8WorkerV2NamedRequest {
	return []l8WorkerV2NamedRequest{
		{name: OperationJobStartV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-start-v2", Operation: OperationJobStartV2, DriverID: RuntimeDriverMicroVM, JobStartV2: &fixtures.startV2}},
		{name: OperationJobResolveV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-resolve-v2", Operation: OperationJobResolveV2, JobResolveV2: &fixtures.resolveV2}},
		{name: OperationJobStatusV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-status-v2", Operation: OperationJobStatusV2, JobStatusV2: &fixtures.statusV2}},
		{name: OperationJobLogsV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-logs-v2", Operation: OperationJobLogsV2, JobLogsV2: &fixtures.logsV2}},
		{name: OperationJobCancelV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-cancel-v2", Operation: OperationJobCancelV2, JobCancelV2: &fixtures.cancelV2}},
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

	for _, operationCase := range l8WorkerV2ClientOperationCases() {
		operation := operationCase.operation
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
				client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, request Request) (Response, error) {
					candidate.RequestID = request.RequestID
					candidate.Operation = request.Operation
					return candidate, nil
				})})
				if err != nil {
					t.Fatal(err)
				}
				if err := operationCase.invoke(client); err == nil {
					t.Fatal("V2 client ignored a smuggled successful response payload")
				}
			})
		}
	}
}

type l8WorkerV2ResponsePointerFixture struct {
	name   string
	attach func(*Response)
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

func TestL8WorkerV2ClientRejectsCorrelatedJobResponseMismatch(t *testing.T) {
	start := l8WorkerV2StartRequest()
	jobID := l8WorkerV2QueuedJob().ID
	tests := []struct {
		name   string
		mutate func(*JobV2)
		invoke func(*Client) error
	}{
		{name: "start runtime driver", mutate: func(job *JobV2) { job.RuntimeDriver = RuntimeDriverRootlessPodman }, invoke: func(client *Client) error {
			_, err := client.JobStartV2(context.Background(), RuntimeDriverMicroVM, start)
			return err
		}},
		{name: "start runtime id", mutate: func(job *JobV2) { job.RuntimeID = "runtime-neighbor" }, invoke: func(client *Client) error {
			_, err := client.JobStartV2(context.Background(), RuntimeDriverMicroVM, start)
			return err
		}},
		{name: "status job id", mutate: func(job *JobV2) { job.ID = "job-neighbor" }, invoke: func(client *Client) error {
			_, err := client.JobStatusV2(context.Background(), JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: jobID})
			return err
		}},
		{name: "cancel job id", mutate: func(job *JobV2) { job.ID = "job-neighbor" }, invoke: func(client *Client) error {
			_, err := client.JobCancelV2(context.Background(), JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: jobID})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			job := l8WorkerV2QueuedJob()
			test.mutate(&job)
			if err := job.Validate(); err != nil {
				t.Fatalf("internally valid mismatched V2 job fixture: %v", err)
			}
			client := l8WorkerV2ClientReturningJob(t, &job)
			if err := test.invoke(client); err == nil {
				t.Fatal("V2 client accepted a mismatched successful job response")
			}
		})
	}
}

func TestL8WorkerV2ClientResolveValidatesOnlyAvailableOpaqueSubmissionIdentity(t *testing.T) {
	start := l8WorkerV2StartRequest()
	request := JobResolveRequestV2{ContractVersion: JobContractVersionV2, SubmissionID: start.SubmissionID}

	// The public resolve request does not carry the server-derived principal or
	// credential intent needed to recompute the V2 submission key. The client can
	// therefore validate only the opaque key's required domain and shape.
	validOpaque := l8WorkerV2QueuedJob()
	validOpaque.SubmissionKey = jobSubmissionKeyV2("principal-neighbor", start)
	if err := validOpaque.Validate(); err != nil {
		t.Fatalf("valid opaque resolve response fixture: %v", err)
	}
	if _, err := l8WorkerV2ClientReturningJob(t, &validOpaque).JobResolveV2(context.Background(), request); err != nil {
		t.Fatalf("resolve rejected valid server-derived opaque submission identity: %v", err)
	}

	for _, invalid := range []struct {
		name string
		key  string
	}{
		{name: "missing", key: ""},
		{name: "wrong domain", key: "request-v2-" + strings.Repeat("0", 64)},
	} {
		t.Run(invalid.name, func(t *testing.T) {
			job := l8WorkerV2QueuedJob()
			job.SubmissionKey = invalid.key
			if _, err := l8WorkerV2ClientReturningJob(t, &job).JobResolveV2(context.Background(), request); err == nil {
				t.Fatal("resolve accepted an invalid opaque submission identity")
			}
		})
	}
}

func TestL8WorkerV2ClientRejectsLogIdentityCursorAndLimitMismatch(t *testing.T) {
	request := JobLogsRequestV2{
		ContractVersion: JobContractVersionV2,
		JobID:           "job-primary",
		Cursor:          4,
		LimitBytes:      DefaultJobLogRecordBytes,
	}
	record := func(cursor uint64, data string) JobLogRecord {
		return JobLogRecord{
			Cursor:    cursor,
			Stream:    JobLogStreamStdout,
			Data:      data,
			Timestamp: time.Date(2026, time.August, 3, 4, 5, 6, 0, time.UTC),
		}
	}
	tests := []struct {
		name     string
		response JobLogsResponseV2
	}{
		{name: "job id", response: JobLogsResponseV2{JobID: "job-neighbor", NextCursor: 4}},
		{name: "next cursor regresses", response: JobLogsResponseV2{JobID: request.JobID, NextCursor: 3}},
		{name: "record replays cursor", response: JobLogsResponseV2{JobID: request.JobID, Records: []JobLogRecord{record(4, "safe")}, NextCursor: 4}},
		{name: "unexplained record gap", response: JobLogsResponseV2{JobID: request.JobID, Records: []JobLogRecord{record(6, "safe")}, NextCursor: 6}},
		{name: "unexplained next cursor gap", response: JobLogsResponseV2{JobID: request.JobID, NextCursor: 5}},
		{name: "records exceed request limit", response: JobLogsResponseV2{
			JobID: request.JobID,
			Records: []JobLogRecord{
				record(5, strings.Repeat("a", int(request.LimitBytes/2)+1)),
				record(6, strings.Repeat("b", int(request.LimitBytes/2)+1)),
			},
			NextCursor: 6,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := test.response
			response.ContractVersion = JobContractVersionV2
			if err := response.Validate(); err != nil {
				t.Fatalf("internally valid mismatched V2 log fixture: %v", err)
			}
			client := l8WorkerV2ClientReturningLogs(t, &response)
			if _, err := client.JobLogsV2(context.Background(), request); err == nil {
				t.Fatal("V2 client accepted mismatched log identity/cursor/limit response")
			}
		})
	}

	for _, valid := range []JobLogsResponseV2{
		{ContractVersion: JobContractVersionV2, JobID: request.JobID, Records: []JobLogRecord{record(5, "safe")}, NextCursor: 5},
		{ContractVersion: JobContractVersionV2, JobID: request.JobID, Records: []JobLogRecord{record(6, "safe")}, NextCursor: 7, Truncated: true},
	} {
		if _, err := l8WorkerV2ClientReturningLogs(t, &valid).JobLogsV2(context.Background(), request); err != nil {
			t.Fatalf("V2 client rejected valid cursor response: %v", err)
		}
	}
}

func l8WorkerV2ClientReturningJob(t *testing.T, job *JobV2) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, request Request) (Response, error) {
		return Response{
			ProtocolVersion: ProtocolVersion,
			RequestID:       request.RequestID,
			Operation:       request.Operation,
			OK:              true,
			JobV2:           job,
		}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func l8WorkerV2ClientReturningLogs(t *testing.T, logs *JobLogsResponseV2) *Client {
	t.Helper()
	client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, request Request) (Response, error) {
		return Response{
			ProtocolVersion: ProtocolVersion,
			RequestID:       request.RequestID,
			Operation:       request.Operation,
			OK:              true,
			JobLogsV2:       logs,
		}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestL8WorkerV2ClientTreatsUnsupportedAsTerminalForAllFiveOperationsWithoutFallback(t *testing.T) {
	tests := l8WorkerV2ClientOperationCases()
	responders := []struct {
		name string
		make func(Request) Response
	}{
		{name: "legacy daemon", make: l8LegacyUnsupportedV2Response},
		{name: "new daemon", make: l8NewUnsupportedV2Response},
	}
	for _, tt := range tests {
		for _, responder := range responders {
			t.Run(tt.operation+"/"+responder.name, func(t *testing.T) {
				calls := 0
				var captured Request
				client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
					calls++
					captured = req
					return responder.make(req), nil
				})})
				if err != nil {
					t.Fatal(err)
				}
				if err := tt.invoke(client); !errors.Is(err, ErrCredentialWorkerProtocolUnsupported) {
					t.Fatalf("%s error = %v, want terminal credential worker protocol unsupported", tt.operation, err)
				}
				if calls != 1 {
					t.Fatalf("%s calls = %d, want one v2 attempt and no fallback", tt.operation, calls)
				}
				if captured.Operation != tt.operation {
					t.Fatalf("captured operation = %q, want %q", captured.Operation, tt.operation)
				}
				if !l8WorkerV2RequestHasOnlyMatchingPayload(captured) {
					t.Fatalf("%s request did not contain exactly its matching v2 payload: %#v", tt.operation, captured)
				}
				if captured.JobStart != nil || captured.JobResolve != nil || captured.JobStatus != nil || captured.JobLogs != nil || captured.JobCancel != nil {
					t.Fatalf("%s request populated a v1 fallback payload: %#v", tt.operation, captured)
				}
			})
		}
	}
}

type l8WorkerV2ClientOperationCase struct {
	operation   string
	v1Operation string
	invoke      func(*Client) error
}

func l8WorkerV2ClientOperationCases() []l8WorkerV2ClientOperationCase {
	start := l8WorkerV2StartRequest()
	job := l8WorkerV2QueuedJob()
	return []l8WorkerV2ClientOperationCase{
		{operation: OperationJobStartV2, v1Operation: OperationJobStart, invoke: func(client *Client) error {
			_, err := client.JobStartV2(context.Background(), RuntimeDriverMicroVM, start)
			return err
		}},
		{operation: OperationJobResolveV2, v1Operation: OperationJobResolve, invoke: func(client *Client) error {
			_, err := client.JobResolveV2(context.Background(), JobResolveRequestV2{ContractVersion: JobContractVersionV2, SubmissionID: start.SubmissionID})
			return err
		}},
		{operation: OperationJobStatusV2, v1Operation: OperationJobStatus, invoke: func(client *Client) error {
			_, err := client.JobStatusV2(context.Background(), JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: job.ID})
			return err
		}},
		{operation: OperationJobLogsV2, v1Operation: OperationJobLogs, invoke: func(client *Client) error {
			_, err := client.JobLogsV2(context.Background(), JobLogsRequestV2{ContractVersion: JobContractVersionV2, JobID: job.ID, LimitBytes: DefaultJobLogRecordBytes})
			return err
		}},
		{operation: OperationJobCancelV2, v1Operation: OperationJobCancel, invoke: func(client *Client) error {
			_, err := client.JobCancelV2(context.Background(), JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: job.ID})
			return err
		}},
	}
}

func l8WorkerV2RequestHasOnlyMatchingPayload(req Request) bool {
	v2Payloads := []bool{
		req.JobStartV2 != nil,
		req.JobResolveV2 != nil,
		req.JobStatusV2 != nil,
		req.JobLogsV2 != nil,
		req.JobCancelV2 != nil,
	}
	wantIndex, knownOperation := map[string]int{
		OperationJobStartV2:   0,
		OperationJobResolveV2: 1,
		OperationJobStatusV2:  2,
		OperationJobLogsV2:    3,
		OperationJobCancelV2:  4,
	}[req.Operation]
	if !knownOperation {
		return false
	}
	for index, populated := range v2Payloads {
		if populated != (index == wantIndex) {
			return false
		}
	}
	return true
}

func TestL8WorkerV2FakeDispatcherRoutesAllFiveOperations(t *testing.T) {
	start := l8WorkerV2StartRequest()
	requests := []Request{
		{ProtocolVersion: ProtocolVersion, RequestID: "request-start-v2", Operation: OperationJobStartV2, DriverID: RuntimeDriverMicroVM, JobStartV2: &start},
		{ProtocolVersion: ProtocolVersion, RequestID: "request-resolve-v2", Operation: OperationJobResolveV2, JobResolveV2: &JobResolveRequestV2{ContractVersion: JobContractVersionV2, SubmissionID: start.SubmissionID}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request-status-v2", Operation: OperationJobStatusV2, JobStatusV2: &JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary"}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request-logs-v2", Operation: OperationJobLogsV2, JobLogsV2: &JobLogsRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary", LimitBytes: DefaultJobLogRecordBytes}},
		{ProtocolVersion: ProtocolVersion, RequestID: "request-cancel-v2", Operation: OperationJobCancelV2, JobCancelV2: &JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary"}},
	}
	wantOperations := []string{OperationJobStartV2, OperationJobResolveV2, OperationJobStatusV2, OperationJobLogsV2, OperationJobCancelV2}
	var gotOperations []string
	dispatcher := RequestHandlerFunc(func(_ context.Context, req Request) Response {
		gotOperations = append(gotOperations, req.Operation)
		return Response{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID, Operation: req.Operation, OK: false, Error: &Error{Code: ErrorCodeUnsupportedOp, Message: "worker v2 fake terminal"}}
	})
	server := &Server{handler: dispatcher, maxRequestBytes: defaultMaxRequestBytes}
	for _, want := range requests {
		payload, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		decoded, errorResp := server.readRequest(bytes.NewReader(payload))
		if errorResp != nil {
			t.Fatalf("decode %s: %#v", want.Operation, errorResp)
		}
		response := server.handler.HandleRequest(context.Background(), decoded)
		if response.RequestID != want.RequestID || response.Operation != want.Operation {
			t.Fatalf("dispatch response = %#v, want requestId=%q operation=%q", response, want.RequestID, want.Operation)
		}
	}
	if !reflect.DeepEqual(gotOperations, wantOperations) {
		t.Fatalf("fake dispatcher operations = %v, want %v", gotOperations, wantOperations)
	}
}

func TestL8WorkerV2ClientUsesEveryDistinctOperationWithoutMutatingIntent(t *testing.T) {
	start := l8WorkerV2StartRequest()
	wantStart := l8CloneWorkerV2StartRequest(start)
	job := l8WorkerV2QueuedJob()
	var operations []string
	client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
		operations = append(operations, req.Operation)
		if req.ProtocolVersion != ProtocolVersion {
			t.Fatalf("outer protocol version = %q, want unchanged %q", req.ProtocolVersion, ProtocolVersion)
		}
		response := Response{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID, Operation: req.Operation, OK: true}
		switch req.Operation {
		case OperationJobStartV2:
			if req.JobStartV2 == nil || !reflect.DeepEqual(*req.JobStartV2, wantStart) {
				t.Fatalf("job_start_v2 request = %#v, want exact credential intent %#v", req.JobStartV2, wantStart)
			}
			response.JobV2 = &job
		case OperationJobResolveV2:
			response.JobV2 = &job
		case OperationJobStatusV2:
			response.JobV2 = &job
		case OperationJobLogsV2:
			response.JobLogsV2 = &JobLogsResponseV2{ContractVersion: JobContractVersionV2, JobID: job.ID}
		case OperationJobCancelV2:
			response.JobV2 = &job
		default:
			t.Fatalf("v2 client attempted unexpected operation %q", req.Operation)
		}
		return response, nil
	})})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.JobStartV2(context.Background(), RuntimeDriverMicroVM, start); err != nil {
		t.Fatalf("JobStartV2: %v", err)
	}
	if _, err := client.JobResolveV2(context.Background(), JobResolveRequestV2{ContractVersion: JobContractVersionV2, SubmissionID: start.SubmissionID}); err != nil {
		t.Fatalf("JobResolveV2: %v", err)
	}
	if _, err := client.JobStatusV2(context.Background(), JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: job.ID}); err != nil {
		t.Fatalf("JobStatusV2: %v", err)
	}
	if _, err := client.JobLogsV2(context.Background(), JobLogsRequestV2{ContractVersion: JobContractVersionV2, JobID: job.ID, LimitBytes: DefaultJobLogRecordBytes}); err != nil {
		t.Fatalf("JobLogsV2: %v", err)
	}
	if _, err := client.JobCancelV2(context.Background(), JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: job.ID}); err != nil {
		t.Fatalf("JobCancelV2: %v", err)
	}

	wantOperations := []string{OperationJobStartV2, OperationJobResolveV2, OperationJobStatusV2, OperationJobLogsV2, OperationJobCancelV2}
	if !reflect.DeepEqual(operations, wantOperations) {
		t.Fatalf("v2 client operations = %v, want %v", operations, wantOperations)
	}
}

func TestL8WorkerV2ClientTreatsOnlyExactUnsupportedResponsesAsTerminal(t *testing.T) {
	v1Job := l8WorkerV1ValidQueuedJob(t)
	responders := []struct {
		name string
		make func(Request) Response
	}{
		{name: "legacy daemon", make: l8LegacyUnsupportedV2Response},
		{name: "new daemon", make: l8NewUnsupportedV2Response},
	}
	mutations := []struct {
		name                   string
		mutate                 func(*testing.T, Response, Request) Response
		wantUnsupported        bool
		wantMalformed          bool
		wantPayloadCorrelation bool
	}{
		{name: "exact", mutate: func(_ *testing.T, response Response, _ Request) Response { return response }, wantUnsupported: true},
		{name: "wrong request id", mutate: func(_ *testing.T, response Response, _ Request) Response {
			response.RequestID = "request-neighbor"
			return response
		}},
		{name: "missing or empty request id", mutate: func(_ *testing.T, response Response, _ Request) Response {
			response.RequestID = ""
			return response
		}, wantMalformed: true},
		{name: "wrong operation", mutate: func(_ *testing.T, response Response, request Request) Response {
			if response.Operation == request.Operation {
				response.Operation = OperationProtocolError
			} else {
				response.Operation = request.Operation
			}
			return response
		}},
		{name: "wrong code", mutate: func(_ *testing.T, response Response, _ Request) Response {
			response.Error.Code = ErrorCodeInternal
			return response
		}},
		{name: "wrong message", mutate: func(_ *testing.T, response Response, _ Request) Response {
			response.Error.Message = "worker protocol is unavailable"
			return response
		}},
		{name: "wrong protocol", mutate: func(_ *testing.T, response Response, _ Request) Response {
			response.ProtocolVersion = "sandboxworker-neighbor"
			return response
		}},
		{name: "wrong ok", mutate: func(_ *testing.T, response Response, _ Request) Response {
			response.OK = true
			return response
		}},
		{name: "unexpected v1 payload", mutate: func(_ *testing.T, response Response, _ Request) Response {
			response.Job = &v1Job
			return response
		}},
		{name: "operation matching v2 payload", mutate: l8WorkerV2AttachValidMatchingResponsePayload},
	}
	for _, fixture := range l8WorkerV2ValidNonJobResponsePointerFixtures(t) {
		fixture := fixture
		mutations = append(mutations, struct {
			name                   string
			mutate                 func(*testing.T, Response, Request) Response
			wantUnsupported        bool
			wantMalformed          bool
			wantPayloadCorrelation bool
		}{
			name: "unexpected " + fixture.name,
			mutate: func(_ *testing.T, response Response, _ Request) Response {
				fixture.attach(&response)
				return response
			},
			wantPayloadCorrelation: true,
		})
	}

	for _, operation := range l8WorkerV2ClientOperationCases() {
		for _, responder := range responders {
			for _, mutation := range mutations {
				t.Run(operation.operation+"/"+responder.name+"/"+mutation.name, func(t *testing.T) {
					calls := 0
					var captured []Request
					client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, request Request) (Response, error) {
						calls++
						captured = append(captured, request)
						response := responder.make(request)
						l8AssertWorkerV2UnsupportedResponsePayloadFree(t, response)
						candidate := mutation.mutate(t, response, request)
						if mutation.wantPayloadCorrelation {
							if validationErr := candidate.Validate(); validationErr == nil {
								t.Errorf("exact unsupported response accepted an unexpected legacy payload")
							}
						}
						return candidate, nil
					})})
					if err != nil {
						t.Fatal(err)
					}
					invokeErr := operation.invoke(client)
					if mutation.wantUnsupported {
						if !errors.Is(invokeErr, ErrCredentialWorkerProtocolUnsupported) {
							t.Fatalf("error = %v, want terminal credential worker protocol unsupported", invokeErr)
						}
					} else if invokeErr == nil || errors.Is(invokeErr, ErrCredentialWorkerProtocolUnsupported) {
						t.Fatalf("mismatched response error = %v, want malformed non-admission error", invokeErr)
					}
					if mutation.wantMalformed {
						var malformed *ClientError
						if !errors.As(invokeErr, &malformed) || malformed.Code != ErrorCodeMalformedRequest {
							t.Fatalf("missing response request id error = %v, want malformed client response", invokeErr)
						}
					}
					l8AssertWorkerV2SingleAttemptWithoutFallback(t, calls, captured, operation.operation)
				})
			}
		}

		t.Run(operation.operation+"/valid v1 success is not admission", func(t *testing.T) {
			calls := 0
			var captured []Request
			client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, request Request) (Response, error) {
				calls++
				captured = append(captured, request)
				return l8WorkerV1ValidSuccessResponse(t, operation.v1Operation, request.RequestID, v1Job), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			invokeErr := operation.invoke(client)
			if invokeErr == nil || errors.Is(invokeErr, ErrCredentialWorkerProtocolUnsupported) {
				t.Fatalf("valid v1 success error = %v, want malformed non-admission error", invokeErr)
			}
			l8AssertWorkerV2SingleAttemptWithoutFallback(t, calls, captured, operation.operation)
		})
	}
}

func l8WorkerV2AttachValidMatchingResponsePayload(t *testing.T, response Response, request Request) Response {
	t.Helper()
	switch request.Operation {
	case OperationJobLogsV2:
		payload := JobLogsResponseV2{
			ContractVersion: JobContractVersionV2,
			JobID:           request.JobLogsV2.JobID,
			NextCursor:      request.JobLogsV2.Cursor,
		}
		if err := payload.Validate(); err != nil {
			t.Fatalf("valid matching V2 logs payload fixture: %v", err)
		}
		response.JobLogsV2 = &payload
	case OperationJobStartV2, OperationJobResolveV2, OperationJobStatusV2, OperationJobCancelV2:
		job := l8WorkerV2QueuedJob()
		if err := job.Validate(); err != nil {
			t.Fatalf("valid matching V2 job payload fixture: %v", err)
		}
		response.JobV2 = &job
	default:
		t.Fatalf("matching V2 payload fixture received unknown operation %q", request.Operation)
	}
	return response
}

func l8AssertWorkerV2UnsupportedResponsePayloadFree(t *testing.T, response Response) {
	t.Helper()
	value := reflect.ValueOf(response)
	typ := value.Type()
	for index := 0; index < value.NumField(); index++ {
		field := typ.Field(index)
		if field.Name == "Error" || field.Type.Kind() != reflect.Ptr {
			continue
		}
		if !value.Field(index).IsNil() {
			t.Fatalf("exact unsupported response populated payload field %s: %#v", field.Name, response)
		}
	}
}

func l8AssertWorkerV2SingleAttemptWithoutFallback(t *testing.T, calls int, captured []Request, operation string) {
	t.Helper()
	if calls != 1 || len(captured) != 1 {
		t.Fatalf("transport calls = %d and captures = %d, want exactly one V2 attempt", calls, len(captured))
	}
	request := captured[0]
	if request.Operation != operation || !l8WorkerV2RequestHasOnlyMatchingPayload(request) {
		t.Fatalf("request = %#v, want exact %s V2 payload", request, operation)
	}
	if request.JobStart != nil || request.JobResolve != nil || request.JobStatus != nil || request.JobLogs != nil || request.JobCancel != nil {
		t.Fatalf("request populated a v1 fallback payload: %#v", request)
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

func l8WorkerV1ValidSuccessResponse(t *testing.T, operation, requestID string, job Job) Response {
	t.Helper()
	response := Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       requestID,
		Operation:       operation,
		OK:              true,
	}
	if operation == OperationJobLogs {
		logs := JobLogsResponse{
			ContractVersion: JobContractVersion,
			JobID:           job.ID,
			NextCursor:      0,
		}
		if err := logs.Validate(); err != nil {
			t.Fatalf("valid v1 log success fixture: %v", err)
		}
		response.JobLogs = &logs
		return response
	}
	response.Job = &job
	return response
}

func TestL8WorkerV2ClientAcceptsEquivalentReorderedCredentialIdentity(t *testing.T) {
	start := l8WorkerV2StartRequest()
	start.SourceReferenceIDs = append(start.SourceReferenceIDs, "source-secondary", "source-tertiary")
	start.Bindings = append(start.Bindings,
		JobCredentialBindingV2{
			BindingID:         "binding-secondary",
			SourceReferenceID: "source-secondary",
			Mode:              CredentialModeFileTmpfs,
		},
		JobCredentialBindingV2{
			BindingID:         "binding-tertiary",
			SourceReferenceID: "source-tertiary",
			Mode:              CredentialModeSSHAgent,
		},
	)
	if err := start.Validate(); err != nil {
		t.Fatalf("valid multi-source V2 request fixture: %v", err)
	}
	originalRequest := l8CloneWorkerV2StartRequest(start)

	job := l8WorkerV2QueuedJob()
	job.SubmissionKey = jobSubmissionKeyV2("principal-owner", start)
	job.CredentialIntent = JobCredentialIntentV2{
		ProductionCredentialsRequested: start.ProductionCredentialsRequested,
		PlanID:                         start.PlanID,
		AdmissionGrantID:               start.AdmissionGrantID,
		AdmissionGrantRevision:         start.AdmissionGrantRevision,
		TemplatePolicyID:               start.TemplatePolicyID,
		WorkspacePolicyID:              start.WorkspacePolicyID,
		SourceReferenceIDs:             append([]string(nil), start.SourceReferenceIDs...),
		Bindings:                       append([]JobCredentialBindingV2(nil), start.Bindings...),
	}
	job.CredentialIntent.SourceReferenceIDs = []string{"source-secondary", "source-primary", "source-tertiary"}
	job.CredentialIntent.Bindings = []JobCredentialBindingV2{
		start.Bindings[2],
		start.Bindings[0],
		start.Bindings[1],
	}
	if err := job.Validate(); err != nil {
		t.Fatalf("valid independently reordered V2 response fixture: %v", err)
	}
	originalResponse := l8CloneWorkerV2Job(job)

	client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, request Request) (Response, error) {
		if request.JobStartV2 == nil || !reflect.DeepEqual(*request.JobStartV2, originalRequest) {
			t.Fatalf("multi-source V2 request mutated before transport: %#v", request.JobStartV2)
		}
		return Response{
			ProtocolVersion: ProtocolVersion,
			RequestID:       request.RequestID,
			Operation:       request.Operation,
			OK:              true,
			JobV2:           &job,
		}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.JobStartV2(context.Background(), RuntimeDriverMicroVM, start)
	if err != nil {
		t.Fatalf("semantically equivalent reordered credential identity: %v", err)
	}
	if result == nil || result.ID != job.ID {
		t.Fatalf("accepted reordered V2 response = %#v, want job %q", result, job.ID)
	}
	if !reflect.DeepEqual(start, originalRequest) {
		t.Fatalf("V2 client mutated original multi-source request: got %#v want %#v", start, originalRequest)
	}
	if !reflect.DeepEqual(job, originalResponse) {
		t.Fatalf("V2 client mutated original reordered response: got %#v want %#v", job, originalResponse)
	}
}

func TestL8WorkerV2ClientRejectsCredentialIdentityResponseMismatch(t *testing.T) {
	start := l8WorkerV2StartRequest()
	mutations := []struct {
		name   string
		mutate func(*JobCredentialIntentV2)
	}{
		{name: "production intent", mutate: func(intent *JobCredentialIntentV2) {
			intent.ProductionCredentialsRequested = false
			intent.PlanID = ""
			intent.AdmissionGrantID = ""
			intent.AdmissionGrantRevision = 0
			intent.TemplatePolicyID = ""
			intent.WorkspacePolicyID = ""
			intent.SourceReferenceIDs = nil
			intent.Bindings = nil
		}},
		{name: "plan", mutate: func(intent *JobCredentialIntentV2) { intent.PlanID = "plan-neighbor" }},
		{name: "grant", mutate: func(intent *JobCredentialIntentV2) { intent.AdmissionGrantID = "grant-neighbor" }},
		{name: "revision", mutate: func(intent *JobCredentialIntentV2) { intent.AdmissionGrantRevision++ }},
		{name: "template policy", mutate: func(intent *JobCredentialIntentV2) { intent.TemplatePolicyID = "template-neighbor" }},
		{name: "workspace policy", mutate: func(intent *JobCredentialIntentV2) { intent.WorkspacePolicyID = "workspace-neighbor" }},
		{name: "source reference and linked binding", mutate: func(intent *JobCredentialIntentV2) {
			intent.SourceReferenceIDs[0] = "source-neighbor"
			intent.Bindings[0].SourceReferenceID = "source-neighbor"
		}},
		{name: "binding", mutate: func(intent *JobCredentialIntentV2) { intent.Bindings[0].BindingID = "binding-neighbor" }},
		{name: "mode", mutate: func(intent *JobCredentialIntentV2) {
			intent.Bindings[0].Mode = CredentialModeSSHAgent
			intent.Bindings[0].ServiceID = ""
		}},
		{name: "service", mutate: func(intent *JobCredentialIntentV2) { intent.Bindings[0].ServiceID = "service-neighbor" }},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			job := l8WorkerV2QueuedJob()
			intent := l8CloneWorkerV2Intent(job.CredentialIntent)
			tt.mutate(&intent)
			job.CredentialIntent = intent
			if err := job.Validate(); err != nil {
				t.Fatalf("internally valid mutated response fixture: %v", err)
			}
			client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
				return Response{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID, Operation: req.Operation, OK: true, JobV2: &job}, nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.JobStartV2(context.Background(), RuntimeDriverMicroVM, start); err == nil || strings.Contains(err.Error(), "neighbor") {
				t.Fatalf("credential mismatch error = %v, want sanitized malformed response", err)
			}
		})
	}
}

func l8CloneWorkerV2Job(job JobV2) JobV2 {
	job.CredentialIntent = l8CloneWorkerV2Intent(job.CredentialIntent)
	return job
}

func l8LegacyUnsupportedV2Response(req Request) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       req.RequestID,
		Operation:       OperationProtocolError,
		OK:              false,
		Error: &Error{
			Code:    ErrorCodeMalformedRequest,
			Message: `malformed worker request: worker request operation "` + req.Operation + `" is unsupported`,
		},
	}
}

func l8NewUnsupportedV2Response(req Request) Response {
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       req.RequestID,
		Operation:       req.Operation,
		OK:              false,
		Error: &Error{
			Code:    ErrorCodeUnsupportedOp,
			Message: `worker operation "` + req.Operation + `" is not supported by this worker service`,
		},
	}
}

func l8WorkerV2QueuedJob() JobV2 {
	request := l8WorkerV2StartRequest()
	intent := JobCredentialIntentV2{
		ProductionCredentialsRequested: true,
		PlanID:                         "plan-primary",
		AdmissionGrantID:               "grant-primary",
		AdmissionGrantRevision:         9,
		TemplatePolicyID:               "template-primary",
		WorkspacePolicyID:              "workspace-primary",
		SourceReferenceIDs:             []string{"source-primary"},
		Bindings: []JobCredentialBindingV2{{
			BindingID:         "binding-primary",
			SourceReferenceID: "source-primary",
			Mode:              "http_proxy",
			ServiceID:         "azure-openai-responses-v1",
		}},
	}
	return JobV2{
		ContractVersion:  JobContractVersionV2,
		ID:               "job-primary",
		SubmissionKey:    jobSubmissionKeyV2("principal-owner", request),
		WorkerID:         "worker-primary",
		HostID:           "host-primary",
		RuntimeDriver:    RuntimeDriverMicroVM,
		RuntimeID:        "runtime-primary",
		State:            JobStateQueued,
		SubmittedAt:      time.Date(2026, time.August, 3, 1, 2, 3, 0, time.UTC),
		CredentialIntent: intent,
	}
}

func l8CloneWorkerV2Intent(intent JobCredentialIntentV2) JobCredentialIntentV2 {
	intent.SourceReferenceIDs = append([]string(nil), intent.SourceReferenceIDs...)
	intent.Bindings = append([]JobCredentialBindingV2(nil), intent.Bindings...)
	return intent
}
