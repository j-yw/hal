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
	start := l8WorkerV2StartRequest()
	resolve := JobResolveRequestV2{ContractVersion: JobContractVersionV2, SubmissionID: start.SubmissionID}
	status := JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary"}
	logs := JobLogsRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary", Cursor: 0, LimitBytes: DefaultJobLogRecordBytes}
	cancel := JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: "job-primary"}
	v1Start := JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    "submission-v1-valid",
		Exec:            l8WorkerV2ExecRequest(),
	}
	if err := v1Start.Validate(); err != nil {
		t.Fatalf("valid v1 mismatch fixture: %v", err)
	}

	tests := []struct {
		name string
		req  Request
	}{
		{name: OperationJobStartV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-start-v2", Operation: OperationJobStartV2, DriverID: RuntimeDriverMicroVM, JobStartV2: &start}},
		{name: OperationJobResolveV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-resolve-v2", Operation: OperationJobResolveV2, JobResolveV2: &resolve}},
		{name: OperationJobStatusV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-status-v2", Operation: OperationJobStatusV2, JobStatusV2: &status}},
		{name: OperationJobLogsV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-logs-v2", Operation: OperationJobLogsV2, JobLogsV2: &logs}},
		{name: OperationJobCancelV2, req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-cancel-v2", Operation: OperationJobCancelV2, JobCancelV2: &cancel}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.req.Validate(); err != nil {
				t.Fatalf("valid v2 dispatch request: %v", err)
			}
		})
	}

	invalid := []Request{
		{ProtocolVersion: ProtocolVersion, RequestID: "request-invalid-v2-payload", Operation: OperationJobStartV2, DriverID: RuntimeDriverMicroVM, JobStart: &v1Start},
		{ProtocolVersion: ProtocolVersion, RequestID: "request-invalid-v1-operation", Operation: OperationJobStart, DriverID: RuntimeDriverMicroVM, JobStartV2: &start},
		{ProtocolVersion: ProtocolVersion, RequestID: "request-invalid-ambiguous-start", Operation: OperationJobStartV2, DriverID: RuntimeDriverMicroVM, JobStartV2: &start, JobStatusV2: &status},
		{ProtocolVersion: ProtocolVersion, RequestID: "request-invalid-ambiguous-status", Operation: OperationJobStatusV2, JobStartV2: &start, JobStatusV2: &status},
	}
	for index, req := range invalid {
		if err := req.Validate(); err == nil {
			t.Fatalf("mismatched or ambiguous payload %d was accepted", index)
		}
	}
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
		name            string
		mutate          func(*testing.T, Response, Request) Response
		wantUnsupported bool
	}{
		{name: "exact", mutate: func(_ *testing.T, response Response, _ Request) Response { return response }, wantUnsupported: true},
		{name: "wrong request id", mutate: func(_ *testing.T, response Response, _ Request) Response {
			response.RequestID = "request-neighbor"
			return response
		}},
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
						return mutation.mutate(t, response, request), nil
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
