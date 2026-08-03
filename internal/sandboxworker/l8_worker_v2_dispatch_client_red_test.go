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
		{ProtocolVersion: ProtocolVersion, RequestID: "request-invalid-v2-payload", Operation: OperationJobStartV2, DriverID: RuntimeDriverMicroVM, JobStart: &JobStartRequest{}},
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
	start := l8WorkerV2StartRequest()
	job := l8WorkerV2QueuedJob()
	tests := []struct {
		operation string
		invoke    func(*Client) error
	}{
		{operation: OperationJobStartV2, invoke: func(client *Client) error {
			_, err := client.JobStartV2(context.Background(), RuntimeDriverMicroVM, start)
			return err
		}},
		{operation: OperationJobResolveV2, invoke: func(client *Client) error {
			_, err := client.JobResolveV2(context.Background(), JobResolveRequestV2{ContractVersion: JobContractVersionV2, SubmissionID: start.SubmissionID})
			return err
		}},
		{operation: OperationJobStatusV2, invoke: func(client *Client) error {
			_, err := client.JobStatusV2(context.Background(), JobStatusRequestV2{ContractVersion: JobContractVersionV2, JobID: job.ID})
			return err
		}},
		{operation: OperationJobLogsV2, invoke: func(client *Client) error {
			_, err := client.JobLogsV2(context.Background(), JobLogsRequestV2{ContractVersion: JobContractVersionV2, JobID: job.ID, LimitBytes: DefaultJobLogRecordBytes})
			return err
		}},
		{operation: OperationJobCancelV2, invoke: func(client *Client) error {
			_, err := client.JobCancelV2(context.Background(), JobCancelRequestV2{ContractVersion: JobContractVersionV2, JobID: job.ID})
			return err
		}},
	}
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
	start := l8WorkerV2StartRequest()
	tests := []struct {
		name            string
		response        func(Request) Response
		wantUnsupported bool
	}{
		{
			name: "exact legacy daemon envelope",
			response: func(req Request) Response {
				return Response{
					ProtocolVersion: ProtocolVersion,
					RequestID:       req.RequestID,
					Operation:       OperationProtocolError,
					OK:              false,
					Error: &Error{
						Code:    ErrorCodeMalformedRequest,
						Message: `malformed worker request: worker request operation "job_start_v2" is unsupported`,
					},
				}
			},
			wantUnsupported: true,
		},
		{
			name: "exact new daemon envelope",
			response: func(req Request) Response {
				return Response{
					ProtocolVersion: ProtocolVersion,
					RequestID:       req.RequestID,
					Operation:       OperationJobStartV2,
					OK:              false,
					Error: &Error{
						Code:    ErrorCodeUnsupportedOp,
						Message: `worker operation "job_start_v2" is not supported by this worker service`,
					},
				}
			},
			wantUnsupported: true,
		},
		{
			name: "legacy wrong request id",
			response: func(req Request) Response {
				resp := l8LegacyUnsupportedV2Response(req)
				resp.RequestID = "request-neighbor"
				return resp
			},
		},
		{
			name: "legacy wrong message",
			response: func(req Request) Response {
				resp := l8LegacyUnsupportedV2Response(req)
				resp.Error.Message = "malformed worker request"
				return resp
			},
		},
		{
			name: "new daemon wrong operation",
			response: func(req Request) Response {
				resp := l8NewUnsupportedV2Response(req)
				resp.Operation = OperationJobStatusV2
				return resp
			},
		},
		{
			name: "v1 success is not admission",
			response: func(req Request) Response {
				job := Job{ContractVersion: JobContractVersion}
				return Response{ProtocolVersion: ProtocolVersion, RequestID: req.RequestID, Operation: OperationJobStart, OK: true, Job: &job}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			var captured Request
			client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
				calls++
				captured = req
				return tt.response(req), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.JobStartV2(context.Background(), RuntimeDriverMicroVM, start)
			if tt.wantUnsupported {
				if !errors.Is(err, ErrCredentialWorkerProtocolUnsupported) {
					t.Fatalf("error = %v, want terminal credential worker protocol unsupported", err)
				}
			} else {
				if err == nil || errors.Is(err, ErrCredentialWorkerProtocolUnsupported) {
					t.Fatalf("mismatched response error = %v, want malformed non-admission error", err)
				}
			}
			if calls != 1 {
				t.Fatalf("v2 client attempts = %d, want exactly one with no v1 retry", calls)
			}
			if captured.Operation != OperationJobStartV2 || captured.JobStartV2 == nil || captured.JobStart != nil {
				t.Fatalf("v2 client downgraded or stripped request: %#v", captured)
			}
			if !captured.JobStartV2.ProductionCredentialsRequested || captured.JobStartV2.AdmissionGrantID != start.AdmissionGrantID || !reflect.DeepEqual(captured.JobStartV2.Bindings, start.Bindings) {
				t.Fatalf("v2 client stripped credential intent: %#v", captured.JobStartV2)
			}
		})
	}
}

func TestL8WorkerV2ClientRejectsCredentialIdentityResponseMismatch(t *testing.T) {
	start := l8WorkerV2StartRequest()
	mutations := []struct {
		name   string
		mutate func(*JobCredentialIntentV2)
	}{
		{name: "production intent", mutate: func(intent *JobCredentialIntentV2) { intent.ProductionCredentialsRequested = false }},
		{name: "plan", mutate: func(intent *JobCredentialIntentV2) { intent.PlanID = "plan-neighbor" }},
		{name: "grant", mutate: func(intent *JobCredentialIntentV2) { intent.AdmissionGrantID = "grant-neighbor" }},
		{name: "revision", mutate: func(intent *JobCredentialIntentV2) { intent.AdmissionGrantRevision++ }},
		{name: "source", mutate: func(intent *JobCredentialIntentV2) { intent.SourceReferenceIDs[0] = "source-neighbor" }},
		{name: "binding", mutate: func(intent *JobCredentialIntentV2) { intent.Bindings[0].BindingID = "binding-neighbor" }},
		{name: "mode", mutate: func(intent *JobCredentialIntentV2) {
			intent.Bindings[0].Mode = CredentialModeSSHAgent
			intent.Bindings[0].ServiceID = ""
		}},
	}
	for _, tt := range mutations {
		t.Run(tt.name, func(t *testing.T) {
			job := l8WorkerV2QueuedJob()
			intent := l8CloneWorkerV2Intent(job.CredentialIntent)
			tt.mutate(&intent)
			job.CredentialIntent = intent
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
