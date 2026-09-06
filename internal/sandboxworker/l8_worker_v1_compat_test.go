package sandboxworker

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestL8WorkerV1JobStartGoldenBytesRemainStable(t *testing.T) {
	req := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-v1",
		Operation:       OperationJobStart,
		DriverID:        RuntimeDriverMicroVM,
		JobStart: &JobStartRequest{
			ContractVersion: JobContractVersion,
			SubmissionID:    "submission-v1",
			Exec: ExecRequest{
				OperationID: "exec-v1",
				Target: Target{
					Name: "sandbox-v1",
					Runtime: RuntimeTarget{
						Driver:    RuntimeDriverMicroVM,
						RuntimeID: "runtime-v1",
					},
				},
				Args:             []string{"pi", "--offline"},
				WorkDir:          "workspace",
				StdoutLimitBytes: 1024,
				StderrLimitBytes: 2048,
			},
		},
	}

	got, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"protocolVersion":"sandboxworker-v1","requestId":"request-v1","operation":"job_start","driverId":"microvm","jobStart":{"contractVersion":"sandboxjob-v1","submissionId":"submission-v1","exec":{"operationId":"exec-v1","target":{"name":"sandbox-v1","runtime":{"driver":"microvm","runtimeId":"runtime-v1"}},"args":["pi","--offline"],"workDir":"workspace","stdoutLimitBytes":1024,"stderrLimitBytes":2048}}}`
	if string(got) != want {
		t.Fatalf("v1 job_start bytes changed\n got: %s\nwant: %s", got, want)
	}
	assertL8V1BytesContainNoV2Fields(t, got)
}

func TestL8WorkerV1JobLookupOperationGoldenBytesRemainStable(t *testing.T) {
	tests := []struct {
		name string
		req  Request
		want string
	}{
		{
			name: OperationJobResolve,
			req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-resolve-v1", Operation: OperationJobResolve, JobResolve: &JobResolveRequest{
				ContractVersion: JobContractVersion,
				SubmissionID:    "submission-v1",
			}},
			want: `{"protocolVersion":"sandboxworker-v1","requestId":"request-resolve-v1","operation":"job_resolve","jobResolve":{"contractVersion":"sandboxjob-v1","submissionId":"submission-v1"}}`,
		},
		{
			name: OperationJobStatus,
			req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-status-v1", Operation: OperationJobStatus, JobStatus: &JobStatusRequest{
				ContractVersion: JobContractVersion,
				JobID:           "job-v1",
			}},
			want: `{"protocolVersion":"sandboxworker-v1","requestId":"request-status-v1","operation":"job_status","jobStatus":{"contractVersion":"sandboxjob-v1","jobId":"job-v1"}}`,
		},
		{
			name: OperationJobLogs,
			req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-logs-v1", Operation: OperationJobLogs, JobLogs: &JobLogsRequest{
				ContractVersion: JobContractVersion,
				JobID:           "job-v1",
				Cursor:          7,
				LimitBytes:      DefaultJobLogReadBytes,
			}},
			want: `{"protocolVersion":"sandboxworker-v1","requestId":"request-logs-v1","operation":"job_logs","jobLogs":{"contractVersion":"sandboxjob-v1","jobId":"job-v1","cursor":7,"limitBytes":65536}}`,
		},
		{
			name: OperationJobCancel,
			req: Request{ProtocolVersion: ProtocolVersion, RequestID: "request-cancel-v1", Operation: OperationJobCancel, JobCancel: &JobCancelRequest{
				ContractVersion: JobContractVersion,
				JobID:           "job-v1",
			}},
			want: `{"protocolVersion":"sandboxworker-v1","requestId":"request-cancel-v1","operation":"job_cancel","jobCancel":{"contractVersion":"sandboxjob-v1","jobId":"job-v1"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.req)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Fatalf("v1 %s bytes changed\n got: %s\nwant: %s", tt.name, got, tt.want)
			}
			assertL8V1BytesContainNoV2Fields(t, got)
		})
	}
}

func TestL8WorkerV1JobResponseGoldenBytesRemainStable(t *testing.T) {
	submitted := time.Date(2026, time.August, 3, 1, 2, 3, 0, time.UTC)
	started := submitted.Add(time.Second)
	heartbeat := submitted.Add(2 * time.Second)
	finished := submitted.Add(3 * time.Second)
	exitCode := 7
	job := Job{
		ContractVersion: JobContractVersion,
		ID:              "job-v1",
		SubmissionKey:   "submission-v1-digest",
		WorkerID:        "worker-v1",
		HostID:          "host-v1",
		RuntimeDriver:   RuntimeDriverMicroVM,
		RuntimeID:       "runtime-v1",
		State:           JobStateFailed,
		SubmittedAt:     submitted,
		StartedAt:       &started,
		HeartbeatAt:     &heartbeat,
		FinishedAt:      &finished,
		LogCursor:       4,
		LogTruncated:    true,
		StdoutTruncated: true,
		StderrTruncated: true,
		ExitCode:        &exitCode,
		FailureCode:     "nonzero_exit",
		CancelRequested: true,
	}
	resp := Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-v1",
		Operation:       OperationJobStatus,
		OK:              true,
		Job:             &job,
	}

	got, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"protocolVersion":"sandboxworker-v1","requestId":"request-v1","operation":"job_status","ok":true,"job":{"contractVersion":"sandboxjob-v1","jobId":"job-v1","submissionKey":"submission-v1-digest","workerId":"worker-v1","hostId":"host-v1","runtimeDriver":"microvm","runtimeId":"runtime-v1","state":"failed","submittedAt":"2026-08-03T01:02:03Z","startedAt":"2026-08-03T01:02:04Z","heartbeatAt":"2026-08-03T01:02:05Z","finishedAt":"2026-08-03T01:02:06Z","logCursor":4,"logTruncated":true,"stdoutTruncated":true,"stderrTruncated":true,"exitCode":7,"failureCode":"nonzero_exit","cancelRequested":true}}`
	if string(got) != want {
		t.Fatalf("v1 job response bytes changed\n got: %s\nwant: %s", got, want)
	}
	assertL8V1BytesContainNoV2Fields(t, got)
}

func TestL8WorkerV1JobLogsResponseGoldenBytesRemainStable(t *testing.T) {
	response := Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-logs-v1",
		Operation:       OperationJobLogs,
		OK:              true,
		JobLogs: &JobLogsResponse{
			ContractVersion: JobContractVersion,
			JobID:           "job-v1",
			Records: []JobLogRecord{{
				Cursor:    8,
				Stream:    JobLogStreamStdout,
				Data:      "safe output\n",
				Timestamp: time.Date(2026, time.August, 3, 1, 2, 3, 0, time.UTC),
			}},
			NextCursor:   8,
			OldestCursor: 8,
			Truncated:    true,
		},
	}
	got, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"protocolVersion":"sandboxworker-v1","requestId":"request-logs-v1","operation":"job_logs","ok":true,"jobLogs":{"contractVersion":"sandboxjob-v1","jobId":"job-v1","records":[{"cursor":8,"stream":"stdout","data":"safe output\n","timestamp":"2026-08-03T01:02:03Z"}],"nextCursor":8,"oldestCursor":8,"truncated":true}}`
	if string(got) != want {
		t.Fatalf("v1 job logs response bytes changed\n got: %s\nwant: %s", got, want)
	}
	assertL8V1BytesContainNoV2Fields(t, got)
}

func TestL8WorkerV1PublicSchemasHaveNoV2CredentialFields(t *testing.T) {
	tests := []struct {
		name   string
		value  any
		fields []string
	}{
		{name: "Request", value: Request{}, fields: []string{"ProtocolVersion", "RequestID", "Operation", "DriverID", "Target", "Create", "Lifecycle", "Inspect", "Exec", "CopyIn", "CopyOut", "JobStart", "JobResolve", "JobStatus", "JobLogs", "JobCancel"}},
		{name: "Response", value: Response{}, fields: []string{"ProtocolVersion", "RequestID", "Operation", "OK", "Status", "Capabilities", "Target", "Exec", "CopyIn", "CopyOut", "Job", "JobLogs", "Error"}},
		{name: "Job", value: Job{}, fields: []string{"ContractVersion", "ID", "SubmissionKey", "WorkerID", "HostID", "RuntimeDriver", "RuntimeID", "State", "SubmittedAt", "StartedAt", "HeartbeatAt", "FinishedAt", "LogCursor", "LogTruncated", "StdoutTruncated", "StderrTruncated", "ExitCode", "FailureCode", "CancelRequested", "requestKey"}},
		{name: "JobStartRequest", value: JobStartRequest{}, fields: []string{"ContractVersion", "SubmissionID", "Exec"}},
		{name: "JobResolveRequest", value: JobResolveRequest{}, fields: []string{"ContractVersion", "SubmissionID"}},
		{name: "JobStatusRequest", value: JobStatusRequest{}, fields: []string{"ContractVersion", "JobID"}},
		{name: "JobLogsRequest", value: JobLogsRequest{}, fields: []string{"ContractVersion", "JobID", "Cursor", "LimitBytes"}},
		{name: "JobCancelRequest", value: JobCancelRequest{}, fields: []string{"ContractVersion", "JobID"}},
		{name: "JobLogsResponse", value: JobLogsResponse{}, fields: []string{"ContractVersion", "JobID", "Records", "NextCursor", "OldestCursor", "Truncated"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typ := reflect.TypeOf(tt.value)
			minimum := len(tt.fields)
			if tt.name != "Request" && tt.name != "Response" && typ.NumField() != minimum {
				t.Fatalf("%s field count = %d, want %d (%v)", tt.name, typ.NumField(), minimum, tt.fields)
			}
			if typ.NumField() < minimum {
				t.Fatalf("%s field count = %d, want at least unchanged v1 prefix of %d (%v)", tt.name, typ.NumField(), minimum, tt.fields)
			}
			for index, name := range tt.fields {
				if got := typ.Field(index).Name; got != name {
					t.Fatalf("%s field[%d] = %s, want %s", tt.name, index, got, name)
				}
			}
		})
	}
}

func assertL8V1BytesContainNoV2Fields(t *testing.T, payload []byte) {
	t.Helper()
	for _, forbidden := range []string{
		"sandboxjob-v2",
		"jobStartV2",
		"jobResolveV2",
		"jobStatusV2",
		"jobLogsV2",
		"jobCancelV2",
		"productionCredentialsRequested",
		"credentialPlanId",
		"admissionGrant",
		"sourceReference",
		"authenticatedPrincipal",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("v1 wire bytes contain v2 field %q: %s", forbidden, payload)
		}
	}
}
