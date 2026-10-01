package sandboxworker

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestL8WorkerV2JobIDVocabularyIsContractConsistent(t *testing.T) {
	for _, jobID := range []string{
		"job-primary",
		"J",
		"job_01",
		"job.01",
		"j" + strings.Repeat("a", 127),
	} {
		t.Run("accepted "+jobID, func(t *testing.T) {
			job := l8WorkerV2QueuedJob()
			job.ID = jobID
			if err := job.Validate(); err != nil {
				t.Fatalf("contract rejected accepted V2 job ID %q: %v", jobID, err)
			}
		})
	}
	for _, tt := range []struct {
		name  string
		jobID string
	}{
		{name: "dot", jobID: "."},
		{name: "underscore", jobID: "_"},
		{name: "hyphen", jobID: "-"},
		{name: "leading dot", jobID: ".leading"},
		{name: "129 bytes", jobID: "j" + strings.Repeat("a", 128)},
		{name: "colon", jobID: "job:colon"},
	} {
		t.Run("rejected "+tt.name, func(t *testing.T) {
			job := l8WorkerV2QueuedJob()
			job.ID = tt.jobID
			if err := job.Validate(); err == nil {
				t.Errorf("JobV2 contract accepted invalid job ID %q", tt.jobID)
			}
		})
	}
}

func TestL8WorkerV2CredentialIdentitiesUseCrossPhaseSafeIDVocabulary(t *testing.T) {
	fields := []struct {
		name   string
		mutate func(*JobStartRequestV2, string)
	}{
		{name: "submission", mutate: func(req *JobStartRequestV2, value string) { req.SubmissionID = value }},
		{name: "plan", mutate: func(req *JobStartRequestV2, value string) { req.PlanID = value }},
		{name: "grant", mutate: func(req *JobStartRequestV2, value string) { req.AdmissionGrantID = value }},
		{name: "template policy", mutate: func(req *JobStartRequestV2, value string) { req.TemplatePolicyID = value }},
		{name: "workspace policy", mutate: func(req *JobStartRequestV2, value string) { req.WorkspacePolicyID = value }},
		{name: "source reference", mutate: func(req *JobStartRequestV2, value string) {
			req.SourceReferenceIDs[0] = value
			req.Bindings[0].SourceReferenceID = value
		}},
		{name: "binding", mutate: func(req *JobStartRequestV2, value string) { req.Bindings[0].BindingID = value }},
		{name: "service", mutate: func(req *JobStartRequestV2, value string) { req.Bindings[0].ServiceID = value }},
	}
	invalid := l8WorkerV2InvalidCrossPhaseSafeIDCases()
	for _, field := range fields {
		for _, value := range invalid {
			t.Run(field.name+" rejects "+value.name, func(t *testing.T) {
				request := l8WorkerV2StartRequest()
				field.mutate(&request, value.value)
				if err := request.Validate(); err == nil {
					t.Fatalf("v2 credential %s accepted %s safe ID", field.name, value.name)
				}
			})
		}
	}
	for _, field := range fields {
		for _, allowed := range l8WorkerV2CrossPhaseSafeIDCases() {
			t.Run(field.name+" accepts "+allowed.name, func(t *testing.T) {
				request := l8WorkerV2StartRequest()
				field.mutate(&request, allowed.value)
				if err := request.Validate(); err != nil {
					t.Fatalf("v2 credential %s rejected allowed %s safe ID: %v", field.name, allowed.name, err)
				}
			})
		}
	}
	for _, value := range invalid {
		t.Run("resolve submission rejects "+value.name, func(t *testing.T) {
			request := JobResolveRequestV2{ContractVersion: JobContractVersionV2, SubmissionID: value.value}
			if err := request.Validate(); err == nil {
				t.Fatalf("v2 resolve accepted %s submission safe ID", value.name)
			}
		})
	}
	for _, allowed := range l8WorkerV2CrossPhaseSafeIDCases() {
		t.Run("resolve submission accepts "+allowed.name, func(t *testing.T) {
			request := JobResolveRequestV2{ContractVersion: JobContractVersionV2, SubmissionID: allowed.value}
			if err := request.Validate(); err != nil {
				t.Fatalf("v2 resolve rejected allowed %s submission safe ID: %v", allowed.name, err)
			}
		})
	}

	legacy := JobStartRequest{
		ContractVersion: JobContractVersion,
		SubmissionID:    strings.Repeat("s", 192),
		Exec:            l8WorkerV2StartRequest().Exec,
	}
	legacy.Exec.Target.Runtime.RuntimeID = "runtime:legacy"
	if err := legacy.Validate(); err != nil {
		t.Fatalf("stricter v2 credential vocabulary changed legacy v1 192-byte/colon job/runtime IDs: %v", err)
	}
	if err := (JobResolveRequest{ContractVersion: JobContractVersion, SubmissionID: "submission:legacy"}).Validate(); err != nil {
		t.Fatalf("stricter v2 submission vocabulary changed legacy v1 resolve identity: %v", err)
	}
	if err := (JobStatusRequest{ContractVersion: JobContractVersion, JobID: strings.Repeat("j", 192)}).Validate(); err != nil {
		t.Fatalf("stricter v2 submission vocabulary changed legacy v1 status identity: %v", err)
	}
}

func TestL8WorkerV2DurableCredentialIntentUsesCrossPhaseSafeIDVocabulary(t *testing.T) {
	fields := []struct {
		name   string
		mutate func(*JobCredentialIntentV2, string)
	}{
		{name: "plan", mutate: func(intent *JobCredentialIntentV2, value string) { intent.PlanID = value }},
		{name: "grant", mutate: func(intent *JobCredentialIntentV2, value string) { intent.AdmissionGrantID = value }},
		{name: "template policy", mutate: func(intent *JobCredentialIntentV2, value string) { intent.TemplatePolicyID = value }},
		{name: "workspace policy", mutate: func(intent *JobCredentialIntentV2, value string) { intent.WorkspacePolicyID = value }},
		{name: "source reference", mutate: func(intent *JobCredentialIntentV2, value string) {
			intent.SourceReferenceIDs[0] = value
			intent.Bindings[0].SourceReferenceID = value
		}},
		{name: "binding", mutate: func(intent *JobCredentialIntentV2, value string) { intent.Bindings[0].BindingID = value }},
		{name: "service", mutate: func(intent *JobCredentialIntentV2, value string) { intent.Bindings[0].ServiceID = value }},
	}
	for _, field := range fields {
		for _, invalid := range l8WorkerV2InvalidCrossPhaseSafeIDCases() {
			t.Run(field.name+" rejects "+invalid.name, func(t *testing.T) {
				job := l8WorkerV2QueuedJob()
				intent := l8CloneWorkerV2Intent(job.CredentialIntent)
				field.mutate(&intent, invalid.value)
				job.CredentialIntent = intent
				if err := job.Validate(); err == nil {
					t.Fatalf("durable v2 credential %s accepted %s safe ID", field.name, invalid.name)
				}
			})
		}
		for _, allowed := range l8WorkerV2CrossPhaseSafeIDCases() {
			t.Run(field.name+" accepts "+allowed.name, func(t *testing.T) {
				job := l8WorkerV2QueuedJob()
				intent := l8CloneWorkerV2Intent(job.CredentialIntent)
				field.mutate(&intent, allowed.value)
				job.CredentialIntent = intent
				if err := job.Validate(); err != nil {
					t.Fatalf("durable v2 credential %s rejected allowed %s safe ID: %v", field.name, allowed.name, err)
				}
			})
		}
	}
}

func TestL8WorkerV2DurableJobJSONContainsOnlySafeCredentialIdentity(t *testing.T) {
	job := l8WorkerV2QueuedJob()
	payload, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`"contractVersion":"sandboxjob-v2"`,
		`"productionCredentialsRequested":true`,
		`"planId":"plan-primary"`,
		`"admissionGrantId":"grant-primary"`,
		`"admissionGrantRevision":9`,
		`"sourceReferenceIds":["source-primary"]`,
		`"bindingId":"binding-primary"`,
		`"mode":"http_proxy"`,
	} {
		if !strings.Contains(string(payload), required) {
			t.Fatalf("durable v2 job omits safe identity %s: %s", required, payload)
		}
	}
	for _, forbidden := range []string{
		"principal-owner",
		"authenticatedPrincipal",
		"raw-canary",
		"ticket",
		"callback",
		"socket",
		"endpoint",
		"hostPath",
		"keySerial",
		"execBinding",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("durable v2 job leaked forbidden %q: %s", forbidden, payload)
		}
	}

	typ := reflect.TypeOf(job)
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		fieldIdentity := strings.ToLower(field.Name + " " + string(field.Tag))
		if strings.Contains(fieldIdentity, "principal") || strings.Contains(fieldIdentity, "daemongeneration") {
			t.Fatalf("private server identity became a JobV2 JSON field: %s %s", field.Name, field.Tag)
		}
	}
}

func TestL8WorkerV2ExactSchemaHelperIncludesUntaggedExportedFields(t *testing.T) {
	type schemaFixture struct {
		Tagged            string `json:"tagged"`
		DefaultSerialized string
		IgnoredByJSON     string `json:"-"`
		private           string
	}
	want := []string{
		`Tagged|string|json:"tagged"`,
		`DefaultSerialized|string|`,
		`IgnoredByJSON|string|json:"-"`,
	}
	fixture := schemaFixture{private: "excluded"}
	if got := l8WorkerV2ExportedSchema(reflect.TypeOf(fixture)); !reflect.DeepEqual(got, want) {
		t.Fatalf("exact exported schema helper = %q, want %q", got, want)
	}
}

func TestL8WorkerV2JobRejectsMalformedOpaqueSubmissionKeys(t *testing.T) {
	for _, tt := range []struct {
		name string
		key  string
	}{
		{name: "missing", key: ""},
		{name: "short digest", key: "submission-v2-" + strings.Repeat("0", 63)},
		{name: "non-hex digest", key: "submission-v2-" + strings.Repeat("g", 64)},
		{name: "uppercase digest", key: "submission-v2-" + strings.Repeat("A", 64)},
		{name: "oversized digest", key: "submission-v2-" + strings.Repeat("0", 65)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			job := l8WorkerV2QueuedJob()
			job.SubmissionKey = tt.key
			if err := job.Validate(); err == nil {
				t.Fatal("JobV2 accepted malformed submission-v2 key")
			}
		})
	}
}

func TestL8WorkerV2NoCredentialIntentRequiresExactAbsence(t *testing.T) {
	req := l8WorkerV2StartRequest()
	req.ProductionCredentialsRequested = false
	req.PlanID = ""
	req.AdmissionGrantID = ""
	req.AdmissionGrantRevision = 0
	req.TemplatePolicyID = ""
	req.WorkspacePolicyID = ""
	req.SourceReferenceIDs = nil
	req.Bindings = nil
	if err := req.Validate(); err != nil {
		t.Fatalf("explicit no-credential v2 request: %v", err)
	}
	for _, allowed := range l8WorkerV2CrossPhaseSafeIDCases() {
		candidate := l8CloneWorkerV2StartRequest(req)
		candidate.SubmissionID = allowed.value
		if err := candidate.Validate(); err != nil {
			t.Fatalf("no-credential v2 request rejected %s submission identity: %v", allowed.name, err)
		}
	}
	for _, invalid := range l8WorkerV2InvalidCrossPhaseSafeIDCases() {
		candidate := l8CloneWorkerV2StartRequest(req)
		candidate.SubmissionID = invalid.value
		if err := candidate.Validate(); err == nil {
			t.Fatalf("no-credential v2 request accepted %s submission identity", invalid.name)
		}
	}

	mutations := []func(*JobStartRequestV2){
		func(value *JobStartRequestV2) { value.PlanID = "plan-smuggled" },
		func(value *JobStartRequestV2) { value.AdmissionGrantID = "grant-smuggled" },
		func(value *JobStartRequestV2) { value.AdmissionGrantRevision = 1 },
		func(value *JobStartRequestV2) { value.TemplatePolicyID = "template-smuggled" },
		func(value *JobStartRequestV2) { value.WorkspacePolicyID = "workspace-smuggled" },
		func(value *JobStartRequestV2) { value.SourceReferenceIDs = []string{"source-smuggled"} },
		func(value *JobStartRequestV2) {
			value.Bindings = []JobCredentialBindingV2{{BindingID: "binding-smuggled", SourceReferenceID: "source-smuggled", Mode: "http_proxy"}}
		},
	}
	for index, mutate := range mutations {
		candidate := l8CloneWorkerV2StartRequest(req)
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Fatalf("no-credential request accepted smuggled identity mutation %d", index)
		}
	}
}

func TestL8WorkerV2OperationsAndPayloadFieldsAreDistinctFromV1(t *testing.T) {
	if JobContractVersionV2 != "sandboxjob-v2" {
		t.Fatalf("JobContractVersionV2 = %q, want sandboxjob-v2", JobContractVersionV2)
	}
	wantOperations := []string{
		"job_start_v2",
		"job_resolve_v2",
		"job_status_v2",
		"job_logs_v2",
		"job_cancel_v2",
	}
	gotOperations := []string{
		OperationJobStartV2,
		OperationJobResolveV2,
		OperationJobStatusV2,
		OperationJobLogsV2,
		OperationJobCancelV2,
	}
	if !reflect.DeepEqual(gotOperations, wantOperations) {
		t.Fatalf("v2 operations = %v, want %v", gotOperations, wantOperations)
	}
	for _, operation := range gotOperations {
		if operation == OperationJobStart || operation == OperationJobResolve || operation == OperationJobStatus || operation == OperationJobLogs || operation == OperationJobCancel {
			t.Fatalf("v2 operation %q aliases a v1 operation", operation)
		}
	}

	req := l8WorkerV2StartRequest()
	envelope := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-v2",
		Operation:       OperationJobStartV2,
		DriverID:        RuntimeDriverMicroVM,
		JobStartV2:      &req,
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{
		`"protocolVersion":"sandboxworker-v1"`,
		`"operation":"job_start_v2"`,
		`"jobStartV2"`,
		`"contractVersion":"sandboxjob-v2"`,
		`"productionCredentialsRequested":true`,
		`"planId":"plan-primary"`,
		`"admissionGrantId":"grant-primary"`,
		`"admissionGrantRevision":9`,
		`"templatePolicyId":"template-primary"`,
		`"workspacePolicyId":"workspace-primary"`,
		`"sourceReferenceIds":["source-primary"]`,
		`"bindings":[`,
		`"bindingId":"binding-primary"`,
		`"sourceReferenceId":"source-primary"`,
		`"mode":"http_proxy"`,
		`"serviceId":"azure-openai-responses-v1"`,
	}
	for _, want := range wantKeys {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("v2 start JSON omits %s: %s", want, payload)
		}
	}
	for _, forbidden := range []string{
		`"jobStart"`,
		`"authenticatedPrincipal"`,
		`"principalId"`,
		`"value"`,
		`"secret"`,
		`"ticket"`,
		`"callback"`,
		`"socket"`,
		`"endpoint"`,
		`"hostPath"`,
		`"keySerial"`,
		`"execBinding"`,
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("v2 start JSON contains forbidden field %s: %s", forbidden, payload)
		}
	}
}

func TestL8WorkerV2PayloadJSONSchemasAreExact(t *testing.T) {
	tests := []struct {
		name   string
		typeOf reflect.Type
		want   []string
	}{
		{name: "JobCredentialBindingV2", typeOf: reflect.TypeOf(JobCredentialBindingV2{}), want: []string{
			`BindingID|string|json:"bindingId"`,
			`SourceReferenceID|string|json:"sourceReferenceId"`,
			`Mode|string|json:"mode"`,
			`ServiceID|string|json:"serviceId,omitempty"`,
		}},
		{name: "JobCredentialIntentV2", typeOf: reflect.TypeOf(JobCredentialIntentV2{}), want: []string{
			`ProductionCredentialsRequested|bool|json:"productionCredentialsRequested"`,
			`PlanID|string|json:"planId,omitempty"`,
			`AdmissionGrantID|string|json:"admissionGrantId,omitempty"`,
			`AdmissionGrantRevision|uint64|json:"admissionGrantRevision,omitempty"`,
			`TemplatePolicyID|string|json:"templatePolicyId,omitempty"`,
			`WorkspacePolicyID|string|json:"workspacePolicyId,omitempty"`,
			`SourceReferenceIDs|[]string|json:"sourceReferenceIds,omitempty"`,
			`Bindings|[]sandboxworker.JobCredentialBindingV2|json:"bindings,omitempty"`,
		}},
		{name: "JobStartRequestV2", typeOf: reflect.TypeOf(JobStartRequestV2{}), want: []string{
			`ContractVersion|string|json:"contractVersion"`,
			`SubmissionID|string|json:"submissionId"`,
			`Exec|sandboxworker.ExecRequest|json:"exec"`,
			`ProductionCredentialsRequested|bool|json:"productionCredentialsRequested"`,
			`PlanID|string|json:"planId,omitempty"`,
			`AdmissionGrantID|string|json:"admissionGrantId,omitempty"`,
			`AdmissionGrantRevision|uint64|json:"admissionGrantRevision,omitempty"`,
			`TemplatePolicyID|string|json:"templatePolicyId,omitempty"`,
			`WorkspacePolicyID|string|json:"workspacePolicyId,omitempty"`,
			`SourceReferenceIDs|[]string|json:"sourceReferenceIds,omitempty"`,
			`Bindings|[]sandboxworker.JobCredentialBindingV2|json:"bindings,omitempty"`,
		}},
		{name: "JobResolveRequestV2", typeOf: reflect.TypeOf(JobResolveRequestV2{}), want: []string{
			`ContractVersion|string|json:"contractVersion"`, `SubmissionID|string|json:"submissionId"`,
		}},
		{name: "JobStatusRequestV2", typeOf: reflect.TypeOf(JobStatusRequestV2{}), want: []string{
			`ContractVersion|string|json:"contractVersion"`, `JobID|string|json:"jobId"`,
		}},
		{name: "JobLogsRequestV2", typeOf: reflect.TypeOf(JobLogsRequestV2{}), want: []string{
			`ContractVersion|string|json:"contractVersion"`, `JobID|string|json:"jobId"`, `Cursor|uint64|json:"cursor"`, `LimitBytes|int64|json:"limitBytes"`,
		}},
		{name: "JobCancelRequestV2", typeOf: reflect.TypeOf(JobCancelRequestV2{}), want: []string{
			`ContractVersion|string|json:"contractVersion"`, `JobID|string|json:"jobId"`,
		}},
		{name: "JobLogsResponseV2", typeOf: reflect.TypeOf(JobLogsResponseV2{}), want: []string{
			`ContractVersion|string|json:"contractVersion"`, `JobID|string|json:"jobId"`, `Records|[]sandboxworker.JobLogRecord|json:"records,omitempty"`, `NextCursor|uint64|json:"nextCursor"`, `OldestCursor|uint64|json:"oldestCursor,omitempty"`, `Truncated|bool|json:"truncated,omitempty"`,
		}},
		{name: "JobV2", typeOf: reflect.TypeOf(JobV2{}), want: []string{
			`ContractVersion|string|json:"contractVersion"`,
			`ID|string|json:"jobId"`,
			`SubmissionKey|string|json:"submissionKey,omitempty"`,
			`WorkerID|string|json:"workerId"`,
			`HostID|string|json:"hostId,omitempty"`,
			`RuntimeDriver|string|json:"runtimeDriver"`,
			`RuntimeID|string|json:"runtimeId,omitempty"`,
			`State|string|json:"state"`,
			`SubmittedAt|time.Time|json:"submittedAt"`,
			`StartedAt|*time.Time|json:"startedAt,omitempty"`,
			`HeartbeatAt|*time.Time|json:"heartbeatAt,omitempty"`,
			`FinishedAt|*time.Time|json:"finishedAt,omitempty"`,
			`LogCursor|uint64|json:"logCursor"`,
			`LogTruncated|bool|json:"logTruncated,omitempty"`,
			`StdoutTruncated|bool|json:"stdoutTruncated,omitempty"`,
			`StderrTruncated|bool|json:"stderrTruncated,omitempty"`,
			`ExitCode|*int|json:"exitCode,omitempty"`,
			`FailureCode|string|json:"failureCode,omitempty"`,
			`CancelRequested|bool|json:"cancelRequested,omitempty"`,
			`CredentialIntent|sandboxworker.JobCredentialIntentV2|json:"credentialIntent"`,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := l8WorkerV2ExportedSchema(tt.typeOf)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("%s JSON schema = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestL8WorkerV2ProductionCredentialIntentValidationFailsClosed(t *testing.T) {
	valid := l8WorkerV2StartRequest()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid v2 request: %v", err)
	}
	for _, tt := range []struct {
		name      string
		mode      string
		serviceID string
	}{
		{name: "http proxy", mode: "http_proxy", serviceID: "azure-openai-responses-v1"},
		{name: "file tmpfs", mode: CredentialModeFileTmpfs},
		{name: "ssh agent", mode: CredentialModeSSHAgent},
	} {
		t.Run("accepts "+tt.name, func(t *testing.T) {
			req := l8CloneWorkerV2StartRequest(valid)
			req.Bindings[0].Mode = tt.mode
			req.Bindings[0].ServiceID = tt.serviceID
			if err := req.Validate(); err != nil {
				t.Fatalf("production mode %q rejected: %v", tt.mode, err)
			}
		})
	}

	tests := []struct {
		name   string
		mutate func(*JobStartRequestV2)
	}{
		{name: "missing plan", mutate: func(req *JobStartRequestV2) { req.PlanID = "" }},
		{name: "missing grant", mutate: func(req *JobStartRequestV2) { req.AdmissionGrantID = "" }},
		{name: "zero grant revision", mutate: func(req *JobStartRequestV2) { req.AdmissionGrantRevision = 0 }},
		{name: "missing template policy", mutate: func(req *JobStartRequestV2) { req.TemplatePolicyID = "" }},
		{name: "missing workspace policy", mutate: func(req *JobStartRequestV2) { req.WorkspacePolicyID = "" }},
		{name: "missing sources", mutate: func(req *JobStartRequestV2) { req.SourceReferenceIDs = nil }},
		{name: "duplicate sources", mutate: func(req *JobStartRequestV2) { req.SourceReferenceIDs = []string{"source-primary", "source-primary"} }},
		{name: "unbound listed source", mutate: func(req *JobStartRequestV2) {
			req.SourceReferenceIDs = append(req.SourceReferenceIDs, "source-unbound")
		}},
		{name: "missing bindings", mutate: func(req *JobStartRequestV2) { req.Bindings = nil }},
		{name: "missing binding id", mutate: func(req *JobStartRequestV2) { req.Bindings[0].BindingID = "" }},
		{name: "missing binding source", mutate: func(req *JobStartRequestV2) { req.Bindings[0].SourceReferenceID = "" }},
		{name: "unlisted binding source", mutate: func(req *JobStartRequestV2) { req.Bindings[0].SourceReferenceID = "source-neighbor" }},
		{name: "missing mode", mutate: func(req *JobStartRequestV2) { req.Bindings[0].Mode = "" }},
		{name: "http missing service", mutate: func(req *JobStartRequestV2) { req.Bindings[0].ServiceID = "" }},
		{name: "file carries service", mutate: func(req *JobStartRequestV2) { req.Bindings[0].Mode = CredentialModeFileTmpfs }},
		{name: "ssh carries service", mutate: func(req *JobStartRequestV2) { req.Bindings[0].Mode = CredentialModeSSHAgent }},
		{name: "compatibility mode", mutate: func(req *JobStartRequestV2) { req.Bindings[0].Mode = CredentialModeEnv }},
		{name: "legacy mode", mutate: func(req *JobStartRequestV2) { req.Bindings[0].Mode = CredentialModeLegacyAuthSync }},
		{name: "unknown mode", mutate: func(req *JobStartRequestV2) { req.Bindings[0].Mode = "future_mode" }},
		{name: "duplicate binding", mutate: func(req *JobStartRequestV2) { req.Bindings = append(req.Bindings, req.Bindings[0]) }},
		{name: "duplicate binding identity independent of fields", mutate: func(req *JobStartRequestV2) {
			req.SourceReferenceIDs = append(req.SourceReferenceIDs, "source-secondary")
			req.Bindings = append(req.Bindings, JobCredentialBindingV2{
				BindingID:         req.Bindings[0].BindingID,
				SourceReferenceID: "source-secondary",
				Mode:              CredentialModeFileTmpfs,
			})
		}},
		{name: "raw looking plan", mutate: func(req *JobStartRequestV2) { req.PlanID = "/home/operator/plan" }},
		{name: "oversized safe identity", mutate: func(req *JobStartRequestV2) { req.PlanID = strings.Repeat("a", 193) }},
		{name: "raw looking grant", mutate: func(req *JobStartRequestV2) { req.AdmissionGrantID = "token=raw-grant" }},
		{name: "raw looking template policy", mutate: func(req *JobStartRequestV2) { req.TemplatePolicyID = "https://policy.example/template" }},
		{name: "raw looking workspace policy", mutate: func(req *JobStartRequestV2) { req.WorkspacePolicyID = "/home/operator/workspace-policy" }},
		{name: "raw looking submission", mutate: func(req *JobStartRequestV2) { req.SubmissionID = "/home/operator/submission" }},
		{name: "raw looking source", mutate: func(req *JobStartRequestV2) {
			req.SourceReferenceIDs[0] = "https://secret.example/value"
			req.Bindings[0].SourceReferenceID = req.SourceReferenceIDs[0]
		}},
		{name: "raw looking binding", mutate: func(req *JobStartRequestV2) { req.Bindings[0].BindingID = "token=raw-canary" }},
		{name: "raw looking service", mutate: func(req *JobStartRequestV2) { req.Bindings[0].ServiceID = "https://service.example/route" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := l8CloneWorkerV2StartRequest(valid)
			tt.mutate(&req)
			if err := req.Validate(); err == nil {
				t.Fatal("unsafe or incomplete production credential intent was accepted")
			}
		})
	}
}

func TestL8WorkerV2PublicContractsRemainPrivateServerIdentityFree(t *testing.T) {
	publicTypes := []reflect.Type{
		reflect.TypeOf(JobCredentialBindingV2{}),
		reflect.TypeOf(JobCredentialIntentV2{}),
		reflect.TypeOf(JobStartRequestV2{}),
		reflect.TypeOf(JobResolveRequestV2{}),
		reflect.TypeOf(JobStatusRequestV2{}),
		reflect.TypeOf(JobLogsRequestV2{}),
		reflect.TypeOf(JobCancelRequestV2{}),
		reflect.TypeOf(JobLogsResponseV2{}),
		reflect.TypeOf(JobV2{}),
		reflect.TypeOf(Request{}),
		reflect.TypeOf(Response{}),
	}
	for _, typ := range publicTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for index := 0; index < typ.NumField(); index++ {
				field := typ.Field(index)
				fieldIdentity := strings.ToLower(field.Name + " " + string(field.Tag))
				if strings.Contains(fieldIdentity, "principal") || strings.Contains(fieldIdentity, "peeruid") || strings.Contains(fieldIdentity, "peergid") || strings.Contains(fieldIdentity, "daemongeneration") {
					t.Fatalf("public V2 contract %s exposes private server identity field %s %s", typ.Name(), field.Name, field.Tag)
				}
			}
		})
	}
}

func TestL8WorkerV2ReusesExistingExecLogAndIdentityBounds(t *testing.T) {
	start := l8WorkerV2StartRequest()
	start.Exec.StdoutLimitBytes = MaxExecStdoutCaptureBytes + 1
	if err := start.Validate(); err == nil {
		t.Fatal("v2 start accepted exec output beyond the existing bound")
	}

	for _, limit := range []int64{DefaultJobLogRecordBytes - 1, DefaultJobLogReadBytes + 1} {
		req := JobLogsRequestV2{
			ContractVersion: JobContractVersionV2,
			JobID:           "job-primary",
			LimitBytes:      limit,
		}
		if err := req.Validate(); err == nil {
			t.Fatalf("v2 logs accepted limitBytes=%d outside existing bounds", limit)
		}
	}
}

func l8CloneWorkerV2Intent(intent JobCredentialIntentV2) JobCredentialIntentV2 {
	intent.SourceReferenceIDs = append([]string(nil), intent.SourceReferenceIDs...)
	intent.Bindings = append([]JobCredentialBindingV2(nil), intent.Bindings...)
	return intent
}

func l8CloneWorkerV2StartRequest(req JobStartRequestV2) JobStartRequestV2 {
	req.Exec = canonicalJobExecRequest(req.Exec)
	req.SourceReferenceIDs = append([]string(nil), req.SourceReferenceIDs...)
	req.Bindings = append([]JobCredentialBindingV2(nil), req.Bindings...)
	return req
}

func l8WorkerV2CrossPhaseSafeIDCases() []l8WorkerV2SafeIDCase {
	return []l8WorkerV2SafeIDCase{
		{name: "128 byte mixed alphabet", value: strings.Repeat("-._Aa0", 21) + "-."},
		{name: "single dot", value: "."},
		{name: "single underscore", value: "_"},
		{name: "single hyphen", value: "-"},
		{name: "leading punctuation and uppercase", value: "._-Upper9"},
	}
}

func l8WorkerV2ExecRequest() ExecRequest {
	return ExecRequest{
		OperationID: "exec-primary",
		Target: Target{
			Name: "sandbox-primary",
			Runtime: RuntimeTarget{
				Driver:    RuntimeDriverMicroVM,
				RuntimeID: "runtime-primary",
			},
		},
		Args:             []string{"pi", "--offline"},
		WorkDir:          "workspace",
		StdoutLimitBytes: 1024,
		StderrLimitBytes: 1024,
	}
}

func l8WorkerV2ExportedSchema(typ reflect.Type) []string {
	fields := make([]string, 0, typ.NumField())
	for index := 0; index < typ.NumField(); index++ {
		field := typ.Field(index)
		if !field.IsExported() {
			continue
		}
		fields = append(fields, field.Name+"|"+field.Type.String()+"|"+string(field.Tag))
	}
	return fields
}

func l8WorkerV2InvalidCrossPhaseSafeIDCases() []l8WorkerV2SafeIDCase {
	cases := []l8WorkerV2SafeIDCase{
		{name: "129 bytes", value: strings.Repeat("a", 129)},
		{name: "representative non-ASCII", value: "credential-邻居"},
	}
	for value := 0; value < 128; value++ {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '_' || value == '.' {
			continue
		}
		cases = append(cases, l8WorkerV2SafeIDCase{
			name:  fmt.Sprintf("forbidden ASCII byte 0x%02x", value),
			value: "credential" + string(rune(value)) + "neighbor",
		})
	}
	return cases
}

func l8WorkerV2QueuedJob() JobV2 {
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
		SubmissionKey:    "submission-v2-" + strings.Repeat("0", 64),
		WorkerID:         "worker-primary",
		HostID:           "host-primary",
		RuntimeDriver:    RuntimeDriverMicroVM,
		RuntimeID:        "runtime-primary",
		State:            JobStateQueued,
		SubmittedAt:      time.Date(2026, time.August, 3, 1, 2, 3, 0, time.UTC),
		CredentialIntent: intent,
	}
}

func l8WorkerV2StartRequest() JobStartRequestV2 {
	return JobStartRequestV2{
		ContractVersion:                JobContractVersionV2,
		SubmissionID:                   "submission-primary",
		Exec:                           l8WorkerV2ExecRequest(),
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
}

type l8WorkerV2SafeIDCase struct {
	name  string
	value string
}
