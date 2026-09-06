package sandboxworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

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

type l8WorkerV2SafeIDCase struct {
	name  string
	value string
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

func TestL8WorkerV2IdentityKeysAreExactOpaqueLowercaseHex(t *testing.T) {
	principalID := l8GeneratedWorkerV2SafeID(t, "principal")
	req := l8WorkerV2StartRequest()
	req.SubmissionID = l8GeneratedWorkerV2SafeID(t, "submission")
	req.PlanID = l8GeneratedWorkerV2SafeID(t, "plan")
	req.AdmissionGrantID = l8GeneratedWorkerV2SafeID(t, "grant")
	req.TemplatePolicyID = l8GeneratedWorkerV2SafeID(t, "template")
	req.WorkspacePolicyID = l8GeneratedWorkerV2SafeID(t, "workspace")
	req.SourceReferenceIDs[0] = l8GeneratedWorkerV2SafeID(t, "source")
	req.Bindings[0].BindingID = l8GeneratedWorkerV2SafeID(t, "binding")
	req.Bindings[0].SourceReferenceID = req.SourceReferenceIDs[0]
	req.Bindings[0].ServiceID = l8GeneratedWorkerV2SafeID(t, "service")
	req.Exec.OperationID = l8GeneratedWorkerV2SafeID(t, "operation")
	req.Exec.Target.Name = l8GeneratedWorkerV2SafeID(t, "target")
	req.Exec.Target.Runtime.RuntimeID = l8GeneratedWorkerV2SafeID(t, "runtime")
	secondSource := l8GeneratedWorkerV2SafeID(t, "source-secondary")
	secondBinding := JobCredentialBindingV2{
		BindingID:         l8GeneratedWorkerV2SafeID(t, "binding-secondary"),
		SourceReferenceID: secondSource,
		Mode:              CredentialModeSSHAgent,
	}
	req.SourceReferenceIDs = append(req.SourceReferenceIDs, secondSource)
	req.Bindings = append(req.Bindings, secondBinding)
	if err := req.Validate(); err != nil {
		t.Fatalf("generated multi-source fixture: %v", err)
	}

	submissionKey := jobSubmissionKeyV2(principalID, l8WorkerV2DaemonGeneration, req)
	requestKey, err := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, l8WorkerV2DaemonGeneration, req)
	if err != nil {
		t.Fatal(err)
	}
	shapes := []struct {
		name    string
		value   string
		pattern string
	}{
		{name: "submission", value: submissionKey, pattern: `^submission-v2-[0-9a-f]{64}$`},
		{name: "request", value: requestKey, pattern: `^request-v2-[0-9a-f]{64}$`},
	}
	for _, shape := range shapes {
		if !regexp.MustCompile(shape.pattern).MatchString(shape.value) {
			t.Fatalf("%s key = %q, want exact normalized lowercase-hex shape %s", shape.name, shape.value, shape.pattern)
		}
		for _, raw := range []string{
			principalID,
			req.SubmissionID,
			req.PlanID,
			req.AdmissionGrantID,
			req.TemplatePolicyID,
			req.WorkspacePolicyID,
			req.SourceReferenceIDs[0],
			req.Bindings[0].BindingID,
			req.Bindings[0].ServiceID,
			req.Exec.OperationID,
			req.Exec.Target.Name,
			req.Exec.Target.Runtime.RuntimeID,
		} {
			if strings.Contains(shape.value, raw) {
				t.Fatalf("%s key exposes raw identity %q: %q", shape.name, raw, shape.value)
			}
		}
	}
	reordered := l8CloneWorkerV2StartRequest(req)
	reordered.SourceReferenceIDs[0], reordered.SourceReferenceIDs[1] = reordered.SourceReferenceIDs[1], reordered.SourceReferenceIDs[0]
	reordered.Bindings[0], reordered.Bindings[1] = reordered.Bindings[1], reordered.Bindings[0]
	reorderedSubmissionKey := jobSubmissionKeyV2(principalID, l8WorkerV2DaemonGeneration, reordered)
	reorderedRequestKey, err := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, l8WorkerV2DaemonGeneration, reordered)
	if err != nil {
		t.Fatal(err)
	}
	if reorderedSubmissionKey != submissionKey || reorderedRequestKey != requestKey {
		t.Fatalf("equivalent reordered intent changed normalized keys: submission=%q request=%q", reorderedSubmissionKey, reorderedRequestKey)
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

func TestL8WorkerV2PrivateRequestKeyIncludesCanonicalExecIdentity(t *testing.T) {
	base := l8WorkerV2StartRequest()
	base.Exec = ExecRequest{
		OperationID: "exec-identity",
		Target: Target{
			ID:     " target-primary ",
			Name:   " sandbox-primary ",
			Status: " ready ",
			Labels: map[string]string{"purpose": "test", "tier": "worker"},
			Runtime: RuntimeTarget{
				Driver:         " microvm ",
				RuntimeID:      " runtime-primary ",
				Image:          " image-primary ",
				WorkerID:       " worker-primary ",
				IsolationLevel: IsolationLevelVM,
				Metadata: &sandboxruntime.RuntimeMetadata{
					Backend:          "firecracker",
					CapabilityLabels: []string{"credential_safe", "offline"},
					PathRoles:        []string{"workspace", "artifacts"},
				},
			},
		},
		Args:    []string{"pi", "--offline", "task"},
		Env:     map[string]string{"HAL_PROFILE": "test", "LANG": "C"},
		WorkDir: " workspace ",
		Stdin: &ExecStdinPayload{
			Data:       "c2FmZQ==",
			Encoding:   CopyPayloadEncodingBase64,
			SizeBytes:  4,
			LimitBytes: 16,
		},
		StdoutLimitBytes: 2048,
		StderrLimitBytes: 4096,
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid full V2 exec identity fixture: %v", err)
	}
	baseKey, err := jobRequestKeyV2(" microvm ", "principal-owner", " "+l8WorkerV2DaemonGeneration+" ", base)
	if err != nil {
		t.Fatal(err)
	}

	equivalent := l8CloneWorkerV2StartRequest(base)
	equivalent.Exec.WorkDir = "workspace"
	equivalent.Exec.Target.ID = "target-primary"
	equivalent.Exec.Target.Name = "sandbox-primary"
	equivalent.Exec.Target.Status = "ready"
	equivalent.Exec.Target.Labels = map[string]string{"tier": "worker", "purpose": "test"}
	equivalent.Exec.Target.Runtime.Driver = "microvm"
	equivalent.Exec.Target.Runtime.RuntimeID = "runtime-primary"
	equivalent.Exec.Target.Runtime.Image = "image-primary"
	equivalent.Exec.Target.Runtime.WorkerID = "worker-primary"
	equivalent.Exec.Target.Runtime.Metadata.CapabilityLabels[0], equivalent.Exec.Target.Runtime.Metadata.CapabilityLabels[1] = equivalent.Exec.Target.Runtime.Metadata.CapabilityLabels[1], equivalent.Exec.Target.Runtime.Metadata.CapabilityLabels[0]
	equivalent.Exec.Target.Runtime.Metadata.PathRoles[0], equivalent.Exec.Target.Runtime.Metadata.PathRoles[1] = equivalent.Exec.Target.Runtime.Metadata.PathRoles[1], equivalent.Exec.Target.Runtime.Metadata.PathRoles[0]
	equivalent.Exec.Env = map[string]string{"LANG": "C", "HAL_PROFILE": "test"}
	equivalentKey, err := jobRequestKeyV2("microvm", "principal-owner", l8WorkerV2DaemonGeneration, equivalent)
	if err != nil {
		t.Fatal(err)
	}
	if equivalentKey != baseKey {
		t.Fatalf("canonical whitespace/map ordering changed private request key: got %q want %q", equivalentKey, baseKey)
	}

	mutations := []struct {
		name   string
		driver string
		mutate func(*JobStartRequestV2)
	}{
		{name: "outer driver", driver: RuntimeDriverRootlessPodman, mutate: func(*JobStartRequestV2) {}},
		{name: "operation id", mutate: func(req *JobStartRequestV2) { req.Exec.OperationID = "exec-neighbor" }},
		{name: "workdir", mutate: func(req *JobStartRequestV2) { req.Exec.WorkDir = "workspace-neighbor" }},
		{name: "args", mutate: func(req *JobStartRequestV2) { req.Exec.Args[2] = "task-neighbor" }},
		{name: "env", mutate: func(req *JobStartRequestV2) { req.Exec.Env["HAL_PROFILE"] = "neighbor" }},
		{name: "stdin data", mutate: func(req *JobStartRequestV2) { req.Exec.Stdin.Data = "dGVzdA==" }},
		{name: "stdin limit", mutate: func(req *JobStartRequestV2) { req.Exec.Stdin.LimitBytes++ }},
		{name: "target id", mutate: func(req *JobStartRequestV2) { req.Exec.Target.ID = "target-neighbor" }},
		{name: "target name", mutate: func(req *JobStartRequestV2) { req.Exec.Target.Name = "sandbox-neighbor" }},
		{name: "target status", mutate: func(req *JobStartRequestV2) { req.Exec.Target.Status = "running" }},
		{name: "target labels", mutate: func(req *JobStartRequestV2) { req.Exec.Target.Labels["tier"] = "neighbor" }},
		{name: "runtime driver", mutate: func(req *JobStartRequestV2) { req.Exec.Target.Runtime.Driver = RuntimeDriverRootlessPodman }},
		{name: "runtime id", mutate: func(req *JobStartRequestV2) { req.Exec.Target.Runtime.RuntimeID = "runtime-neighbor" }},
		{name: "runtime image", mutate: func(req *JobStartRequestV2) { req.Exec.Target.Runtime.Image = "image-neighbor" }},
		{name: "runtime worker", mutate: func(req *JobStartRequestV2) { req.Exec.Target.Runtime.WorkerID = "worker-neighbor" }},
		{name: "runtime isolation", mutate: func(req *JobStartRequestV2) { req.Exec.Target.Runtime.IsolationLevel = IsolationLevelContainer }},
		{name: "runtime metadata", mutate: func(req *JobStartRequestV2) {
			req.Exec.Target.Runtime.Metadata = &sandboxruntime.RuntimeMetadata{Backend: "rootless_podman"}
		}},
		{name: "runtime capability labels", mutate: func(req *JobStartRequestV2) {
			req.Exec.Target.Runtime.Metadata.CapabilityLabels[0] = "credential_neighbor"
		}},
		{name: "runtime path roles", mutate: func(req *JobStartRequestV2) {
			req.Exec.Target.Runtime.Metadata.PathRoles[0] = "workspace_neighbor"
		}},
		{name: "stdout limit", mutate: func(req *JobStartRequestV2) { req.Exec.StdoutLimitBytes++ }},
		{name: "stderr limit", mutate: func(req *JobStartRequestV2) { req.Exec.StderrLimitBytes++ }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := l8CloneWorkerV2StartRequest(base)
			mutation.mutate(&candidate)
			if err := candidate.Validate(); err != nil {
				t.Fatalf("valid changed exec identity fixture: %v", err)
			}
			driver := mutation.driver
			if driver == "" {
				driver = " microvm "
			}
			key, keyErr := jobRequestKeyV2(driver, "principal-owner", l8WorkerV2DaemonGeneration, candidate)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			if key == baseKey {
				t.Fatal("private request key ignored changed canonical exec identity")
			}
		})
	}
}

func TestL8WorkerV2PrivateRequestKeyCanonicalizationDoesNotMutateInput(t *testing.T) {
	request := l8WorkerV2StartRequest()
	request.SourceReferenceIDs = []string{"source-secondary", "source-primary"}
	request.Bindings = []JobCredentialBindingV2{
		{
			BindingID:         "binding-secondary",
			SourceReferenceID: "source-secondary",
			Mode:              CredentialModeSSHAgent,
		},
		{
			BindingID:         "binding-primary",
			SourceReferenceID: "source-primary",
			Mode:              "http_proxy",
			ServiceID:         "azure-openai-responses-v1",
		},
	}
	request.Exec = ExecRequest{
		OperationID: "exec-identity",
		Target: Target{
			ID:     " target-primary ",
			Name:   " sandbox-primary ",
			Status: " ready ",
			Labels: map[string]string{"tier": "worker", "purpose": "test"},
			Runtime: RuntimeTarget{
				Driver:         " microvm ",
				RuntimeID:      " runtime-primary ",
				Image:          " image-primary ",
				WorkerID:       " worker-primary ",
				IsolationLevel: IsolationLevelVM,
				Metadata: &sandboxruntime.RuntimeMetadata{
					Backend:          "firecracker",
					CapabilityLabels: []string{"offline", "credential_safe"},
					PathRoles:        []string{"workspace", "artifacts"},
				},
			},
		},
		Args:    []string{"pi", "--offline", "task"},
		Env:     map[string]string{"LANG": "C", "HAL_PROFILE": "test"},
		WorkDir: " workspace ",
		Stdin: &ExecStdinPayload{
			Data:       "c2FmZQ==",
			Encoding:   CopyPayloadEncodingBase64,
			SizeBytes:  4,
			LimitBytes: 16,
		},
		StdoutLimitBytes: 2048,
		StderrLimitBytes: 4096,
	}
	if err := request.Validate(); err != nil {
		t.Fatalf("valid full canonicalization fixture: %v", err)
	}
	before, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var equivalent JobStartRequestV2
	if err := json.Unmarshal(before, &equivalent); err != nil {
		t.Fatal(err)
	}
	equivalent.SourceReferenceIDs[0], equivalent.SourceReferenceIDs[1] = equivalent.SourceReferenceIDs[1], equivalent.SourceReferenceIDs[0]
	equivalent.Bindings[0], equivalent.Bindings[1] = equivalent.Bindings[1], equivalent.Bindings[0]
	equivalent.Exec.Target.Runtime.Metadata.CapabilityLabels[0], equivalent.Exec.Target.Runtime.Metadata.CapabilityLabels[1] = equivalent.Exec.Target.Runtime.Metadata.CapabilityLabels[1], equivalent.Exec.Target.Runtime.Metadata.CapabilityLabels[0]
	equivalent.Exec.Target.Runtime.Metadata.PathRoles[0], equivalent.Exec.Target.Runtime.Metadata.PathRoles[1] = equivalent.Exec.Target.Runtime.Metadata.PathRoles[1], equivalent.Exec.Target.Runtime.Metadata.PathRoles[0]
	equivalentBefore, err := json.Marshal(equivalent)
	if err != nil {
		t.Fatal(err)
	}

	key, err := jobRequestKeyV2(" microvm ", " principal-owner ", " "+l8WorkerV2DaemonGeneration+" ", request)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("private request key canonicalization mutated caller input:\n before: %s\n  after: %s", before, after)
	}
	canonicalKey, err := jobRequestKeyV2("microvm", "principal-owner", l8WorkerV2DaemonGeneration, equivalent)
	if err != nil {
		t.Fatal(err)
	}
	equivalentAfter, err := json.Marshal(equivalent)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(equivalentAfter, equivalentBefore) {
		t.Fatalf("private request key canonicalization mutated reordered caller input:\n before: %s\n  after: %s", equivalentBefore, equivalentAfter)
	}
	if key != canonicalKey {
		t.Fatalf("private request key did not preserve canonical equivalence: got %q want %q", key, canonicalKey)
	}
	if !regexp.MustCompile(`^request-v2-[0-9a-f]{64}$`).MatchString(key) {
		t.Fatalf("private request key = %q, want exact opaque canonical shape", key)
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

func TestL8WorkerV2CredentialIntentChangesBothSubmissionAndPrivateRequestIdentity(t *testing.T) {
	base := l8WorkerV2StartRequest()
	baseSubmission := jobSubmissionKeyV2("principal-owner", l8WorkerV2DaemonGeneration, base)
	baseRequest, err := jobRequestKeyV2(RuntimeDriverMicroVM, "principal-owner", l8WorkerV2DaemonGeneration, base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(baseSubmission, "submission-v2-") || !strings.HasPrefix(baseRequest, "request-v2-") {
		t.Fatalf("v2 identities are not domain-separated: submission=%q request=%q", baseSubmission, baseRequest)
	}
	replay := l8CloneWorkerV2StartRequest(base)
	replayRequest, err := jobRequestKeyV2(RuntimeDriverMicroVM, "principal-owner", l8WorkerV2DaemonGeneration, replay)
	if err != nil {
		t.Fatal(err)
	}
	if got := jobSubmissionKeyV2("principal-owner", l8WorkerV2DaemonGeneration, replay); got != baseSubmission || replayRequest != baseRequest {
		t.Fatalf("exact replay changed idempotency identity: submission=%q request=%q", got, replayRequest)
	}

	tests := []struct {
		name      string
		principal string
		mutate    func(*JobStartRequestV2)
	}{
		{name: "submission", principal: "principal-owner", mutate: func(req *JobStartRequestV2) { req.SubmissionID = "submission-neighbor" }},
		{name: "production intent", principal: "principal-owner", mutate: func(req *JobStartRequestV2) {
			req.ProductionCredentialsRequested = false
			req.PlanID = ""
			req.AdmissionGrantID = ""
			req.AdmissionGrantRevision = 0
			req.TemplatePolicyID = ""
			req.WorkspacePolicyID = ""
			req.SourceReferenceIDs = nil
			req.Bindings = nil
		}},
		{name: "plan", principal: "principal-owner", mutate: func(req *JobStartRequestV2) { req.PlanID = "plan-neighbor" }},
		{name: "grant", principal: "principal-owner", mutate: func(req *JobStartRequestV2) { req.AdmissionGrantID = "grant-neighbor" }},
		{name: "grant revision", principal: "principal-owner", mutate: func(req *JobStartRequestV2) { req.AdmissionGrantRevision++ }},
		{name: "template policy", principal: "principal-owner", mutate: func(req *JobStartRequestV2) { req.TemplatePolicyID = "template-neighbor" }},
		{name: "workspace policy", principal: "principal-owner", mutate: func(req *JobStartRequestV2) { req.WorkspacePolicyID = "workspace-neighbor" }},
		{name: "source", principal: "principal-owner", mutate: func(req *JobStartRequestV2) {
			req.SourceReferenceIDs[0] = "source-neighbor"
			req.Bindings[0].SourceReferenceID = "source-neighbor"
		}},
		{name: "binding", principal: "principal-owner", mutate: func(req *JobStartRequestV2) { req.Bindings[0].BindingID = "binding-neighbor" }},
		{name: "mode", principal: "principal-owner", mutate: func(req *JobStartRequestV2) {
			req.Bindings[0].Mode = CredentialModeFileTmpfs
			req.Bindings[0].ServiceID = ""
		}},
		{name: "service", principal: "principal-owner", mutate: func(req *JobStartRequestV2) { req.Bindings[0].ServiceID = "service-neighbor" }},
		{name: "server principal", principal: "principal-neighbor", mutate: func(*JobStartRequestV2) {}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidate := l8CloneWorkerV2StartRequest(base)
			tt.mutate(&candidate)
			if got := jobSubmissionKeyV2(tt.principal, l8WorkerV2DaemonGeneration, candidate); got == baseSubmission {
				t.Fatalf("submission identity ignored changed %s", tt.name)
			}
			gotRequest, keyErr := jobRequestKeyV2(RuntimeDriverMicroVM, tt.principal, l8WorkerV2DaemonGeneration, candidate)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			if gotRequest == baseRequest {
				t.Fatalf("private request identity ignored changed %s", tt.name)
			}
		})
	}

	neighborGeneration := "daemon-generation-neighbor"
	if got := jobSubmissionKeyV2("principal-owner", neighborGeneration, base); got == baseSubmission {
		t.Fatal("submission identity ignored changed daemon generation")
	}
	neighborRequest, err := jobRequestKeyV2(RuntimeDriverMicroVM, "principal-owner", neighborGeneration, base)
	if err != nil {
		t.Fatal(err)
	}
	if neighborRequest == baseRequest {
		t.Fatal("private request identity ignored changed daemon generation")
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

func TestL8WorkerV2PrivateDurableIdentitySurvivesRestartRoundTrip(t *testing.T) {
	principalID := l8GeneratedWorkerV2SafeID(t, "principal")
	request := l8WorkerV2StartRequest()
	requestKey, err := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, l8WorkerV2DaemonGeneration, request)
	if err != nil {
		t.Fatal(err)
	}
	job := l8WorkerV2QueuedJob()
	job.SubmissionKey = jobSubmissionKeyV2(principalID, l8WorkerV2DaemonGeneration, request)
	state := storedJobStateV2{
		JobV2:            job,
		RequestKey:       requestKey,
		PrincipalID:      principalID,
		DaemonGeneration: l8WorkerV2DaemonGeneration,
		CredentialState:  l8D6StoredCredentialStateForJob(t, job, principalID),
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("valid private durable v2 state: %v", err)
	}
	wantPrivateSchema := []string{
		`JobV2|sandboxworker.JobV2|`,
		`RequestKey|string|json:"requestKey"`,
		`PrincipalID|string|json:"principalId"`,
		`DaemonGeneration|string|json:"daemonGeneration"`,
		`CredentialState|*sandboxworker.storedJobCredentialStateV2|json:"credentialState,omitempty"`,
		`CredentialRecoveryReceipt|*sandboxworker.storedJobCredentialRuntimeRecoveryReceiptV1|json:"credentialRecoveryReceipt,omitempty"`,
	}
	for _, allowed := range l8WorkerV2CrossPhaseSafeIDCases() {
		t.Run("accepts daemon generation "+allowed.name, func(t *testing.T) {
			candidate := state
			candidate.DaemonGeneration = allowed.value
			candidate.JobV2.SubmissionKey = jobSubmissionKeyV2(principalID, allowed.value, request)
			requestKey, keyErr := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, allowed.value, request)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			candidate.RequestKey = requestKey
			if err := candidate.Validate(); err != nil {
				t.Fatalf("private durable v2 state rejected allowed daemon generation %s: %v", allowed.name, err)
			}
		})
	}
	privateType := reflect.TypeOf(state)
	gotPrivateSchema := make([]string, 0, privateType.NumField())
	for index := 0; index < privateType.NumField(); index++ {
		field := privateType.Field(index)
		gotPrivateSchema = append(gotPrivateSchema, field.Name+"|"+field.Type.String()+"|"+string(field.Tag))
	}
	if !reflect.DeepEqual(gotPrivateSchema, wantPrivateSchema) {
		t.Fatalf("storedJobStateV2 schema = %q, want exact private wrapper %q", gotPrivateSchema, wantPrivateSchema)
	}
	for _, allowed := range l8WorkerV2CrossPhaseSafeIDCases() {
		t.Run("accepts principal "+allowed.name, func(t *testing.T) {
			candidate := state
			candidate.PrincipalID = allowed.value
			candidate.CredentialState = l8D6StoredCredentialStateForJob(t, candidate.JobV2, allowed.value)
			candidate.JobV2.SubmissionKey = jobSubmissionKeyV2(allowed.value, l8WorkerV2DaemonGeneration, request)
			requestKey, keyErr := jobRequestKeyV2(RuntimeDriverMicroVM, allowed.value, l8WorkerV2DaemonGeneration, request)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			candidate.RequestKey = requestKey
			if err := candidate.Validate(); err != nil {
				t.Fatalf("private durable v2 state rejected allowed principal %s: %v", allowed.name, err)
			}
		})
	}
	for _, tt := range []struct {
		name   string
		mutate func(*storedJobStateV2)
	}{
		{name: "missing submission key", mutate: func(candidate *storedJobStateV2) { candidate.JobV2.SubmissionKey = "" }},
		{name: "missing request key", mutate: func(candidate *storedJobStateV2) { candidate.RequestKey = "" }},
		{name: "raw looking request key", mutate: func(candidate *storedJobStateV2) { candidate.RequestKey = "token=raw-request" }},
		{name: "oversized request key", mutate: func(candidate *storedJobStateV2) { candidate.RequestKey = strings.Repeat("r", 193) }},
		{name: "wrong domain request key", mutate: func(candidate *storedJobStateV2) { candidate.RequestKey = "submission-v2-" + strings.Repeat("0", 64) }},
		{name: "non hex request key", mutate: func(candidate *storedJobStateV2) { candidate.RequestKey = "request-v2-" + strings.Repeat("g", 64) }},
		{name: "short request key", mutate: func(candidate *storedJobStateV2) { candidate.RequestKey = "request-v2-" + strings.Repeat("0", 63) }},
		{name: "missing principal", mutate: func(candidate *storedJobStateV2) { candidate.PrincipalID = "" }},
		{name: "129 byte principal", mutate: func(candidate *storedJobStateV2) { candidate.PrincipalID = strings.Repeat("p", 129) }},
		{name: "missing daemon generation", mutate: func(candidate *storedJobStateV2) { candidate.DaemonGeneration = "" }},
		{name: "129 byte daemon generation", mutate: func(candidate *storedJobStateV2) { candidate.DaemonGeneration = strings.Repeat("d", 129) }},
	} {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			candidate := state
			tt.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("private durable v2 state accepted unsafe required identity")
			}
		})
	}
	for _, invalid := range l8WorkerV2InvalidCrossPhaseSafeIDCases() {
		t.Run("rejects principal "+invalid.name, func(t *testing.T) {
			candidate := state
			candidate.PrincipalID = invalid.value
			if err := candidate.Validate(); err == nil {
				t.Fatal("private durable v2 state accepted unsafe principal")
			}
		})
		t.Run("rejects daemon generation "+invalid.name, func(t *testing.T) {
			candidate := state
			candidate.DaemonGeneration = invalid.value
			if err := candidate.Validate(); err == nil {
				t.Fatal("private durable v2 state accepted unsafe daemon generation")
			}
		})
	}
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"principalId":"`+principalID+`"`) {
		t.Fatalf("private durable v2 state omits principal identity: %s", payload)
	}
	if !strings.Contains(string(payload), `"requestKey":"`+requestKey+`"`) {
		t.Fatalf("private durable v2 state omits request identity: %s", payload)
	}
	if !strings.Contains(string(payload), `"daemonGeneration":"`+l8WorkerV2DaemonGeneration+`"`) {
		t.Fatalf("private durable v2 state omits daemon generation: %s", payload)
	}

	stateDir := t.TempDir() + "/jobs-v2"
	store, err := newJobStoreV2(stateDir)
	if err != nil {
		t.Fatalf("new v2 job store: %v", err)
	}
	if err := store.save(state); err != nil {
		t.Fatalf("save private durable v2 state through store: %v", err)
	}
	restartedStore, err := newJobStoreV2(stateDir)
	if err != nil {
		t.Fatalf("reopen v2 job store: %v", err)
	}
	restarted, err := restartedStore.load(job.ID)
	if err != nil {
		t.Fatalf("load private durable v2 state after reopen: %v", err)
	}
	l8AssertWorkerV2PrivateStateIdentity(t, restarted, state)
	listed, err := restartedStore.list()
	if err != nil {
		t.Fatalf("list private durable v2 state after reopen: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("listed private durable v2 states = %d, want 1", len(listed))
	}
	l8AssertWorkerV2PrivateStateIdentity(t, listed[0], state)

	if reconciled, err := reconcileJobStoreV2AtStartup(restartedStore, job.SubmittedAt.Add(time.Minute)); reconciled != nil || !errors.Is(err, ErrL8RecoveryDependency) {
		t.Fatalf("credential startup reconciliation = %#v, %v, want retained recovery dependency", reconciled, err)
	}
	persistedReconciliation, err := restartedStore.load(job.ID)
	if err != nil {
		t.Fatalf("reload reconciled private durable v2 state: %v", err)
	}
	if !reflect.DeepEqual(persistedReconciliation, state) {
		t.Fatalf("failed-closed startup reconciliation mutated retained ownership: got %#v want %#v", persistedReconciliation, state)
	}

	publicValues := []any{
		state.JobV2,
		Request{ProtocolVersion: ProtocolVersion, RequestID: "request-v2", Operation: OperationJobStartV2, DriverID: RuntimeDriverMicroVM, JobStartV2: &request},
		Response{ProtocolVersion: ProtocolVersion, RequestID: "request-v2", Operation: OperationJobStatusV2, OK: true, JobV2: &state.JobV2},
	}
	for index, value := range publicValues {
		publicJSON, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		lowerJSON := strings.ToLower(string(publicJSON))
		if strings.Contains(lowerJSON, "principal") || strings.Contains(lowerJSON, "peeruid") || strings.Contains(lowerJSON, "peergid") || strings.Contains(lowerJSON, "daemongeneration") || strings.Contains(string(publicJSON), principalID) || strings.Contains(string(publicJSON), l8WorkerV2DaemonGeneration) {
			t.Fatalf("public/wire v2 value %d exposed private server identity: %s", index, publicJSON)
		}
	}
}

func TestL8WorkerV2StoreRejectsInvalidOrMismatchedDurableStateBeforeReconciliation(t *testing.T) {
	principalID := l8GeneratedWorkerV2SafeID(t, "principal")
	request := l8WorkerV2StartRequest()
	requestKey, err := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, l8WorkerV2DaemonGeneration, request)
	if err != nil {
		t.Fatal(err)
	}
	validState := storedJobStateV2{
		JobV2:            l8WorkerV2QueuedJob(),
		RequestKey:       requestKey,
		PrincipalID:      principalID,
		DaemonGeneration: l8WorkerV2DaemonGeneration,
	}
	validState.JobV2.SubmissionKey = jobSubmissionKeyV2(principalID, l8WorkerV2DaemonGeneration, request)
	validState.CredentialState = l8D6StoredCredentialStateForJob(t, validState.JobV2, principalID)
	if err := validState.Validate(); err != nil {
		t.Fatalf("valid private durable v2 state: %v", err)
	}

	for _, test := range []struct {
		name        string
		requestedID string
		mutate      func(*storedJobStateV2)
		crossJobID  string
	}{
		{
			name:        "invalid private identity",
			requestedID: validState.JobV2.ID,
			mutate: func(state *storedJobStateV2) {
				state.PrincipalID = ""
			},
		},
		{
			name:        "filename and embedded job identity differ",
			requestedID: "job-file-primary",
			mutate:      func(*storedJobStateV2) {},
			crossJobID:  validState.JobV2.ID,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			store, err := newJobStoreV2(filepath.Join(t.TempDir(), "jobs-v2"))
			if err != nil {
				t.Fatal(err)
			}
			candidate := validState
			test.mutate(&candidate)
			payload, err := encodeStoredJobStateV2(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(store.root, test.requestedID+".json"), payload, 0o600); err != nil {
				t.Fatal(err)
			}

			if _, err := store.load(test.requestedID); err == nil || err.Error() != "stored job state is malformed" {
				t.Fatalf("load malformed private durable state error = %v, want generic malformed-state rejection", err)
			}
			if test.crossJobID == "" {
				return
			}
			if _, err := reconcileJobStoreV2AtStartup(store, validState.JobV2.SubmittedAt.Add(time.Minute)); err == nil {
				t.Fatal("startup reconciliation accepted a filename/embedded job identity mismatch")
			}
			_, statErr := os.Lstat(filepath.Join(store.root, test.crossJobID+".json"))
			if !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("startup reconciliation created a cross-job durable state: %v", statErr)
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

func TestL8WorkerV2StoreJobIDVocabularyIsContractAndPersistenceConsistent(t *testing.T) {
	principalID := l8GeneratedWorkerV2SafeID(t, "principal")
	request := l8WorkerV2StartRequest()
	requestKey, err := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, l8WorkerV2DaemonGeneration, request)
	if err != nil {
		t.Fatal(err)
	}
	base := storedJobStateV2{
		JobV2:            l8WorkerV2QueuedJob(),
		RequestKey:       requestKey,
		PrincipalID:      principalID,
		DaemonGeneration: l8WorkerV2DaemonGeneration,
	}
	base.JobV2.SubmissionKey = jobSubmissionKeyV2(principalID, l8WorkerV2DaemonGeneration, request)
	base.CredentialState = l8D6StoredCredentialStateForJob(t, base.JobV2, principalID)

	for _, jobID := range []string{
		"job-primary",
		"J",
		"job_01",
		"job.01",
		"j" + strings.Repeat("a", 127),
	} {
		t.Run("accepted "+jobID, func(t *testing.T) {
			state := base
			state.JobV2.ID = jobID
			state.CredentialState = l8D6StoredCredentialStateForJob(t, state.JobV2, principalID)
			if err := state.Validate(); err != nil {
				t.Fatalf("contract rejected accepted V2 job ID %q: %v", jobID, err)
			}
			store, err := newJobStoreV2(filepath.Join(t.TempDir(), "jobs-v2"))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.save(state); err != nil {
				t.Fatalf("save rejected accepted V2 job ID %q: %v", jobID, err)
			}
			loaded, err := store.load(jobID)
			if err != nil {
				t.Fatalf("load rejected saved V2 job ID %q: %v", jobID, err)
			}
			if !reflect.DeepEqual(loaded, state) {
				t.Fatalf("loaded V2 job ID %q state = %#v, want %#v", jobID, loaded, state)
			}
			listed, err := store.list()
			if err != nil {
				t.Fatalf("list rejected saved V2 job ID %q: %v", jobID, err)
			}
			if len(listed) != 1 || !reflect.DeepEqual(listed[0], state) {
				t.Fatalf("listed V2 job ID %q states = %#v, want exact saved state", jobID, listed)
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
			jobID := tt.jobID
			state := base
			state.JobV2.ID = jobID
			if err := state.JobV2.Validate(); err == nil {
				t.Errorf("JobV2 contract accepted store-incompatible job ID %q", jobID)
			}
			if err := state.Validate(); err == nil {
				t.Errorf("durable-state contract accepted store-incompatible job ID %q", jobID)
			}
			store, err := newJobStoreV2(filepath.Join(t.TempDir(), "jobs-v2"))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.save(state); err == nil {
				t.Errorf("store persisted contract-invalid job ID %q", jobID)
			}
			entries, err := os.ReadDir(store.root)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("contract-invalid job ID %q left durable entries: %#v", jobID, entries)
			}
		})
	}
}

func l8AssertWorkerV2PrivateStateIdentity(t *testing.T, got, want storedJobStateV2) {
	t.Helper()
	if got.PrincipalID != want.PrincipalID || got.DaemonGeneration != want.DaemonGeneration || got.RequestKey != want.RequestKey || !reflect.DeepEqual(got.JobV2, want.JobV2) {
		t.Fatalf("private durable v2 state = %#v, want exact safe job/request/principal/generation identity %#v", got, want)
	}
}

const l8WorkerV2DaemonGeneration = "daemon-generation-primary"

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

func l8CloneWorkerV2StartRequest(req JobStartRequestV2) JobStartRequestV2 {
	req.Exec = canonicalJobExecRequest(req.Exec)
	req.SourceReferenceIDs = append([]string(nil), req.SourceReferenceIDs...)
	req.Bindings = append([]JobCredentialBindingV2(nil), req.Bindings...)
	return req
}

func l8GeneratedWorkerV2SafeID(t *testing.T, domain string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(t.Name() + "\x00" + domain))
	return domain + "-" + hex.EncodeToString(digest[:12])
}
