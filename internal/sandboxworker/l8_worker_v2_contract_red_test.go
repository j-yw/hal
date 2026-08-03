package sandboxworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
	"strings"
	"testing"
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
			got := make([]string, 0, tt.typeOf.NumField())
			for index := 0; index < tt.typeOf.NumField(); index++ {
				field := tt.typeOf.Field(index)
				if field.Tag.Get("json") == "" {
					continue
				}
				got = append(got, field.Name+"|"+field.Type.String()+"|"+string(field.Tag))
			}
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

	submissionKey := jobSubmissionKeyV2(principalID, req)
	requestKey, err := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, req)
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
	reorderedSubmissionKey := jobSubmissionKeyV2(principalID, reordered)
	reorderedRequestKey, err := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, reordered)
	if err != nil {
		t.Fatal(err)
	}
	if reorderedSubmissionKey != submissionKey || reorderedRequestKey != requestKey {
		t.Fatalf("equivalent reordered intent changed normalized keys: submission=%q request=%q", reorderedSubmissionKey, reorderedRequestKey)
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
	baseSubmission := jobSubmissionKeyV2("principal-owner", base)
	baseRequest, err := jobRequestKeyV2(RuntimeDriverMicroVM, "principal-owner", base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(baseSubmission, "submission-v2-") || !strings.HasPrefix(baseRequest, "request-v2-") {
		t.Fatalf("v2 identities are not domain-separated: submission=%q request=%q", baseSubmission, baseRequest)
	}
	replay := l8CloneWorkerV2StartRequest(base)
	replayRequest, err := jobRequestKeyV2(RuntimeDriverMicroVM, "principal-owner", replay)
	if err != nil {
		t.Fatal(err)
	}
	if got := jobSubmissionKeyV2("principal-owner", replay); got != baseSubmission || replayRequest != baseRequest {
		t.Fatalf("exact replay changed idempotency identity: submission=%q request=%q", got, replayRequest)
	}

	tests := []struct {
		name      string
		principal string
		mutate    func(*JobStartRequestV2)
	}{
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
			if got := jobSubmissionKeyV2(tt.principal, candidate); got == baseSubmission {
				t.Fatalf("submission identity ignored changed %s", tt.name)
			}
			gotRequest, keyErr := jobRequestKeyV2(RuntimeDriverMicroVM, tt.principal, candidate)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			if gotRequest == baseRequest {
				t.Fatalf("private request identity ignored changed %s", tt.name)
			}
		})
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
		if strings.Contains(strings.ToLower(string(field.Tag)), "principal") {
			t.Fatalf("server-derived principal became a JobV2 JSON field: %s %s", field.Name, field.Tag)
		}
	}
}

func TestL8WorkerV2PrivateDurablePrincipalSurvivesRestartRoundTrip(t *testing.T) {
	principalID := l8GeneratedWorkerV2SafeID(t, "principal")
	request := l8WorkerV2StartRequest()
	requestKey, err := jobRequestKeyV2(RuntimeDriverMicroVM, principalID, request)
	if err != nil {
		t.Fatal(err)
	}
	job := l8WorkerV2QueuedJob()
	job.SubmissionKey = jobSubmissionKeyV2(principalID, request)
	state := storedJobStateV2{
		JobV2:       job,
		RequestKey:  requestKey,
		PrincipalID: principalID,
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("valid private durable v2 state: %v", err)
	}
	for _, tt := range []struct {
		name      string
		principal string
	}{
		{name: "missing", principal: ""},
		{name: "raw looking", principal: "/run/user/1000/peer"},
		{name: "oversized", principal: strings.Repeat("p", 193)},
	} {
		t.Run("rejects "+tt.name+" principal", func(t *testing.T) {
			candidate := state
			candidate.PrincipalID = tt.principal
			if err := candidate.Validate(); err == nil {
				t.Fatal("private durable v2 state accepted unsafe principal identity")
			}
		})
	}
	typ := reflect.TypeOf(state)
	field, ok := typ.FieldByName("PrincipalID")
	if !ok || field.Type.Kind() != reflect.String || field.Tag.Get("json") != "principalId" {
		t.Fatalf("storedJobStateV2 PrincipalID field = %#v, want private durable string json:\"principalId\"", field)
	}
	payload, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"principalId":"`+principalID+`"`) {
		t.Fatalf("private durable v2 state omits principal identity: %s", payload)
	}

	privateDir := t.TempDir()
	path := privateDir + "/job-v2.json"
	if err := writePrivateFileAtomic(privateDir, "job-v2.json", append(payload, '\n')); err != nil {
		t.Fatal(err)
	}
	var restarted storedJobStateV2
	if err := decodePrivateJSONFile(path, &restarted, 64<<10); err != nil {
		t.Fatalf("reload private durable v2 state: %v", err)
	}
	if err := restarted.Validate(); err != nil {
		t.Fatalf("validate reloaded private durable v2 state: %v", err)
	}
	if restarted.PrincipalID != principalID || !reflect.DeepEqual(restarted.JobV2, state.JobV2) || restarted.RequestKey != state.RequestKey {
		t.Fatalf("private durable v2 restart round trip = %#v, want principal and exact safe job identity", restarted)
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
		if strings.Contains(lowerJSON, "principal") || strings.Contains(lowerJSON, "peeruid") || strings.Contains(lowerJSON, "peergid") || strings.Contains(string(publicJSON), principalID) {
			t.Fatalf("public/wire v2 value %d exposed private principal: %s", index, publicJSON)
		}
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
