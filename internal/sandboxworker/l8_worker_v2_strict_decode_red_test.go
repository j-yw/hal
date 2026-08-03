package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestL8WorkerOuterRequestDecoderIsStrictForV1AndV2BeforeDispatch(t *testing.T) {
	server := &Server{maxRequestBytes: defaultMaxRequestBytes}
	v1 := `{"protocolVersion":"sandboxworker-v1","requestId":"request-v1","operation":"job_status","jobStatus":{"contractVersion":"sandboxjob-v1","jobId":"job-primary"}}`
	v2 := l8WorkerV2StartJSON(t)
	noIntentV2 := l8WorkerV2NoCredentialStartJSON(t)
	missingRequiredBool := strings.Replace(noIntentV2, `,"productionCredentialsRequested":false`, "", 1)
	if missingRequiredBool == noIntentV2 {
		t.Fatal("explicit-false V2 fixture did not contain required productionCredentialsRequested")
	}
	nullRequiredBool := strings.Replace(noIntentV2, `"productionCredentialsRequested":false`, `"productionCredentialsRequested":null`, 1)
	if nullRequiredBool == noIntentV2 {
		t.Fatal("explicit-false V2 fixture could not be changed to null required boolean")
	}

	tests := []struct {
		name string
		raw  string
	}{
		{name: "v1 unknown outer", raw: strings.Replace(v1, `"operation":`, `"unknown":true,"operation":`, 1)},
		{name: "v1 duplicate outer", raw: strings.Replace(v1, `"operation":"job_status"`, `"operation":"job_status","operation":"job_status"`, 1)},
		{name: "v1 unknown nested", raw: strings.Replace(v1, `"jobId":"job-primary"`, `"jobId":"job-primary","unknown":true`, 1)},
		{name: "v1 duplicate nested", raw: strings.Replace(v1, `"jobId":"job-primary"`, `"jobId":"job-primary","jobId":"job-primary"`, 1)},
		{name: "v1 trailing value", raw: v1 + `{}`},
		{name: "v2 unknown outer", raw: strings.Replace(v2, `"operation":`, `"unknown":true,"operation":`, 1)},
		{name: "v2 duplicate outer", raw: strings.Replace(v2, `"operation":"job_start_v2"`, `"operation":"job_start_v2","operation":"job_start_v2"`, 1)},
		{name: "v2 v1 payload alias", raw: strings.Replace(v2, `"jobStartV2":`, `"jobStart":`, 1)},
		{name: "v2 unknown payload", raw: strings.Replace(v2, `"productionCredentialsRequested":true`, `"productionCredentialsRequested":true,"unknown":true`, 1)},
		{name: "v2 duplicate required boolean", raw: strings.Replace(v2, `"productionCredentialsRequested":true`, `"productionCredentialsRequested":true,"productionCredentialsRequested":true`, 1)},
		{name: "v2 missing required boolean", raw: strings.Replace(v2, `"productionCredentialsRequested":true,`, "", 1)},
		{name: "v2 no-intent missing required boolean", raw: missingRequiredBool},
		{name: "v2 no-intent null required boolean", raw: nullRequiredBool},
		{name: "v2 string boolean", raw: strings.Replace(v2, `"productionCredentialsRequested":true`, `"productionCredentialsRequested":"true"`, 1)},
		{name: "v2 decimal revision", raw: strings.Replace(v2, `"admissionGrantRevision":9`, `"admissionGrantRevision":9.0`, 1)},
		{name: "v2 exponent revision", raw: strings.Replace(v2, `"admissionGrantRevision":9`, `"admissionGrantRevision":9e0`, 1)},
		{name: "v2 negative zero revision", raw: strings.Replace(v2, `"admissionGrantRevision":9`, `"admissionGrantRevision":-0`, 1)},
		{name: "v2 duplicate binding field", raw: strings.Replace(v2, `"bindingId":"binding-primary"`, `"bindingId":"binding-primary","bindingId":"binding-primary"`, 1)},
		{name: "v2 unknown binding field", raw: strings.Replace(v2, `"bindingId":"binding-primary"`, `"bindingId":"binding-primary","ticket":"opaque-canary"`, 1)},
		{name: "v2 trailing value", raw: v2 + `[]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			server.handler = RequestHandlerFunc(func(context.Context, Request) Response {
				called = true
				return Response{}
			})
			decoded, errorResp := server.readRequest(strings.NewReader(tt.raw))
			if errorResp == nil {
				server.handler.HandleRequest(context.Background(), decoded)
			}
			if errorResp == nil || errorResp.Error == nil || errorResp.Error.Code != ErrorCodeMalformedRequest {
				t.Fatalf("strict decode response = %#v, want malformed_request", errorResp)
			}
			if called {
				t.Fatal("malformed request reached dispatcher")
			}
			if strings.Contains(errorResp.Error.Message, "opaque-canary") || strings.Contains(errorResp.Error.Message, "ticket") {
				t.Fatalf("strict decode error leaked rejected field/value: %#v", errorResp.Error)
			}
		})
	}

	for _, valid := range []string{v1, v1 + " \n\t", v2, v2 + " \n\t", noIntentV2, noIntentV2 + " \n\t"} {
		if _, errorResp := server.readRequest(strings.NewReader(valid)); errorResp != nil {
			t.Fatalf("canonical single request rejected: %#v", errorResp)
		}
	}
}

func l8WorkerV2NoCredentialStartJSON(t *testing.T) string {
	t.Helper()
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
		t.Fatalf("programmatic explicit-false V2 request: %v", err)
	}
	envelope := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "request-v2-no-intent",
		Operation:       OperationJobStartV2,
		DriverID:        RuntimeDriverMicroVM,
		JobStartV2:      &req,
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"productionCredentialsRequested":false`) {
		t.Fatalf("canonical no-intent V2 request omitted explicit required boolean: %s", payload)
	}
	return string(payload)
}

func TestL8WorkerOuterRequestDecoderEnforcesExistingByteLimit(t *testing.T) {
	raw := l8WorkerV2StartJSON(t)
	server := &Server{maxRequestBytes: int64(len(raw) - 1)}
	if _, errorResp := server.readRequest(strings.NewReader(raw)); errorResp == nil || errorResp.Error == nil || errorResp.Error.Code != ErrorCodeMalformedRequest {
		t.Fatalf("oversized v2 request response = %#v, want malformed_request", errorResp)
	}
}

func TestL8WorkerClientResponseDecoderRejectsUnknownDuplicateTrailingAndNoncanonicalJSON(t *testing.T) {
	job := l8WorkerV2QueuedJob()
	response := Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "job_status_v2-1",
		Operation:       OperationJobStatusV2,
		OK:              true,
		JobV2:           &job,
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	canonical := string(encoded)
	tests := []string{
		strings.Replace(canonical, `"operation":`, `"unknown":true,"operation":`, 1),
		strings.Replace(canonical, `"operation":"job_status_v2"`, `"operation":"job_status_v2","operation":"job_status_v2"`, 1),
		strings.Replace(canonical, `"contractVersion":"sandboxjob-v2"`, `"contractVersion":"sandboxjob-v2","contractVersion":"sandboxjob-v2"`, 1),
		strings.Replace(canonical, `"logCursor":0`, `"logCursor":0.0`, 1),
		canonical + `{}`,
	}
	for index, raw := range tests {
		if _, err := decodeWorkerResponse(io.LimitReader(strings.NewReader(raw), defaultMaxResponseBytes)); err == nil {
			t.Fatalf("malformed client response %d was accepted: %s", index, raw)
		}
	}
	decoded, err := decodeWorkerResponse(io.LimitReader(bytes.NewReader(encoded), defaultMaxResponseBytes))
	if err != nil {
		t.Fatalf("canonical client response: %v", err)
	}
	if decoded.Operation != OperationJobStatusV2 || decoded.JobV2 == nil {
		t.Fatalf("decoded response = %#v", decoded)
	}
}

func l8WorkerV2StartJSON(t *testing.T) string {
	t.Helper()
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
	return string(payload)
}
