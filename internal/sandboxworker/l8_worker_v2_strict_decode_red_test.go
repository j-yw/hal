package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

func TestL8WorkerV2BoundedJSONReaderPreservesFullPositiveInt64Range(t *testing.T) {
	raw := []byte(`{"operation":"status"}`)
	got, err := readWorkerJSONBoundedV2(bytes.NewReader(raw), math.MaxInt64)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("MaxInt64 bounded read = %q, %v; want exact small payload", got, err)
	}
	large := bytes.Repeat([]byte{'x'}, (1<<20)+1)
	got, err = readWorkerJSONBoundedV2(bytes.NewReader(large), int64(len(large)))
	if err != nil || !bytes.Equal(got, large) {
		t.Fatalf("configured read above 1 MiB length = %d, %v; want exact %d-byte payload", len(got), err, len(large))
	}
	got, err = readWorkerJSONBoundedV2(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("exact-limit EOF read = %q, %v; want success", got, err)
	}
	if _, err := readWorkerJSONBoundedV2(bytes.NewReader(append(append([]byte(nil), raw...), '!')), int64(len(raw))); err == nil {
		t.Fatal("one byte beyond the exact limit was accepted")
	}

	probeFailure := errors.New("probe failure")
	reader := io.MultiReader(bytes.NewReader(raw), l8WorkerV2ProbeErrorReader{err: probeFailure})
	if _, err := readWorkerJSONBoundedV2(reader, int64(len(raw))); !errors.Is(err, probeFailure) {
		t.Fatalf("probe error = %v, want wrapped probe failure", err)
	}
}

func TestL8WorkerV2JSONPreflightBoundsNestingBeforeTypedDecode(t *testing.T) {
	const decoderNestingLimit = 10_000
	atLimit := strings.Repeat("[", decoderNestingLimit) + "null" + strings.Repeat("]", decoderNestingLimit)
	if err := validateWorkerJSONPreflightV2(atLimit); err != nil {
		t.Fatalf("preflight rejected JSON at the typed decoder nesting limit: %v", err)
	}
	overLimit := "[" + atLimit + "]"
	if err := validateWorkerJSONPreflightV2(overLimit); err == nil {
		t.Fatal("preflight accepted JSON beyond the typed decoder nesting limit")
	}
}

type l8WorkerV2ProbeErrorReader struct {
	err error
}

func (reader l8WorkerV2ProbeErrorReader) Read([]byte) (int, error) {
	return 0, reader.err
}

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

func TestL8WorkerStrictRequestDecoderAcceptsAllFiveExactV1Operations(t *testing.T) {
	fixtures := l8WorkerV2RequestPayloadFixturesForTest(t)
	server := &Server{maxRequestBytes: defaultMaxRequestBytes}
	for index, operation := range fixtures.v1Names() {
		t.Run(operation, func(t *testing.T) {
			request := Request{
				ProtocolVersion: ProtocolVersion,
				RequestID:       "request-v1-" + operation,
				Operation:       operation,
			}
			if operation == OperationJobStart {
				request.DriverID = RuntimeDriverMicroVM
			}
			fixtures.setV1Payload(&request, index)
			payload, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			decoded, errorResp := server.readRequest(bytes.NewReader(payload))
			if errorResp != nil {
				t.Fatalf("strict request decoder rejected exact V1 %s: %#v", operation, errorResp)
			}
			if decoded.Operation != operation {
				t.Fatalf("decoded operation = %q, want %q", decoded.Operation, operation)
			}
		})
	}
}

func TestL8WorkerStrictDecodersPreserveCredentialSchemaNamesInsideStringMaps(t *testing.T) {
	server := &Server{maxRequestBytes: defaultMaxRequestBytes}
	fixtures := l8WorkerV2RequestPayloadFixturesForTest(t)

	for _, key := range []string{"credentialIntent", "jobStartV2"} {
		for _, location := range []string{"env", "labels"} {
			for _, version := range []string{"v1", "v2"} {
				t.Run(version+"/"+location+"/"+key, func(t *testing.T) {
					request := Request{
						ProtocolVersion: ProtocolVersion,
						RequestID:       "request-map-key-" + version + "-" + location,
						DriverID:        RuntimeDriverMicroVM,
					}
					if version == "v1" {
						start := fixtures.startV1
						if location == "env" {
							start.Exec.Env = map[string]string{key: "safe-map-value"}
						} else {
							start.Exec.Target.Labels = map[string]string{key: "safe-map-value"}
						}
						request.Operation = OperationJobStart
						request.JobStart = &start
					} else {
						start := l8WorkerV2StartRequest()
						if location == "env" {
							start.Exec.Env = map[string]string{key: "safe-map-value"}
						} else {
							start.Exec.Target.Labels = map[string]string{key: "safe-map-value"}
						}
						request.Operation = OperationJobStartV2
						request.JobStartV2 = &start
					}
					if err := request.Validate(); err != nil {
						t.Fatalf("typed request rejected unrestricted map key: %v", err)
					}
					payload, err := json.Marshal(request)
					if err != nil {
						t.Fatal(err)
					}
					decoded, errorResp := server.readRequest(bytes.NewReader(payload))
					if errorResp != nil {
						t.Fatalf("strict request decoder rejected unrestricted map key: %#v", errorResp)
					}
					var got string
					if decoded.JobStart != nil {
						if location == "env" {
							got = decoded.JobStart.Exec.Env[key]
						} else {
							got = decoded.JobStart.Exec.Target.Labels[key]
						}
					} else if decoded.JobStartV2 != nil {
						if location == "env" {
							got = decoded.JobStartV2.Exec.Env[key]
						} else {
							got = decoded.JobStartV2.Exec.Target.Labels[key]
						}
					}
					if got != "safe-map-value" {
						t.Fatalf("decoded unrestricted map value = %q", got)
					}
				})
			}
		}

		t.Run("response/labels/"+key, func(t *testing.T) {
			target := l8WorkerV2ExecRequest().Target
			target.Labels = map[string]string{key: "safe-map-value"}
			response := Response{
				ProtocolVersion: ProtocolVersion,
				RequestID:       "response-map-key",
				Operation:       OperationInspect,
				OK:              true,
				Target:          &target,
			}
			if err := response.Validate(); err != nil {
				t.Fatalf("typed response rejected unrestricted map key: %v", err)
			}
			payload, err := json.Marshal(response)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeWorkerResponse(bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("strict response decoder rejected unrestricted map key: %v", err)
			}
			if decoded.Target == nil || decoded.Target.Labels[key] != "safe-map-value" {
				t.Fatalf("decoded unrestricted response map value = %#v", decoded.Target)
			}
		})
	}
}

func TestL8WorkerV2JSONPreflightRequiresProductionFlagOnlyAtCredentialSchemaPaths(t *testing.T) {
	for _, raw := range []string{
		`{"jobStartV2":{"contractVersion":"sandboxjob-v2"}}`,
		`{"jobV2":{"credentialIntent":{"planId":"plan-primary"}}}`,
		`{"JobV2":{"credentialIntent":{"planId":"plan-primary"}}}`,
	} {
		if err := validateWorkerJSONPreflightV2(raw); err == nil {
			t.Fatalf("preflight accepted credential schema without productionCredentialsRequested: %s", raw)
		}
	}

	for _, raw := range []string{
		`{"env":{"credentialIntent":"safe-map-value","jobStartV2":"safe-map-value"}}`,
		`{"labels":{"credentialIntent":"safe-map-value","jobStartV2":"safe-map-value"}}`,
	} {
		if err := validateWorkerJSONPreflightV2(raw); err != nil {
			t.Fatalf("preflight treated unrestricted string-map key as credential schema: %v", err)
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

func TestL8WorkerStrictResponseDecoderAcceptsExactV1JobLogAndError(t *testing.T) {
	job := l8WorkerV1ValidQueuedJob(t)
	responses := []struct {
		name     string
		response Response
	}{
		{name: "job", response: l8WorkerV1ValidSuccessResponse(t, OperationJobStatus, "request-v1-job", job)},
		{name: "log", response: l8WorkerV1ValidSuccessResponse(t, OperationJobLogs, "request-v1-log", job)},
		{name: "error", response: Response{
			ProtocolVersion: ProtocolVersion,
			RequestID:       "request-v1-error",
			Operation:       OperationJobCancel,
			OK:              false,
			Error:           &Error{Code: ErrorCodeInternal, Message: "bounded v1 error"},
		}},
	}
	for _, tt := range responses {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := json.Marshal(tt.response)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := decodeWorkerResponse(bytes.NewReader(payload))
			if err != nil {
				t.Fatalf("strict response decoder rejected exact V1 %s response: %v", tt.name, err)
			}
			if decoded.Operation != tt.response.Operation || decoded.OK != tt.response.OK {
				t.Fatalf("decoded response = %#v, want operation=%q ok=%t", decoded, tt.response.Operation, tt.response.OK)
			}
		})
	}
}

func TestL8WorkerV1ClientsAcceptEmptyLegacyResponseIDForAllFiveOperations(t *testing.T) {
	fixtures := l8WorkerV2RequestPayloadFixturesForTest(t)
	job := l8WorkerV1ValidQueuedJob(t)
	tests := []struct {
		operation string
		invoke    func(*Client) error
	}{
		{operation: OperationJobStart, invoke: func(client *Client) error {
			_, err := client.JobStart(context.Background(), RuntimeDriverMicroVM, fixtures.startV1)
			return err
		}},
		{operation: OperationJobResolve, invoke: func(client *Client) error {
			_, err := client.JobResolve(context.Background(), fixtures.resolveV1)
			return err
		}},
		{operation: OperationJobStatus, invoke: func(client *Client) error {
			_, err := client.JobStatus(context.Background(), fixtures.statusV1)
			return err
		}},
		{operation: OperationJobLogs, invoke: func(client *Client) error {
			_, err := client.JobLogs(context.Background(), fixtures.logsV1)
			return err
		}},
		{operation: OperationJobCancel, invoke: func(client *Client) error {
			_, err := client.JobCancel(context.Background(), fixtures.cancelV1)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.operation, func(t *testing.T) {
			client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(func(_ context.Context, request Request) (Response, error) {
				if request.Operation != tt.operation {
					t.Fatalf("client operation = %q, want %q", request.Operation, tt.operation)
				}
				return l8WorkerV1ValidSuccessResponse(t, tt.operation, "", job), nil
			})})
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.invoke(client); err != nil {
				t.Fatalf("V1 client rejected legacy empty response ID: %v", err)
			}
		})
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
